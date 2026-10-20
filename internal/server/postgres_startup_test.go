package server

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/footprintai/containarium/internal/policyreadiness"
)

// blackholePostgres accepts TCP connections and never answers, the shape of
// a Postgres whose process is wedged or whose packets are dropped: a dial
// with no deadline blocks on it indefinitely.
func blackholePostgres(t *testing.T) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = lis.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	return "postgres://u:p@" + lis.Addr().String() + "/db?sslmode=disable&connect_timeout=0"
}

// withTimeout fails the test if fn does not return within d.
func withTimeout(t *testing.T, d time.Duration, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { fn(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("did not return within %s (unbounded Postgres wait)", d)
	}
}

// connectToPostgres must not block forever on a Postgres that accepts and
// never answers (#2824).
func TestConnectToPostgres_PingIsBounded(t *testing.T) {
	dsn := blackholePostgres(t)
	old := postgresPingTimeout
	postgresPingTimeout = 200 * time.Millisecond
	t.Cleanup(func() { postgresPingTimeout = old })

	withTimeout(t, 5*time.Second, func() {
		if _, err := connectToPostgres(dsn, 2, 10*time.Millisecond); err == nil {
			t.Error("connectToPostgres succeeded against a blackhole")
		}
	})
}

// The startup sequence calls the gate once per store (about 15 sites). With
// Postgres hanging, the first call is bounded by the startup deadline and
// every later one fails at once, so time-to-serve is ~one deadline, not one
// deadline (or 5 retries) per store.
func TestPostgresStartupGate_BoundsTimeToServe(t *testing.T) {
	blocking := func(ctx context.Context, _ string) error {
		<-ctx.Done()
		return ctx.Err()
	}
	h := health.NewServer()
	g := newPostgresStartupGate(300*time.Millisecond, blocking, h)

	start := time.Now()
	for i := 0; i < 15; i++ {
		if _, err := g.connect("postgres://x", 5, 3*time.Second); err == nil {
			t.Fatalf("site %d: connect succeeded against a blocking Postgres", i)
		}
		if _, err := gatedStore(g, "postgres://x", func(context.Context, string) (int, error) {
			t.Fatal("store constructor ran after the startup check failed")
			return 0, nil
		}); err == nil {
			t.Fatalf("site %d: gatedStore succeeded against a blocking Postgres", i)
		}
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("startup sequence took %s with a 300ms deadline; want ~one deadline", el)
	}

	reason := g.degradedReason()
	if !strings.Contains(reason, "startup Postgres check failed") {
		t.Errorf("degradedReason() = %q, want it to name the failed startup check", reason)
	}
	resp, err := h.Check(context.Background(), &healthpb.HealthCheckRequest{Service: policyreadiness.CorePostgresService})
	if err != nil || resp.GetStatus() != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Errorf("readiness for %s = %v, %v; want NOT_SERVING", policyreadiness.CorePostgresService, resp.GetStatus(), err)
	}
}

func TestPostgresStartupGate_RefusedFailsWithinDeadline(t *testing.T) {
	var calls int
	refused := func(context.Context, string) error {
		calls++
		return errors.New("connection refused")
	}
	g := newPostgresStartupGate(150*time.Millisecond, refused, nil)
	g.retryInterval = 20 * time.Millisecond
	start := time.Now()
	if err := g.check("dsn"); err == nil {
		t.Fatal("check succeeded on a refusing Postgres")
	}
	if el := time.Since(start); el > time.Second {
		t.Fatalf("check took %s, want within the 150ms deadline", el)
	}
	if calls < 2 {
		t.Errorf("check made %d attempts, want it to retry inside the deadline", calls)
	}
	n := calls
	_ = g.check("dsn")
	if calls != n {
		t.Errorf("second check re-pinged (%d -> %d); want the cached result", n, calls)
	}
}

func TestPostgresStartupGate_HealthyIsServingAndNotDegraded(t *testing.T) {
	h := health.NewServer()
	g := newPostgresStartupGate(time.Second, func(context.Context, string) error { return nil }, h)
	if err := g.check("dsn"); err != nil {
		t.Fatalf("check: %v", err)
	}
	if r := g.degradedReason(); r != "" {
		t.Errorf("degradedReason() = %q on a healthy Postgres", r)
	}
	if g.failedDSN() != "" {
		t.Errorf("failedDSN() = %q on a healthy Postgres", g.failedDSN())
	}
	resp, _ := h.Check(context.Background(), &healthpb.HealthCheckRequest{Service: policyreadiness.CorePostgresService})
	if resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Errorf("readiness = %v, want SERVING", resp.GetStatus())
	}
}

func TestStartupPostgresTimeoutFromEnv(t *testing.T) {
	cases := map[string]time.Duration{"": 20 * time.Second, "5s": 5 * time.Second, "junk": 20 * time.Second, "-1s": 20 * time.Second}
	for in, want := range cases {
		t.Setenv(envStartupPostgresTimeout, in)
		if got := startupPostgresTimeoutFromEnv(); got != want {
			t.Errorf("%q: got %s, want %s", in, got, want)
		}
	}
}
