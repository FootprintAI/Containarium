//go:build !containarium_client

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

// --- self-restart watcher (option B) ---

type pgFakeClock struct{ t time.Time }

func (c *pgFakeClock) now() time.Time { return c.t }
func (c *pgFakeClock) sleep(ctx context.Context, d time.Duration) bool {
	if ctx.Err() != nil {
		return false
	}
	c.t = c.t.Add(d)
	return true
}

// pgScriptedPinger answers from a script; after the script it keeps the last answer.
type pgScriptedPinger struct {
	script []error
	calls  int
}

func (p *pgScriptedPinger) ping(context.Context) error {
	i := p.calls
	p.calls++
	if i >= len(p.script) {
		i = len(p.script) - 1
	}
	return p.script[i]
}

func newTestPGWatcher(clk *pgFakeClock, p *pgScriptedPinger, minUptime time.Duration) *postgresRecoveryWatcher {
	w := &postgresRecoveryWatcher{
		ping:      p.ping,
		started:   clk.now(),
		now:       clk.now,
		sleep:     clk.sleep,
		minUptime: minUptime,
		required:  3,
		interval:  5 * time.Second,
		maxDelay:  60 * time.Second,
	}
	return w
}

var errDown = errors.New("connection refused")

func TestRecoveryWatcher_ExitsAfterNConsecutiveSuccesses(t *testing.T) {
	clk := &pgFakeClock{t: time.Unix(0, 0)}
	p := &pgScriptedPinger{script: []error{errDown, nil}}
	w := newTestPGWatcher(clk, p, 0)
	if !w.run(context.Background()) {
		t.Fatal("run returned false; want a restart decision")
	}
	if p.calls != 4 { // one failure, then exactly 3 successes
		t.Errorf("pinged %d times, want 4 (1 failure + 3 successes)", p.calls)
	}
}

func TestRecoveryWatcher_SingleSuccessDoesNotExit(t *testing.T) {
	clk := &pgFakeClock{t: time.Unix(0, 0)}
	p := &pgScriptedPinger{script: []error{nil, errDown, nil, nil, errDown, nil, nil, nil}}
	w := newTestPGWatcher(clk, p, 0)
	if !w.run(context.Background()) {
		t.Fatal("run returned false")
	}
	// Each failure resets the count: only the final 3-in-a-row exits.
	if p.calls != 8 {
		t.Errorf("pinged %d times, want 8 (a failure must reset the count)", p.calls)
	}
}

func TestRecoveryWatcher_WaitsForMinimumUptime(t *testing.T) {
	clk := &pgFakeClock{t: time.Unix(0, 0)}
	p := &pgScriptedPinger{script: []error{nil}}
	w := newTestPGWatcher(clk, p, 2*time.Minute)
	if !w.run(context.Background()) {
		t.Fatal("run returned false")
	}
	if up := clk.now().Sub(w.started); up < 2*time.Minute {
		t.Errorf("exited after %s of uptime, want >= 2m", up)
	}
}

func TestRecoveryWatcher_StopsOnContextCancel(t *testing.T) {
	clk := &pgFakeClock{t: time.Unix(0, 0)}
	p := &pgScriptedPinger{script: []error{errDown}}
	w := newTestPGWatcher(clk, p, 0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if w.run(ctx) {
		t.Fatal("run returned true after cancel")
	}
}

func TestNewPostgresRecoveryWatcher_OnlyWhenFlagOnAndStartupFailed(t *testing.T) {
	cases := []struct {
		name      string
		flag      bool
		failedDSN string
		want      bool
	}{
		{"flag off, startup failed", false, "postgres://x", false},
		{"flag on, startup ok", true, "", false},
		{"flag off, startup ok", false, "", false},
		{"flag on, startup failed", true, "postgres://x", true},
	}
	for _, c := range cases {
		if v := "0"; c.flag {
			t.Setenv(envRestartOnPostgresRecovery, "1")
		} else {
			t.Setenv(envRestartOnPostgresRecovery, v)
		}
		got := newPostgresRecoveryWatcher(c.failedDSN) != nil
		if got != c.want {
			t.Errorf("%s: watcher created = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestDualServer_RecoveryWatcherShutsDownWithRestartError(t *testing.T) {
	clk := &pgFakeClock{t: time.Unix(0, 0)}
	p := &pgScriptedPinger{script: []error{nil}}
	ds := &DualServer{postgresRecovery: newTestPGWatcher(clk, p, 0)}
	ctx, restart := ds.watchPostgresRecovery(context.Background())
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("serving context not cancelled after recovery")
	}
	if err := restart(nil); !errors.Is(err, ErrRestartForPostgresRecovery) {
		t.Errorf("Start's result = %v, want ErrRestartForPostgresRecovery", err)
	}

	// No watcher: ctx is not cancelled and the result passes through.
	ds2 := &DualServer{}
	ctx2, restart2 := ds2.watchPostgresRecovery(context.Background())
	if ctx2.Err() != nil {
		t.Error("ctx cancelled with no watcher")
	}
	if err := restart2(nil); err != nil {
		t.Errorf("result = %v, want nil with no watcher", err)
	}
}
