package gateway

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/auth"
)

// #3130: the daemon used to bind its HTTP port only after waiting up to two
// minutes for the core containers and two more for Postgres. For those
// minutes the tunnel client saw "connection refused" and the control plane
// marked the backend dead. The StartupListener binds the port first and
// answers /health with "degraded" plus the reason until the real gateway
// takes the listener over.

func startStartupListener(t *testing.T, reason string) *StartupListener {
	t.Helper()
	sl, err := ListenStartup("127.0.0.1:0", reason)
	if err != nil {
		t.Fatalf("ListenStartup: %v", err)
	}
	t.Cleanup(func() { _ = sl.Close() })
	return sl
}

func getHealth(t *testing.T, base string) (int, healthResponse) {
	t.Helper()
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get(base + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()
	var got healthResponse
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("/health is not JSON: %v (body %q)", err, body)
	}
	return resp.StatusCode, got
}

func TestStartupListener_HealthReportsDegradedWithReason(t *testing.T) {
	sl := startStartupListener(t, "waiting for core containers")
	base := "http://" + sl.Addr().String()

	code, got := getHealth(t, base)
	// Live-but-degraded: 200 so a liveness probe sees the backend up, the
	// body says it is not fully ready.
	if code != http.StatusOK {
		t.Errorf("status code = %d, want 200 (degraded is live, not down)", code)
	}
	if got.Status != "degraded" {
		t.Errorf("status = %q, want degraded", got.Status)
	}
	if got.Reason != "waiting for core containers" {
		t.Errorf("reason = %q, want %q", got.Reason, "waiting for core containers")
	}
	if got.Version == "" {
		t.Error("version is empty; /health always carries the version (#1647)")
	}

	sl.SetReason("postgres unavailable")
	if _, got := getHealth(t, base); got.Reason != "postgres unavailable" {
		t.Errorf("after SetReason, reason = %q, want %q", got.Reason, "postgres unavailable")
	}
}

func TestStartupListener_OtherPathsUnavailable(t *testing.T) {
	sl := startStartupListener(t, "postgres unavailable")
	base := "http://" + sl.Addr().String()

	for _, path := range []string{"/v1/containers", "/v1/network-policies", "/webui/", "/"} {
		resp, err := http.Get(base + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("GET %s = %d, want 503 while the daemon is starting", path, resp.StatusCode)
		}
		if !strings.Contains(string(body), "postgres unavailable") {
			t.Errorf("GET %s body %q does not name the reason", path, body)
		}
		if resp.Header.Get("Retry-After") == "" {
			t.Errorf("GET %s has no Retry-After header", path)
		}
	}
}

func TestStartupListener_ServeHandsOverToRealHandler(t *testing.T) {
	sl := startStartupListener(t, "initialising daemon")
	base := "http://" + sl.Addr().String()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/v1/ping", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "pong") })

	errCh := make(chan error, 1)
	go func() { errCh <- sl.Serve(mux) }()

	deadline := time.Now().Add(3 * time.Second)
	for {
		_, got := getHealth(t, base)
		if got.Status == "healthy" {
			if got.Reason != "" {
				t.Errorf("healthy response carries reason %q", got.Reason)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("/health still %q after Serve installed the real handler", got.Status)
		}
		time.Sleep(10 * time.Millisecond)
	}
	resp, err := http.Get(base + "/v1/ping")
	if err != nil {
		t.Fatalf("GET /v1/ping: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "pong" {
		t.Errorf("/v1/ping = %q, want pong from the handed-over handler", body)
	}

	_ = sl.Close()
	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return after Close")
	}
}

// The real gateway must serve on the listener the daemon bound early, not
// bind the port a second time (which would fail with "address in use").
func TestGatewayStart_TakesOverStartupListener(t *testing.T) {
	sl := startStartupListener(t, "initialising daemon")
	base := "http://" + sl.Addr().String()

	tm, err := auth.NewTokenManager("test-secret-for-startup-listener-0123456789", "containarium")
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	// httpPort 1 would be unbindable for a test process; Start must not
	// try to bind it when it has a startup listener.
	gs := NewGatewayServer("127.0.0.1:1", 1, auth.NewAuthMiddleware(tm), t.TempDir(), "", "")
	gs.SetStartupListener(sl)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- gs.Start(ctx) }()

	deadline := time.Now().Add(5 * time.Second)
	for {
		select {
		case err := <-errCh:
			t.Fatalf("gateway Start returned early: %v", err)
		default:
		}
		_, got := getHealth(t, base)
		if got.Status == healthStatusHealthy {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("/health still %q: the gateway did not take over the startup listener", got.Status)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
