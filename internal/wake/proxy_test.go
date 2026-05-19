package wake

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/app"
)

// fakeStarter satisfies WakeStarter for tests.
type fakeStarter struct {
	ready bool
	ip    string
	port  int
	err   error
}

func (f *fakeStarter) WakeForRequest(ctx context.Context, username string) (bool, string, int, error) {
	return f.ready, f.ip, f.port, f.err
}

// fakeLookup satisfies RouteLookup for tests. Returns a static route
// when the incoming Host matches the configured fullDomain.
type fakeLookup struct {
	fullDomain    string
	containerName string
	targetIP      string
	targetPort    int
}

func (f *fakeLookup) ResolveByHost(ctx context.Context, host string) (*app.RouteRecord, bool, error) {
	// http.Request.Host can include ":<port>"; we compare prefix.
	if host == f.fullDomain || strings.HasPrefix(host, f.fullDomain+":") {
		return &app.RouteRecord{
			FullDomain:    f.fullDomain,
			Subdomain:     f.fullDomain,
			ContainerName: f.containerName,
			TargetIP:      f.targetIP,
			TargetPort:    f.targetPort,
			Protocol:      "http",
		}, true, nil
	}
	return nil, false, nil
}

// fakeRouteStore satisfies RouteStore for tests. The schedule-swap-to-
// direct goroutine calls into this after a successful wake; we return
// an empty slice so the swap is a no-op (we don't have a real
// ProxyManager in this test).
type fakeRouteStore struct{}

func (f *fakeRouteStore) ListByContainer(ctx context.Context, containerName string) ([]*app.RouteRecord, error) {
	return nil, nil
}

// TestWakeProxy_HappyPath wires a fake upstream (httptest.Server), a
// fake starter that reports "ready" against that upstream, and asserts
// that ServeHTTP proxies the request through and returns the
// upstream's body verbatim.
func TestWakeProxy_HappyPath(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "hello from container")
	}))
	defer upstream.Close()

	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "http://"))
	if err != nil {
		t.Fatalf("split host/port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port parse: %v", err)
	}

	const fullDomain = "alice-web.example.test"

	proxy := NewWakeProxy(
		&fakeStarter{ready: true, ip: host, port: port},
		&fakeLookup{fullDomain: fullDomain, containerName: "alice-container", targetIP: host, targetPort: port},
		&fakeRouteStore{},
		nil, // no Router — schedule-swap-to-direct is gated on non-nil router
		nil, // no AuditLogger — falls back to log.Printf
		5*time.Second,
	)

	req := httptest.NewRequest(http.MethodGet, "http://"+fullDomain+"/", nil)
	req.Host = fullDomain
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); got != "hello from container" {
		t.Errorf("body: got %q, want %q", got, "hello from container")
	}
}

// TestWakeProxy_NotFound returns 404 when the Host header doesn't
// match any route.
func TestWakeProxy_NotFound(t *testing.T) {
	proxy := NewWakeProxy(
		&fakeStarter{},
		&fakeLookup{fullDomain: "real.example.test", containerName: "real-container"},
		&fakeRouteStore{},
		nil,
		nil,
		1*time.Second,
	)
	req := httptest.NewRequest(http.MethodGet, "http://bogus.example.test/", nil)
	req.Host = "bogus.example.test"
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status: got %d, want 404", rec.Code)
	}
}
