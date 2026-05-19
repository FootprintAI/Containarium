package wake

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/footprintai/containarium/internal/app"
)

// fakeProxyManager satisfies ProxyManager for tests. Records every call
// in order and optionally returns a pre-canned error from updateErr (or
// grpcUpdateErr) on each invocation.
type fakeProxyManager struct {
	mu             sync.Mutex
	updateCalls    []proxyCall
	grpcCalls      []proxyCall
	updateErr      error // returned by UpdateRoute
	grpcUpdateErr  error // returned by UpdateGRPCRoute
}

type proxyCall struct {
	subdomain string
	ip        string
	port      int
}

func (f *fakeProxyManager) UpdateRoute(subdomain, ip string, port int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updateCalls = append(f.updateCalls, proxyCall{subdomain, ip, port})
	return f.updateErr
}

func (f *fakeProxyManager) UpdateGRPCRoute(subdomain, ip string, port int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.grpcCalls = append(f.grpcCalls, proxyCall{subdomain, ip, port})
	return f.grpcUpdateErr
}

func (f *fakeProxyManager) httpCallsCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.updateCalls)
}

func (f *fakeProxyManager) grpcCallsCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.grpcCalls)
}

// httpRoute builds a RouteRecord for an HTTP route.
func httpRoute(subdomain, ip string, port int, container string) *app.RouteRecord {
	return &app.RouteRecord{
		FullDomain:    subdomain,
		Subdomain:     subdomain,
		TargetIP:      ip,
		TargetPort:    port,
		Protocol:      string(app.RouteProtocolHTTP),
		ContainerName: container,
	}
}

func grpcRoute(subdomain, ip string, port int, container string) *app.RouteRecord {
	return &app.RouteRecord{
		FullDomain:    subdomain,
		Subdomain:     subdomain,
		TargetIP:      ip,
		TargetPort:    port,
		Protocol:      string(app.RouteProtocolGRPC),
		ContainerName: container,
	}
}

// TestRouter_SwapToWake_SingleRoute — single HTTP route flips to the
// wake address and the tracker is marked once.
func TestRouter_SwapToWake_SingleRoute(t *testing.T) {
	pm := &fakeProxyManager{}
	tracker := New()
	r := NewRouter(pm, tracker, "10.0.3.1", 8080)

	routes := []*app.RouteRecord{httpRoute("alice.example.test", "10.0.3.42", 9000, "alice-container")}
	if err := r.SwapToWake(context.Background(), "alice-container", routes); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := pm.httpCallsCount(); got != 1 {
		t.Fatalf("UpdateRoute calls = %d, want 1", got)
	}
	if c := pm.updateCalls[0]; c.subdomain != "alice.example.test" || c.ip != "10.0.3.1" || c.port != 8080 {
		t.Errorf("UpdateRoute args = %+v, want subdomain=alice.example.test ip=10.0.3.1 port=8080", c)
	}
	if host, port, ok := tracker.IsInWakeMode("alice-container"); !ok || host != "10.0.3.1" || port != 8080 {
		t.Errorf("tracker entry = (%q,%d,%v), want (10.0.3.1,8080,true)", host, port, ok)
	}
}

// TestRouter_SwapToWake_MultiRoute — three routes → three UpdateRoute
// calls; all share the same tracker entry (keyed by container name).
func TestRouter_SwapToWake_MultiRoute(t *testing.T) {
	pm := &fakeProxyManager{}
	tracker := New()
	r := NewRouter(pm, tracker, "10.0.3.1", 8080)

	routes := []*app.RouteRecord{
		httpRoute("a.example.test", "10.0.3.42", 9000, "alice-container"),
		httpRoute("b.example.test", "10.0.3.42", 9001, "alice-container"),
		httpRoute("c.example.test", "10.0.3.42", 9002, "alice-container"),
	}
	if err := r.SwapToWake(context.Background(), "alice-container", routes); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := pm.httpCallsCount(); got != 3 {
		t.Fatalf("UpdateRoute calls = %d, want 3", got)
	}
	if got := len(tracker.Snapshot()); got != 1 {
		t.Errorf("tracker entries = %d, want 1 (one per container, not per route)", got)
	}
}

// TestRouter_SwapToWake_NoRoutes — empty/nil slice is a no-op, the
// tracker stays empty and no error is returned.
func TestRouter_SwapToWake_NoRoutes(t *testing.T) {
	pm := &fakeProxyManager{}
	tracker := New()
	r := NewRouter(pm, tracker, "10.0.3.1", 8080)

	if err := r.SwapToWake(context.Background(), "alice-container", nil); err != nil {
		t.Fatalf("nil slice: unexpected error: %v", err)
	}
	if err := r.SwapToWake(context.Background(), "alice-container", []*app.RouteRecord{}); err != nil {
		t.Fatalf("empty slice: unexpected error: %v", err)
	}
	if got := pm.httpCallsCount(); got != 0 {
		t.Errorf("no routes must skip UpdateRoute, got %d calls", got)
	}
	if got := len(tracker.Snapshot()); got != 0 {
		t.Errorf("no routes must leave tracker empty, got %d entries", got)
	}
}

// TestRouter_SwapToWake_ProxyManagerError — the production design marks
// the tracker FIRST so a racing RouteSyncJob tick sees the new state
// even before Caddy is updated, and so the next sync re-converges if
// Caddy fails. This test locks that behaviour: error bubbles up AND
// tracker is marked (RouteSync will then retry the push).
func TestRouter_SwapToWake_ProxyManagerError(t *testing.T) {
	pm := &fakeProxyManager{updateErr: errors.New("caddy admin 502")}
	tracker := New()
	r := NewRouter(pm, tracker, "10.0.3.1", 8080)

	routes := []*app.RouteRecord{httpRoute("alice.example.test", "10.0.3.42", 9000, "alice-container")}
	err := r.SwapToWake(context.Background(), "alice-container", routes)
	if err == nil {
		t.Fatal("expected error to propagate from UpdateRoute")
	}
	// Locked design: tracker MUST be marked even on Caddy failure so
	// RouteSyncJob re-pushes the wake upstream on the next tick.
	if _, _, ok := tracker.IsInWakeMode("alice-container"); !ok {
		t.Errorf("tracker should still be marked so RouteSync can retry; got ok=false")
	}
}

// TestRouter_SwapToWake_Idempotent — calling SwapToWake twice for the
// same container pushes UpdateRoute each time (Caddy may have drifted)
// and the tracker holds exactly one entry (per-container).
func TestRouter_SwapToWake_Idempotent(t *testing.T) {
	pm := &fakeProxyManager{}
	tracker := New()
	r := NewRouter(pm, tracker, "10.0.3.1", 8080)

	routes := []*app.RouteRecord{httpRoute("alice.example.test", "10.0.3.42", 9000, "alice-container")}
	for i := 0; i < 2; i++ {
		if err := r.SwapToWake(context.Background(), "alice-container", routes); err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
	}
	if got := pm.httpCallsCount(); got != 2 {
		t.Errorf("expected 2 UpdateRoute calls across 2 swaps, got %d", got)
	}
	if got := len(tracker.Snapshot()); got != 1 {
		t.Errorf("tracker entries after idempotent swap = %d, want 1", got)
	}
}

// TestRouter_SwapToDirect_SingleRoute — tracker cleared and Caddy is
// pointed at the route's direct TargetIP / TargetPort.
func TestRouter_SwapToDirect_SingleRoute(t *testing.T) {
	pm := &fakeProxyManager{}
	tracker := New()
	tracker.MarkWakeMode("alice-container", "alice.example.test", "10.0.3.1", 8080)
	r := NewRouter(pm, tracker, "10.0.3.1", 8080)

	routes := []*app.RouteRecord{httpRoute("alice.example.test", "10.0.3.42", 9000, "alice-container")}
	if err := r.SwapToDirect(context.Background(), "alice-container", routes); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := pm.httpCallsCount(); got != 1 {
		t.Fatalf("UpdateRoute calls = %d, want 1", got)
	}
	if c := pm.updateCalls[0]; c.ip != "10.0.3.42" || c.port != 9000 {
		t.Errorf("UpdateRoute args = %+v, want ip=10.0.3.42 port=9000", c)
	}
	if _, _, ok := tracker.IsInWakeMode("alice-container"); ok {
		t.Errorf("tracker entry must be cleared after SwapToDirect")
	}
}

// TestRouter_SwapToDirect_MultiRoute — each route swapped back to its
// own TargetIP/TargetPort.
func TestRouter_SwapToDirect_MultiRoute(t *testing.T) {
	pm := &fakeProxyManager{}
	tracker := New()
	tracker.MarkWakeMode("alice-container", "a.example.test", "10.0.3.1", 8080)
	r := NewRouter(pm, tracker, "10.0.3.1", 8080)

	routes := []*app.RouteRecord{
		httpRoute("a.example.test", "10.0.3.42", 9000, "alice-container"),
		httpRoute("b.example.test", "10.0.3.42", 9001, "alice-container"),
	}
	if err := r.SwapToDirect(context.Background(), "alice-container", routes); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := pm.httpCallsCount(); got != 2 {
		t.Errorf("UpdateRoute calls = %d, want 2", got)
	}
	if pm.updateCalls[0].port != 9000 || pm.updateCalls[1].port != 9001 {
		t.Errorf("ports = (%d,%d), want (9000,9001)", pm.updateCalls[0].port, pm.updateCalls[1].port)
	}
}

// TestRouter_SwapToDirect_NotInWakeMode — calling SwapToDirect on a
// container that was never in wake mode is a no-op for the tracker
// (delete-missing is fine) and still pushes the direct routes.
func TestRouter_SwapToDirect_NotInWakeMode(t *testing.T) {
	pm := &fakeProxyManager{}
	tracker := New()
	r := NewRouter(pm, tracker, "10.0.3.1", 8080)

	routes := []*app.RouteRecord{httpRoute("alice.example.test", "10.0.3.42", 9000, "alice-container")}
	if err := r.SwapToDirect(context.Background(), "alice-container", routes); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := pm.httpCallsCount(); got != 1 {
		t.Errorf("UpdateRoute calls = %d, want 1 (direct push still happens)", got)
	}
}

// TestRouter_SwapToDirect_ProxyManagerError — the tracker is cleared
// BEFORE Caddy is touched (design comment in router.go); when Caddy
// then fails, the error bubbles up but the tracker stays cleared (the
// next RouteSync tick will re-push direct).
func TestRouter_SwapToDirect_ProxyManagerError(t *testing.T) {
	pm := &fakeProxyManager{updateErr: errors.New("caddy admin 502")}
	tracker := New()
	tracker.MarkWakeMode("alice-container", "alice.example.test", "10.0.3.1", 8080)
	r := NewRouter(pm, tracker, "10.0.3.1", 8080)

	routes := []*app.RouteRecord{httpRoute("alice.example.test", "10.0.3.42", 9000, "alice-container")}
	err := r.SwapToDirect(context.Background(), "alice-container", routes)
	if err == nil {
		t.Fatal("expected error to propagate from UpdateRoute")
	}
	if _, _, ok := tracker.IsInWakeMode("alice-container"); ok {
		t.Errorf("tracker should be cleared even on Caddy failure (cleared FIRST in impl)")
	}
}

// TestRouter_HTTPvsGRPC — HTTP routes go to UpdateRoute, gRPC routes to
// UpdateGRPCRoute. The router dispatches by RouteRecord.Protocol.
func TestRouter_HTTPvsGRPC(t *testing.T) {
	pm := &fakeProxyManager{}
	tracker := New()
	r := NewRouter(pm, tracker, "10.0.3.1", 8080)

	routes := []*app.RouteRecord{
		httpRoute("http.example.test", "10.0.3.42", 9000, "alice-container"),
		grpcRoute("grpc.example.test", "10.0.3.42", 9001, "alice-container"),
	}
	if err := r.SwapToWake(context.Background(), "alice-container", routes); err != nil {
		t.Fatalf("SwapToWake: %v", err)
	}
	if got := pm.httpCallsCount(); got != 1 {
		t.Errorf("HTTP UpdateRoute calls = %d, want 1", got)
	}
	if got := pm.grpcCallsCount(); got != 1 {
		t.Errorf("gRPC UpdateGRPCRoute calls = %d, want 1", got)
	}

	// Reset and verify SwapToDirect dispatches the same way.
	pm = &fakeProxyManager{}
	r = NewRouter(pm, tracker, "10.0.3.1", 8080)
	if err := r.SwapToDirect(context.Background(), "alice-container", routes); err != nil {
		t.Fatalf("SwapToDirect: %v", err)
	}
	if got := pm.httpCallsCount(); got != 1 {
		t.Errorf("SwapToDirect HTTP calls = %d, want 1", got)
	}
	if got := pm.grpcCallsCount(); got != 1 {
		t.Errorf("SwapToDirect gRPC calls = %d, want 1", got)
	}
}

// TestRouter_Nil_SafeSwapToWake / SwapToDirect — calling either on a
// nil *Router is documented to be safe; the autosleep/start hooks rely
// on that for nil-safety when wake is disabled.
func TestRouter_Nil_SafeSwapToWake(t *testing.T) {
	var r *Router
	routes := []*app.RouteRecord{httpRoute("a.example.test", "10.0.3.42", 9000, "alice-container")}
	if err := r.SwapToWake(context.Background(), "alice-container", routes); err != nil {
		t.Errorf("nil router SwapToWake: %v", err)
	}
	if err := r.SwapToDirect(context.Background(), "alice-container", routes); err != nil {
		t.Errorf("nil router SwapToDirect: %v", err)
	}
}
