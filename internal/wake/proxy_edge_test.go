package wake

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/app"
)

// countingStarter is a WakeStarter that records every WakeForRequest
// invocation atomically. The configured response is returned for every
// call.
type countingStarter struct {
	calls    atomic.Int64
	delay    time.Duration
	ready    bool
	ip       string
	port     int
	err      error
}

func (c *countingStarter) WakeForRequest(ctx context.Context, username string) (bool, string, int, error) {
	c.calls.Add(1)
	if c.delay > 0 {
		select {
		case <-time.After(c.delay):
		case <-ctx.Done():
			return false, "", 0, ctx.Err()
		}
	}
	return c.ready, c.ip, c.port, c.err
}

// recordingAudit captures the last (or all) Log calls so tests can
// assert on event name + fields.
type recordingAudit struct {
	mu     sync.Mutex
	events []auditEvent
}

type auditEvent struct {
	name   string
	fields map[string]any
}

func (a *recordingAudit) Log(event string, fields map[string]any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	// Deep-copy the fields map so a later mutation by the impl can't
	// race with the test reader.
	copied := make(map[string]any, len(fields))
	for k, v := range fields {
		copied[k] = v
	}
	a.events = append(a.events, auditEvent{name: event, fields: copied})
}

func (a *recordingAudit) last() (auditEvent, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.events) == 0 {
		return auditEvent{}, false
	}
	return a.events[len(a.events)-1], true
}

// upstreamWithRecorder spins up an httptest server that records the
// last (path, host, headers) it received and replies with `body`.
type upstreamRecorder struct {
	mu          sync.Mutex
	lastPath    string
	lastHost    string
	lastHeaders http.Header
	upgrade     bool
}

func startUpstream(t *testing.T, body string) (string, int, *upstreamRecorder, *httptest.Server) {
	t.Helper()
	rec := &upstreamRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.mu.Lock()
		rec.lastPath = r.URL.Path
		rec.lastHost = r.Host
		rec.lastHeaders = r.Header.Clone()
		rec.upgrade = strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
		rec.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, body)
	}))
	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("split host/port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port parse: %v", err)
	}
	return host, port, rec, srv
}

// TestWakeProxy_StarterReturnsNotReady — starter reports ready=false →
// proxy responds 503 with Retry-After: 5.
func TestWakeProxy_StarterReturnsNotReady(t *testing.T) {
	proxy := NewWakeProxy(
		&countingStarter{ready: false, ip: "10.0.0.42", port: 8080},
		&fakeLookup{fullDomain: "alice.example.test", containerName: "alice-container", targetIP: "10.0.0.42", targetPort: 8080},
		&fakeRouteStore{},
		nil,
		nil,
		1*time.Second,
	)
	req := httptest.NewRequest(http.MethodGet, "http://alice.example.test/", nil)
	req.Host = "alice.example.test"
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "5" {
		t.Errorf("Retry-After = %q, want %q", got, "5")
	}
}

// TestWakeProxy_StarterReturnsError — hard error from starter → 503.
func TestWakeProxy_StarterReturnsError(t *testing.T) {
	proxy := NewWakeProxy(
		&countingStarter{err: errors.New("incus start failed")},
		&fakeLookup{fullDomain: "alice.example.test", containerName: "alice-container"},
		&fakeRouteStore{},
		nil,
		nil,
		1*time.Second,
	)
	req := httptest.NewRequest(http.MethodGet, "http://alice.example.test/", nil)
	req.Host = "alice.example.test"
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
}

// TestWakeProxy_InflightDedup — 50 concurrent requests for the same
// container coalesce into a single starter call. All 50 receive the
// upstream body. Run with -race to also exercise the inflight map.
func TestWakeProxy_InflightDedup(t *testing.T) {
	host, port, _, srv := startUpstream(t, "hello")
	defer srv.Close()

	const fullDomain = "alice.example.test"
	starter := &countingStarter{ready: true, ip: host, port: port, delay: 50 * time.Millisecond}
	proxy := NewWakeProxy(
		starter,
		&fakeLookup{fullDomain: fullDomain, containerName: "alice-container", targetIP: host, targetPort: port},
		&fakeRouteStore{},
		nil,
		nil,
		5*time.Second,
	)

	const N = 50
	var wg sync.WaitGroup
	wg.Add(N)
	results := make(chan int, N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "http://"+fullDomain+"/", nil)
			req.Host = fullDomain
			rec := httptest.NewRecorder()
			proxy.ServeHTTP(rec, req)
			results <- rec.Code
		}()
	}
	wg.Wait()
	close(results)

	var ok200 int
	for code := range results {
		if code == http.StatusOK {
			ok200++
		}
	}
	if ok200 != N {
		t.Errorf("got %d/%d 200s", ok200, N)
	}
	if got := starter.calls.Load(); got != 1 {
		t.Errorf("starter calls = %d, want 1 (inflight de-dup failed)", got)
	}
}

// TestWakeProxy_InflightDedup_DifferentContainers — two different
// containers in flight at the same time → two starter calls, not one.
// The dedup key is the container name.
func TestWakeProxy_InflightDedup_DifferentContainers(t *testing.T) {
	host, port, _, srv := startUpstream(t, "hi")
	defer srv.Close()

	starter := &countingStarter{ready: true, ip: host, port: port, delay: 30 * time.Millisecond}

	// Two routes / two containers, served by a lookup that resolves on
	// FullDomain.
	stubs := []lookupStub{
		{"alice.example.test", "alice-container", host, port},
		{"bob.example.test", "bob-container", host, port},
	}
	lookup := &multiLookup{stubs: stubs}

	proxy := NewWakeProxy(starter, lookup, &fakeRouteStore{}, nil, nil, 5*time.Second)

	var wg sync.WaitGroup
	for _, s := range stubs {
		s := s
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				req := httptest.NewRequest(http.MethodGet, "http://"+s.full+"/", nil)
				req.Host = s.full
				rec := httptest.NewRecorder()
				proxy.ServeHTTP(rec, req)
				if rec.Code != http.StatusOK {
					t.Errorf("%s: status %d, want 200", s.full, rec.Code)
				}
			}()
		}
	}
	wg.Wait()

	if got := starter.calls.Load(); got != 2 {
		t.Errorf("starter calls = %d, want 2 (one per container)", got)
	}
}

// lookupStub describes one route for multiLookup. Named so the test
// callers can construct the slice literal without redeclaring the
// anonymous struct each time (Go has no structural equivalence between
// independently-declared anon structs across statements).
type lookupStub struct {
	full string
	name string
	ip   string
	port int
}

// multiLookup resolves multiple FullDomains in one struct.
type multiLookup struct {
	stubs []lookupStub
}

func (m *multiLookup) ResolveByHost(ctx context.Context, host string) (*app.RouteRecord, bool, error) {
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	for _, s := range m.stubs {
		if s.full == host {
			return &app.RouteRecord{
				FullDomain:    s.full,
				Subdomain:     s.full,
				ContainerName: s.name,
				TargetIP:      s.ip,
				TargetPort:    s.port,
				Protocol:      "http",
			}, true, nil
		}
	}
	return nil, false, nil
}

// TestWakeProxy_PathStripping — /wake/foo/bar is the smoke-test prefix;
// the handler strips it and forwards /foo/bar upstream.
func TestWakeProxy_PathStripping(t *testing.T) {
	host, port, rec, srv := startUpstream(t, "ok")
	defer srv.Close()

	proxy := NewWakeProxy(
		&countingStarter{ready: true, ip: host, port: port},
		&fakeLookup{fullDomain: "alice.example.test", containerName: "alice-container", targetIP: host, targetPort: port},
		&fakeRouteStore{},
		nil,
		nil,
		5*time.Second,
	)
	req := httptest.NewRequest(http.MethodGet, "http://alice.example.test/wake/foo/bar", nil)
	req.Host = "alice.example.test"
	resp := httptest.NewRecorder()
	proxy.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", resp.Code, resp.Body.String())
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.lastPath != "/foo/bar" {
		t.Errorf("upstream saw path %q, want /foo/bar", rec.lastPath)
	}
}

// TestWakeProxy_CatchAllPath — requests to arbitrary app paths (no
// /wake/ prefix) are forwarded unchanged. This is how Caddy delivers
// the user's original request URL.
func TestWakeProxy_CatchAllPath(t *testing.T) {
	host, port, rec, srv := startUpstream(t, "ok")
	defer srv.Close()

	proxy := NewWakeProxy(
		&countingStarter{ready: true, ip: host, port: port},
		&fakeLookup{fullDomain: "alice.example.test", containerName: "alice-container", targetIP: host, targetPort: port},
		&fakeRouteStore{},
		nil,
		nil,
		5*time.Second,
	)
	req := httptest.NewRequest(http.MethodGet, "http://alice.example.test/api/v1/widgets", nil)
	req.Host = "alice.example.test"
	resp := httptest.NewRecorder()
	proxy.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.Code)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.lastPath != "/api/v1/widgets" {
		t.Errorf("upstream saw path %q, want /api/v1/widgets", rec.lastPath)
	}
}

// TestWakeProxy_AuditOnReady — success path writes one audit event
// `autosleep.woken` with result="ready" and a non-zero wake_latency_ms.
func TestWakeProxy_AuditOnReady(t *testing.T) {
	host, port, _, srv := startUpstream(t, "ok")
	defer srv.Close()

	audit := &recordingAudit{}
	proxy := NewWakeProxy(
		&countingStarter{ready: true, ip: host, port: port, delay: 5 * time.Millisecond},
		&fakeLookup{fullDomain: "alice.example.test", containerName: "alice-container", targetIP: host, targetPort: port},
		&fakeRouteStore{},
		nil,
		audit,
		5*time.Second,
	)
	req := httptest.NewRequest(http.MethodGet, "http://alice.example.test/", nil)
	req.Host = "alice.example.test"
	resp := httptest.NewRecorder()
	proxy.ServeHTTP(resp, req)

	ev, ok := audit.last()
	if !ok {
		t.Fatal("no audit event recorded")
	}
	if ev.name != "autosleep.woken" {
		t.Errorf("event name = %q, want autosleep.woken", ev.name)
	}
	if ev.fields["result"] != "ready" {
		t.Errorf("result = %v, want ready", ev.fields["result"])
	}
	// Latency is int64 in the impl.
	if lat, _ := ev.fields["wake_latency_ms"].(int64); lat <= 0 {
		t.Errorf("wake_latency_ms = %v, want > 0", ev.fields["wake_latency_ms"])
	}
	if ev.fields["triggered_by"] != "http" {
		t.Errorf("triggered_by = %v, want http", ev.fields["triggered_by"])
	}
	if ev.fields["username"] != "alice" {
		t.Errorf("username = %v, want alice (containerName-trimmed)", ev.fields["username"])
	}
}

// TestWakeProxy_AuditOnTimeout — starter ready=false → audit event has
// result="error" (the impl folds timeout into the error branch with an
// explicit "wake: timeout after" error).
func TestWakeProxy_AuditOnTimeout(t *testing.T) {
	audit := &recordingAudit{}
	proxy := NewWakeProxy(
		&countingStarter{ready: false},
		&fakeLookup{fullDomain: "alice.example.test", containerName: "alice-container"},
		&fakeRouteStore{},
		nil,
		audit,
		1*time.Second,
	)
	req := httptest.NewRequest(http.MethodGet, "http://alice.example.test/", nil)
	req.Host = "alice.example.test"
	resp := httptest.NewRecorder()
	proxy.ServeHTTP(resp, req)

	ev, ok := audit.last()
	if !ok {
		t.Fatal("no audit event recorded")
	}
	if ev.fields["result"] != "error" {
		t.Errorf("result = %v, want error (timeout folds into error branch)", ev.fields["result"])
	}
	msg, _ := ev.fields["error"].(string)
	if !strings.Contains(msg, "timeout") {
		t.Errorf("error = %q, want it to mention timeout", msg)
	}
}

// TestWakeProxy_AuditOnError — hard error from starter → audit event
// result="error" with the error string preserved.
func TestWakeProxy_AuditOnError(t *testing.T) {
	audit := &recordingAudit{}
	proxy := NewWakeProxy(
		&countingStarter{err: errors.New("incus refused")},
		&fakeLookup{fullDomain: "alice.example.test", containerName: "alice-container"},
		&fakeRouteStore{},
		nil,
		audit,
		1*time.Second,
	)
	req := httptest.NewRequest(http.MethodGet, "http://alice.example.test/", nil)
	req.Host = "alice.example.test"
	resp := httptest.NewRecorder()
	proxy.ServeHTTP(resp, req)

	ev, ok := audit.last()
	if !ok {
		t.Fatal("no audit event recorded")
	}
	if ev.fields["result"] != "error" {
		t.Errorf("result = %v, want error", ev.fields["result"])
	}
	if msg, _ := ev.fields["error"].(string); !strings.Contains(msg, "incus refused") {
		t.Errorf("error = %q, want it to contain 'incus refused'", msg)
	}
}

// fakeRouter records SwapToDirect invocations on a channel so tests
// can wait for the fire-and-forget goroutine.
type fakeRouter struct {
	swapDirect chan string // container name
}

func (f *fakeRouter) SwapToDirect(ctx context.Context, containerName string, routes []*app.RouteRecord) error {
	// Non-blocking send so a slow test can't deadlock the wake proxy
	// goroutine; channel is buffered by the test.
	select {
	case f.swapDirect <- containerName:
	default:
	}
	return nil
}

func (f *fakeRouter) SwapToWake(ctx context.Context, containerName string, routes []*app.RouteRecord) error {
	return nil
}

// listingRouteStore returns a non-empty slice so the wake proxy's
// post-success scheduleSwapToDirect actually invokes the router.
type listingRouteStore struct{}

func (l *listingRouteStore) ListByContainer(ctx context.Context, name string) ([]*app.RouteRecord, error) {
	return []*app.RouteRecord{{
		ContainerName: name,
		FullDomain:    "alice.example.test",
		TargetIP:      "10.0.0.42",
		TargetPort:    8080,
		Protocol:      "http",
	}}, nil
}

// TestWakeProxy_AfterSuccessSwapToDirect — a successful wake schedules
// SwapToDirect (fire-and-forget). We can only thread a fake against
// the *Router type via direct construction; since NewWakeProxy takes
// `*Router` concretely, we build a Router wrapping a fake ProxyManager
// and assert via the underlying proxy manager calls.
func TestWakeProxy_AfterSuccessSwapToDirect(t *testing.T) {
	host, port, _, srv := startUpstream(t, "ok")
	defer srv.Close()

	pm := &fakeProxyManager{}
	tracker := New()
	router := NewRouter(pm, tracker, "10.0.3.1", 8080)

	proxy := NewWakeProxy(
		&countingStarter{ready: true, ip: host, port: port},
		&fakeLookup{fullDomain: "alice.example.test", containerName: "alice-container", targetIP: host, targetPort: port},
		&listingRouteStore{},
		router,
		nil,
		5*time.Second,
	)
	req := httptest.NewRequest(http.MethodGet, "http://alice.example.test/", nil)
	req.Host = "alice.example.test"
	resp := httptest.NewRecorder()
	proxy.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.Code)
	}
	// SwapToDirect is fire-and-forget; poll briefly.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if pm.httpCallsCount() > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := pm.httpCallsCount(); got != 1 {
		t.Errorf("post-wake SwapToDirect → UpdateRoute calls = %d, want 1", got)
	}
}

// TestWakeProxy_PortZeroFallsBackToRouteTarget — starter reports
// port=0 → proxy reuses route.TargetPort. Same for empty IP.
func TestWakeProxy_PortZeroFallsBackToRouteTarget(t *testing.T) {
	host, port, _, srv := startUpstream(t, "fellback")
	defer srv.Close()

	proxy := NewWakeProxy(
		// Starter reports ready but no ip/port — proxy must reuse the
		// route record's TargetIP/TargetPort.
		&countingStarter{ready: true, ip: "", port: 0},
		&fakeLookup{fullDomain: "alice.example.test", containerName: "alice-container", targetIP: host, targetPort: port},
		&fakeRouteStore{},
		nil,
		nil,
		5*time.Second,
	)
	req := httptest.NewRequest(http.MethodGet, "http://alice.example.test/", nil)
	req.Host = "alice.example.test"
	resp := httptest.NewRecorder()
	proxy.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", resp.Code, resp.Body.String())
	}
	if got := resp.Body.String(); got != "fellback" {
		t.Errorf("body = %q, want fellback", got)
	}
}

// TestWakeProxy_WebSocketUpgradeSmoke — Upgrade: websocket headers
// reach the upstream. httputil.NewSingleHostReverseProxy forwards
// these headers correctly out of the box (Go 1.12+).
func TestWakeProxy_WebSocketUpgradeSmoke(t *testing.T) {
	host, port, rec, srv := startUpstream(t, "ok")
	defer srv.Close()

	proxy := NewWakeProxy(
		&countingStarter{ready: true, ip: host, port: port},
		&fakeLookup{fullDomain: "alice.example.test", containerName: "alice-container", targetIP: host, targetPort: port},
		&fakeRouteStore{},
		nil,
		nil,
		5*time.Second,
	)
	req := httptest.NewRequest(http.MethodGet, "http://alice.example.test/ws", nil)
	req.Host = "alice.example.test"
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	resp := httptest.NewRecorder()
	proxy.ServeHTTP(resp, req)

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if !rec.upgrade {
		t.Errorf("upstream did not receive Upgrade: websocket; headers=%v", rec.lastHeaders)
	}
}

// TestWakeProxy_NilAuditLogger — when audit is nil, the impl falls
// back to log.Printf — must not panic.
func TestWakeProxy_NilAuditLogger(t *testing.T) {
	host, port, _, srv := startUpstream(t, "ok")
	defer srv.Close()

	proxy := NewWakeProxy(
		&countingStarter{ready: true, ip: host, port: port},
		&fakeLookup{fullDomain: "alice.example.test", containerName: "alice-container", targetIP: host, targetPort: port},
		&fakeRouteStore{},
		nil,
		nil, // explicit nil
		5*time.Second,
	)
	req := httptest.NewRequest(http.MethodGet, "http://alice.example.test/", nil)
	req.Host = "alice.example.test"
	resp := httptest.NewRecorder()
	// Defer/recover guards against a regression that introduces a
	// nil-deref into the impl.
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("panicked with nil audit logger: %v", r)
		}
	}()
	proxy.ServeHTTP(resp, req)
}

// TestWakeProxy_InflightMapClearsAfterCompletion — after a wake
// completes, a follow-up request re-enters the leader path (i.e. the
// inflight map entry was deleted). Verified by counting starter calls
// across two sequential waves.
func TestWakeProxy_InflightMapClearsAfterCompletion(t *testing.T) {
	host, port, _, srv := startUpstream(t, "ok")
	defer srv.Close()

	starter := &countingStarter{ready: true, ip: host, port: port}
	proxy := NewWakeProxy(
		starter,
		&fakeLookup{fullDomain: "alice.example.test", containerName: "alice-container", targetIP: host, targetPort: port},
		&fakeRouteStore{},
		nil,
		nil,
		5*time.Second,
	)
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("http://alice.example.test/iter%d", i), nil)
		req.Host = "alice.example.test"
		resp := httptest.NewRecorder()
		proxy.ServeHTTP(resp, req)
		if resp.Code != http.StatusOK {
			t.Fatalf("iter %d: status = %d, want 200", i, resp.Code)
		}
	}
	// Three sequential waves should each re-enter the leader path —
	// the inflight entry must be cleared after each completes.
	if got := starter.calls.Load(); got != 3 {
		t.Errorf("starter calls = %d, want 3 (inflight not cleared between waves)", got)
	}
}
