package server

import (
	"context"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/app"
)

type fakeRouteLister struct {
	routes []*app.RouteRecord
	err    error
}

func (f *fakeRouteLister) ListByContainer(ctx context.Context, name string) ([]*app.RouteRecord, error) {
	return f.routes, f.err
}

func (f *fakeRouteLister) Delete(ctx context.Context, fullDomain string) error { return nil }

func (f *fakeRouteLister) Save(ctx context.Context, r *app.RouteRecord) error { return nil }

func listenLocal(t *testing.T) (net.Listener, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	return ln, ln.Addr().(*net.TCPAddr).Port
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	return port
}

// TestWaitForContainerReady_NilRouteStore — when the daemon was
// started without --app-hosting, routeStore is nil and the probe must
// short-circuit to "ready" (false = not timed out). Anything else
// would block start_container against daemons with no route store.
func TestWaitForContainerReady_NilRouteStore(t *testing.T) {
	s := &ContainerServer{} // routeStore deliberately nil
	start := time.Now()
	timedOut := s.waitForContainerReady(context.Background(), "alice", "10.0.0.1", 5*time.Second)
	if timedOut {
		t.Errorf("nil routeStore should short-circuit to ready, got timedOut=true")
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Errorf("nil routeStore should return immediately, took %v", elapsed)
	}
}

// TestWaitForContainerReady_EmptyContainerIP — same fast-path when
// the container has no IP yet. The probe has nothing to dial against
// so it returns "ready" rather than blocking for the full timeout.
func TestWaitForContainerReady_EmptyContainerIP(t *testing.T) {
	s := &ContainerServer{} // also exercises nil routeStore path, but the IP check would also short-circuit.
	start := time.Now()
	timedOut := s.waitForContainerReady(context.Background(), "alice", "", 5*time.Second)
	if timedOut {
		t.Errorf("empty containerIP should short-circuit to ready, got timedOut=true")
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Errorf("empty IP should return immediately, took %v", elapsed)
	}
}

// TestWaitForContainerReady_CtxCancelledBeforeStart — even when both
// fast-paths trip, the helper must complete; this guards against a
// regression where someone adds a long-running operation before the
// nil/IP checks.
func TestWaitForContainerReady_CtxCancelledBeforeStart(t *testing.T) {
	s := &ContainerServer{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan bool, 1)
	go func() {
		done <- s.waitForContainerReady(ctx, "alice", "", 5*time.Second)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("waitForContainerReady did not return on cancelled ctx within 1s")
	}
}

func TestWaitForContainerReady_ListenerImmediatelyOpen(t *testing.T) {
	ln, port := listenLocal(t)
	defer ln.Close()
	s := &ContainerServer{
		routeStore: &fakeRouteLister{routes: []*app.RouteRecord{{TargetPort: port}}},
	}
	start := time.Now()
	timedOut := s.waitForContainerReady(context.Background(), "alice", "127.0.0.1", 5*time.Second)
	elapsed := time.Since(start)
	if timedOut {
		t.Errorf("open listener should not time out")
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("immediate-success probe took %v, want <500ms", elapsed)
	}
}

func TestWaitForContainerReady_ListenerOpensAfterDelay(t *testing.T) {
	port := freePort(t)
	openAt := 600 * time.Millisecond
	go func() {
		time.Sleep(openAt)
		ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			return
		}
		// Hold the listener open long enough for the probe to dial it.
		time.AfterFunc(3*time.Second, func() { _ = ln.Close() })
	}()
	s := &ContainerServer{
		routeStore: &fakeRouteLister{routes: []*app.RouteRecord{{TargetPort: port}}},
	}
	start := time.Now()
	timedOut := s.waitForContainerReady(context.Background(), "alice", "127.0.0.1", 5*time.Second)
	elapsed := time.Since(start)
	if timedOut {
		t.Errorf("delayed listener should not time out")
	}
	// Probe polls every ~250ms after a near-instant loopback RST; first
	// successful dial lands shortly after openAt. Allow CI jitter.
	if elapsed < 500*time.Millisecond || elapsed > 1500*time.Millisecond {
		t.Errorf("elapsed = %v, want roughly %v ± 500ms", elapsed, openAt)
	}
}

func TestWaitForContainerReady_NeverOpens(t *testing.T) {
	port := freePort(t)
	s := &ContainerServer{
		routeStore: &fakeRouteLister{routes: []*app.RouteRecord{{TargetPort: port}}},
	}
	start := time.Now()
	timedOut := s.waitForContainerReady(context.Background(), "alice", "127.0.0.1", 1*time.Second)
	elapsed := time.Since(start)
	if !timedOut {
		t.Errorf("no listener should time out")
	}
	if elapsed < 900*time.Millisecond || elapsed > 1500*time.Millisecond {
		t.Errorf("elapsed = %v, want ~1s", elapsed)
	}
}

func TestWaitForContainerReady_ExplicitTimeoutHonored(t *testing.T) {
	port := freePort(t)
	s := &ContainerServer{
		routeStore: &fakeRouteLister{routes: []*app.RouteRecord{{TargetPort: port}}},
	}
	start := time.Now()
	timedOut := s.waitForContainerReady(context.Background(), "alice", "127.0.0.1", 2*time.Second)
	elapsed := time.Since(start)
	if !timedOut {
		t.Errorf("no listener should time out")
	}
	if elapsed < 1900*time.Millisecond || elapsed > 2500*time.Millisecond {
		t.Errorf("elapsed = %v, want ~2s", elapsed)
	}
}

func TestWaitForContainerReady_ListByContainerErrors(t *testing.T) {
	s := &ContainerServer{
		routeStore: &fakeRouteLister{err: errors.New("db down")},
	}
	start := time.Now()
	timedOut := s.waitForContainerReady(context.Background(), "alice", "127.0.0.1", 5*time.Second)
	elapsed := time.Since(start)
	if timedOut {
		t.Errorf("route-lookup error should short-circuit to ready, got timedOut=true")
	}
	if elapsed > 100*time.Millisecond {
		t.Errorf("error path should return immediately, took %v", elapsed)
	}
}
