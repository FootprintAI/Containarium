package server

import (
	"context"
	"testing"
	"time"
)

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
