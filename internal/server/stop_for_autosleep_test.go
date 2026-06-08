package server

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/footprintai/containarium/internal/app"
	"github.com/footprintai/containarium/internal/events"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/incus/incustest"
)

// newStopForAutoSleepTestServer wires the minimum dependencies the
// thin wrapper needs: a backend the manager can call Stop / Get on,
// and an event emitter (StopContainer always emits a stopped event).
func newStopForAutoSleepTestServer(t *testing.T, seed map[string]*incus.ContainerInfo) (*ContainerServer, *incustest.MockBackend) {
	t.Helper()
	mock := incustest.NewMockBackend()
	for n, info := range seed {
		mock.Containers[n] = info
	}
	return &ContainerServer{
		manager: container.NewWithBackend(mock),
		emitter: events.NewEmitter(events.NewBus()),
	}, mock
}

// TestStopForAutoSleep_CallsStopContainer — the wrapper drives the
// same plumbing as a manual stop: backend StopContainer is invoked
// with the "<username>-container" name and no force flag.
func TestStopForAutoSleep_CallsStopContainer(t *testing.T) {
	var stops int32
	var stoppedName string
	var stoppedForce bool
	s, mock := newStopForAutoSleepTestServer(t, map[string]*incus.ContainerInfo{
		"alice-container": {Name: "alice-container", State: "Running"},
	})
	mock.StopContainerFunc = func(name string, force bool) error {
		atomic.AddInt32(&stops, 1)
		stoppedName = name
		stoppedForce = force
		if c, ok := mock.Containers[name]; ok {
			c.State = "Stopped"
		}
		return nil
	}

	if err := s.StopForAutoSleep(testCtx(), "alice", "idle 90m", 90); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := atomic.LoadInt32(&stops); got != 1 {
		t.Fatalf("StopContainer calls = %d, want 1", got)
	}
	if stoppedName != "alice-container" {
		t.Errorf("stopped name = %q, want alice-container", stoppedName)
	}
	if stoppedForce {
		t.Errorf("auto-sleep stop must not use force=true (graceful stop only)")
	}
}

// TestStopForAutoSleep_PropagatesError — when the inner Stop fails
// and no peer pool is wired, the error bubbles up so the Manager can
// log it and skip the audit entry.
func TestStopForAutoSleep_PropagatesError(t *testing.T) {
	s, mock := newStopForAutoSleepTestServer(t, map[string]*incus.ContainerInfo{
		"alice-container": {Name: "alice-container", State: "Running"},
	})
	mock.StopContainerFunc = func(string, bool) error {
		return errors.New("incus refused stop")
	}
	err := s.StopForAutoSleep(testCtx(), "alice", "idle 90m", 90)
	if err == nil {
		t.Fatal("expected error to propagate from inner Stop")
	}
}

// TestStopForAutoSleep_DoesNotInvokeAuditDirectly — locks the design
// layering: the server method is a thin wrapper that emits the
// stopped event (same as a manual stop) and returns. The audit row
// is the Manager's job — the wrapper must not write one itself, or
// we'd get duplicate audit_logs rows when the Manager logs too.
//
// We can't reach the audit store from here (it's wired one level
// up), but we can assert the wrapper writes nothing it shouldn't:
// exactly one stopped-event emission, no other side effects beyond
// the inner StopContainer call.
func TestStopForAutoSleep_DoesNotInvokeAuditDirectly(t *testing.T) {
	bus := events.NewBus()
	sub := bus.Subscribe(nil)
	defer bus.Unsubscribe(sub.ID)

	mock := incustest.NewMockBackend()
	mock.Containers["alice-container"] = &incus.ContainerInfo{Name: "alice-container", State: "Running"}
	s := &ContainerServer{
		manager: container.NewWithBackend(mock),
		emitter: events.NewEmitter(bus),
	}

	if err := s.StopForAutoSleep(testCtx(), "alice", "idle 90m", 90); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Drain the channel non-blockingly to count events. Publish is
	// synchronous (sends under the bus's read lock), so by the time
	// StopForAutoSleep returns the channel either holds the event or
	// it was dropped because the buffer was full — neither happens
	// here with a single subscriber and a single emit.
	var stoppedEvents int
	drain := true
	for drain {
		select {
		case ev := <-sub.Events:
			if ev == nil {
				drain = false
				continue
			}
			// Any stopped-shaped event counts; payload asserted in events tests.
			stoppedEvents++
		default:
			drain = false
		}
	}
	if stoppedEvents != 1 {
		t.Errorf("expected exactly 1 stop event from wrapper, got %d", stoppedEvents)
	}
}

// recordingWakeRouter / recordingRouteStore stamp a shared seq counter
// when their tracked method is called, so the test can assert the
// SwapToWake → StopContainer happens-before relationship.
type recordingWakeRouter struct {
	seq       *atomic.Int64
	swapSeqAt int64
}

func (r *recordingWakeRouter) SwapToWake(_ context.Context, _ string, _ []*app.RouteRecord) error {
	r.swapSeqAt = r.seq.Add(1)
	return nil
}
func (r *recordingWakeRouter) SwapToDirect(context.Context, string, []*app.RouteRecord) error {
	return nil
}

type recordingRouteStore struct{}

func (recordingRouteStore) ListByContainer(_ context.Context, _ string) ([]*app.RouteRecord, error) {
	return []*app.RouteRecord{{FullDomain: "alice.example.test", TargetIP: "10.0.0.5", TargetPort: 8080}}, nil
}
func (recordingRouteStore) Delete(context.Context, string) error         { return nil }
func (recordingRouteStore) Save(context.Context, *app.RouteRecord) error { return nil }

// TestStopForAutoSleep_SwapsBeforeStop pins the #224 fix: the Caddy
// route swap MUST happen before the container is stopped, otherwise
// any request hitting Caddy during the graceful-stop window gets a
// 502 from a dead upstream. The recorded sequence numbers must show
// SwapToWake < StopContainer.
func TestStopForAutoSleep_SwapsBeforeStop(t *testing.T) {
	var seq atomic.Int64
	var stopSeqAt int64

	mock := incustest.NewMockBackend()
	mock.Containers["alice-container"] = &incus.ContainerInfo{Name: "alice-container", State: "Running"}
	mock.StopContainerFunc = func(name string, force bool) error {
		stopSeqAt = seq.Add(1)
		if c, ok := mock.Containers[name]; ok {
			c.State = "Stopped"
		}
		return nil
	}

	wakeRouter := &recordingWakeRouter{seq: &seq}
	s := &ContainerServer{
		manager:    container.NewWithBackend(mock),
		emitter:    events.NewEmitter(events.NewBus()),
		wakeRouter: wakeRouter,
		routeStore: recordingRouteStore{},
	}

	if err := s.StopForAutoSleep(testCtx(), "alice", "idle 90m", 90); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if wakeRouter.swapSeqAt == 0 {
		t.Fatal("SwapToWake was not called")
	}
	if stopSeqAt == 0 {
		t.Fatal("StopContainer was not called")
	}
	if wakeRouter.swapSeqAt >= stopSeqAt {
		t.Errorf("ordering bug (#224): SwapToWake seq=%d must be < StopContainer seq=%d; otherwise Caddy points at the dead container during the stop window and inbound requests 502",
			wakeRouter.swapSeqAt, stopSeqAt)
	}
}
