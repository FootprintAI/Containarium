package server

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/events"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/incus/incustest"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// newStartContainerTestServer wires a ContainerServer with just enough
// dependencies for StartContainer to run end-to-end: a mocked backend
// + the real Manager + a no-op emitter. routeStore is intentionally
// nil so waitForContainerReady takes its short-circuit fast-path,
// which lets the test reason about wall-clock without a TCP listener.
func newStartContainerTestServer(t *testing.T, seed map[string]*incus.ContainerInfo) *ContainerServer {
	t.Helper()
	mock := incustest.NewMockBackend()
	for n, info := range seed {
		mock.Containers[n] = info
	}
	return &ContainerServer{
		manager: container.NewWithBackend(mock),
		emitter: events.NewEmitter(events.NewBus()),
	}
}

// TestStartContainer_NoWaitDefault — WaitForReady defaults to false;
// the handler must complete near-instantly without consulting the
// probe.
func TestStartContainer_NoWaitDefault(t *testing.T) {
	s := newStartContainerTestServer(t, map[string]*incus.ContainerInfo{
		"alice-container": {Name: "alice-container", State: "Stopped", IPAddress: "10.0.0.42"},
	})
	start := time.Now()
	resp, err := s.StartContainer(context.Background(), &pb.StartContainerRequest{Username: "alice"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.ReadyTimedOut {
		t.Errorf("default (no wait) must not report timeout")
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Errorf("no-wait path took %v, expected near-instant", elapsed)
	}
}

// TestStartContainer_WaitForReady_NilRouteStoreShortCircuits —
// wait_for_ready=true with a nil routeStore must still be near-
// instant (the probe short-circuits to "ready"). Prevents accidental
// deadlock on daemons that lack --app-hosting.
func TestStartContainer_WaitForReady_NilRouteStoreShortCircuits(t *testing.T) {
	s := newStartContainerTestServer(t, map[string]*incus.ContainerInfo{
		"alice-container": {Name: "alice-container", State: "Stopped", IPAddress: "10.0.0.42"},
	})
	start := time.Now()
	resp, err := s.StartContainer(context.Background(), &pb.StartContainerRequest{
		Username:     "alice",
		WaitForReady: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.ReadyTimedOut {
		t.Errorf("nil routeStore must short-circuit, got ReadyTimedOut=true")
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("nil routeStore probe took %v, expected near-instant", elapsed)
	}
}

// TestStartContainer_WaitForReady_EmptyIPShortCircuits — even with a
// non-nil routeStore (we still leave it nil here, but the impl checks
// IP before consulting the store), an empty IP must not stall.
func TestStartContainer_WaitForReady_EmptyIPShortCircuits(t *testing.T) {
	s := newStartContainerTestServer(t, map[string]*incus.ContainerInfo{
		"alice-container": {Name: "alice-container", State: "Stopped", IPAddress: ""},
	})
	start := time.Now()
	resp, err := s.StartContainer(context.Background(), &pb.StartContainerRequest{
		Username:            "alice",
		WaitForReady:        true,
		ReadyTimeoutSeconds: 1,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.ReadyTimedOut {
		t.Errorf("empty IP must short-circuit, got ReadyTimedOut=true")
	}
	if elapsed := time.Since(start); elapsed > 300*time.Millisecond {
		t.Errorf("empty-IP probe took %v, expected near-instant", elapsed)
	}
}

// TestStartContainer_MissingUsername — request validation.
func TestStartContainer_MissingUsername(t *testing.T) {
	s := newStartContainerTestServer(t, nil)
	_, err := s.StartContainer(context.Background(), &pb.StartContainerRequest{})
	if err == nil {
		t.Fatal("expected error for empty username")
	}
}

// TestStartContainer_StartFailureSurfaces — when manager.Start fails
// and there's no peer pool, the error propagates rather than getting
// silently swallowed.
func TestStartContainer_StartFailureSurfaces(t *testing.T) {
	mock := incustest.NewMockBackend()
	mock.StartContainerFunc = func(_ string) error {
		return errors.New("incus refused")
	}
	s := &ContainerServer{
		manager: container.NewWithBackend(mock),
		emitter: events.NewEmitter(events.NewBus()),
	}
	_, err := s.StartContainer(context.Background(), &pb.StartContainerRequest{Username: "alice"})
	if err == nil {
		t.Fatal("expected error when manager.Start fails")
	}
}

// TestStartContainer_ResponsePopulatesContainerName — the response
// must include the *toProtoContainer* shape so MCP/CLI callers can
// display state, not just the message.
func TestStartContainer_ResponsePopulatesContainerName(t *testing.T) {
	s := newStartContainerTestServer(t, map[string]*incus.ContainerInfo{
		"alice-container": {Name: "alice-container", State: "Stopped", IPAddress: "10.0.0.99"},
	})
	resp, err := s.StartContainer(context.Background(), &pb.StartContainerRequest{Username: "alice"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Container == nil {
		t.Fatal("response.Container must be populated")
	}
	if resp.Container.Name != "alice-container" {
		t.Errorf("Container.Name = %q, want alice-container", resp.Container.Name)
	}
}

// TestStartContainer_StampsLastStartedAt — successful start writes
// the Incus `user.containarium.last_started_at` key with an RFC3339
// timestamp near `time.Now()`. The Phase 2 auto-sleep ticker reads
// this for its anti-thrash window.
func TestStartContainer_StampsLastStartedAt(t *testing.T) {
	mock := incustest.NewMockBackend()
	mock.Containers["alice-container"] = &incus.ContainerInfo{
		Name: "alice-container", State: "Stopped", IPAddress: "10.0.0.42",
	}
	var (
		mu         sync.Mutex
		stampCalls []struct{ name, key, value string }
	)
	mock.SetConfigFunc = func(name, key, value string) error {
		mu.Lock()
		defer mu.Unlock()
		stampCalls = append(stampCalls, struct{ name, key, value string }{name, key, value})
		return nil
	}
	s := &ContainerServer{
		manager: container.NewWithBackend(mock),
		emitter: events.NewEmitter(events.NewBus()),
	}

	before := time.Now()
	_, err := s.StartContainer(context.Background(), &pb.StartContainerRequest{Username: "alice"})
	after := time.Now()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	var stamp *struct{ name, key, value string }
	for i := range stampCalls {
		if stampCalls[i].key == incus.LastStartedAtKey {
			stamp = &stampCalls[i]
			break
		}
	}
	if stamp == nil {
		t.Fatalf("expected SetConfig(%q) after successful start; calls=%+v",
			incus.LastStartedAtKey, stampCalls)
	}
	if stamp.name != "alice-container" {
		t.Errorf("stamp on container %q, want alice-container", stamp.name)
	}
	parsed, perr := time.Parse(time.RFC3339, stamp.value)
	if perr != nil {
		t.Fatalf("stamped value %q is not RFC3339: %v", stamp.value, perr)
	}
	// 5s tolerance — generous enough for slow CI but tight enough to
	// catch a clock-source regression (e.g. a stale value).
	if parsed.Before(before.Add(-5*time.Second)) || parsed.After(after.Add(5*time.Second)) {
		t.Errorf("stamp %s is outside [%s, %s] window", parsed, before, after)
	}
}

// TestStartContainer_DoesNotStampOnFailure — when manager.Start
// fails, the stamp must not be written. Locks the "only stamp on
// success" branch so a refactor moving the SetConfig before the
// error check would fail.
func TestStartContainer_DoesNotStampOnFailure(t *testing.T) {
	mock := incustest.NewMockBackend()
	mock.StartContainerFunc = func(string) error { return errors.New("incus refused") }
	var sawStamp bool
	mock.SetConfigFunc = func(_, key, _ string) error {
		if key == incus.LastStartedAtKey {
			sawStamp = true
		}
		return nil
	}
	s := &ContainerServer{
		manager: container.NewWithBackend(mock),
		emitter: events.NewEmitter(events.NewBus()),
	}

	_, err := s.StartContainer(context.Background(), &pb.StartContainerRequest{Username: "alice"})
	if err == nil {
		t.Fatal("expected start to fail")
	}
	if sawStamp {
		t.Errorf("LastStartedAt must not be stamped when Start fails")
	}
}
