package server

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/footprintai/containarium/internal/app"
	"github.com/footprintai/containarium/internal/events"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/incus/incustest"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// fakeWakeRouter records SwapToWake / SwapToDirect calls. Both methods
// satisfy the WakeRouter interface defined in wake_router.go.
type fakeWakeRouter struct {
	mu              sync.Mutex
	swapToWake      []wakeCall
	swapToDirect    []wakeCall
	swapToWakeErr   error
	swapToDirectErr error
}

type wakeCall struct {
	container string
	routes    []*app.RouteRecord
}

func (f *fakeWakeRouter) SwapToWake(ctx context.Context, name string, routes []*app.RouteRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.swapToWake = append(f.swapToWake, wakeCall{name, routes})
	return f.swapToWakeErr
}

func (f *fakeWakeRouter) SwapToDirect(ctx context.Context, name string, routes []*app.RouteRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.swapToDirect = append(f.swapToDirect, wakeCall{name, routes})
	return f.swapToDirectErr
}

func (f *fakeWakeRouter) wakeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.swapToWake)
}

func (f *fakeWakeRouter) directCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.swapToDirect)
}

// memoryRouteStore is an in-memory routeLister for the hook tests.
type memoryRouteStore struct {
	routes []*app.RouteRecord
	err    error
}

func (m *memoryRouteStore) ListByContainer(ctx context.Context, name string) ([]*app.RouteRecord, error) {
	if m.err != nil {
		return nil, m.err
	}
	var out []*app.RouteRecord
	for _, r := range m.routes {
		if r.ContainerName == name {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *memoryRouteStore) Delete(ctx context.Context, fullDomain string) error { return nil }
func (m *memoryRouteStore) Save(ctx context.Context, route *app.RouteRecord) error {
	m.routes = append(m.routes, route)
	return nil
}

// newWakeHookTestServer wires a ContainerServer with a mock backend, a
// real Manager, an in-memory route store, and a configurable wake
// router. seed populates the mock with initial container state.
func newWakeHookTestServer(t *testing.T, seed map[string]*incus.ContainerInfo, routes []*app.RouteRecord, router WakeRouter) (*ContainerServer, *incustest.MockBackend) {
	t.Helper()
	mock := incustest.NewMockBackend()
	for n, info := range seed {
		mock.Containers[n] = info
	}
	s := &ContainerServer{
		manager:    container.NewWithBackend(mock),
		emitter:    events.NewEmitter(events.NewBus()),
		routeStore: &memoryRouteStore{routes: routes},
		wakeRouter: router,
	}
	return s, mock
}

// TestStopForAutoSleep_CallsSwapToWake — happy path: stop + a wired
// router + matching routes → exactly one SwapToWake call with the
// container's routes.
func TestStopForAutoSleep_CallsSwapToWake(t *testing.T) {
	router := &fakeWakeRouter{}
	routes := []*app.RouteRecord{{
		ContainerName: "alice-container",
		FullDomain:    "alice.example.test",
		TargetIP:      "10.0.0.42",
		TargetPort:    8080,
		Protocol:      "http",
	}}
	s, _ := newWakeHookTestServer(t,
		map[string]*incus.ContainerInfo{"alice-container": {Name: "alice-container", State: "Running"}},
		routes, router)

	if err := s.StopForAutoSleep(testCtx(), "alice", "idle 90m", 90); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := router.wakeCount(); got != 1 {
		t.Fatalf("SwapToWake calls = %d, want 1", got)
	}
	call := router.swapToWake[0]
	if call.container != "alice-container" {
		t.Errorf("SwapToWake container = %q, want alice-container", call.container)
	}
	if len(call.routes) != 1 || call.routes[0].FullDomain != "alice.example.test" {
		t.Errorf("SwapToWake routes = %+v, want one route for alice.example.test", call.routes)
	}
}

// TestStopForAutoSleep_NilWakeRouter_NoOp — without a wakeRouter the
// stop still succeeds (backward compat with --app-hosting=off).
func TestStopForAutoSleep_NilWakeRouter_NoOp(t *testing.T) {
	s, _ := newWakeHookTestServer(t,
		map[string]*incus.ContainerInfo{"alice-container": {Name: "alice-container", State: "Running"}},
		nil, nil) // nil router

	if err := s.StopForAutoSleep(testCtx(), "alice", "idle 90m", 90); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestStopForAutoSleep_SwapToWakeError_DoesNotFailStop — if SwapToWake
// returns an error, StopForAutoSleep still returns success (the stop
// itself already happened; RouteSync will reconverge).
func TestStopForAutoSleep_SwapToWakeError_DoesNotFailStop(t *testing.T) {
	router := &fakeWakeRouter{swapToWakeErr: errors.New("caddy 502")}
	routes := []*app.RouteRecord{{ContainerName: "alice-container", FullDomain: "alice.example.test", TargetIP: "10.0.0.42", TargetPort: 8080, Protocol: "http"}}
	s, _ := newWakeHookTestServer(t,
		map[string]*incus.ContainerInfo{"alice-container": {Name: "alice-container", State: "Running"}},
		routes, router)

	if err := s.StopForAutoSleep(testCtx(), "alice", "idle 90m", 90); err != nil {
		t.Fatalf("SwapToWake failure must not fail the stop: got %v", err)
	}
}

// TestStopForAutoSleep_RouteStoreError_DoesNotFailStop — listing
// routes can fail (Postgres hiccup); the stop still succeeds.
func TestStopForAutoSleep_RouteStoreError_DoesNotFailStop(t *testing.T) {
	router := &fakeWakeRouter{}
	s := &ContainerServer{
		manager:    container.NewWithBackend(seededMock("alice-container", "Running")),
		emitter:    events.NewEmitter(events.NewBus()),
		routeStore: &memoryRouteStore{err: errors.New("pg unreachable")},
		wakeRouter: router,
	}
	if err := s.StopForAutoSleep(testCtx(), "alice", "idle 90m", 90); err != nil {
		t.Fatalf("route-store error must not fail the stop: %v", err)
	}
	if got := router.wakeCount(); got != 0 {
		t.Errorf("SwapToWake calls = %d, want 0 (no routes available)", got)
	}
}

// TestStopForAutoSleep_NoRoutes_NoSwap — container has no public route
// → no SwapToWake (wake-on-HTTP wouldn't fire anyway).
func TestStopForAutoSleep_NoRoutes_NoSwap(t *testing.T) {
	router := &fakeWakeRouter{}
	s, _ := newWakeHookTestServer(t,
		map[string]*incus.ContainerInfo{"alice-container": {Name: "alice-container", State: "Running"}},
		nil, router) // no routes

	if err := s.StopForAutoSleep(testCtx(), "alice", "idle 90m", 90); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := router.wakeCount(); got != 0 {
		t.Errorf("SwapToWake calls = %d, want 0 (no routes)", got)
	}
}

// TestStartContainer_CallsSwapToDirectWhenAutoSleepEnabled — wakeRouter
// set, info.AutoSleepEnabled=true → one SwapToDirect call.
func TestStartContainer_CallsSwapToDirectWhenAutoSleepEnabled(t *testing.T) {
	router := &fakeWakeRouter{}
	routes := []*app.RouteRecord{{
		ContainerName: "alice-container",
		FullDomain:    "alice.example.test",
		TargetIP:      "10.0.0.42",
		TargetPort:    8080,
		Protocol:      "http",
	}}
	s, _ := newWakeHookTestServer(t,
		map[string]*incus.ContainerInfo{
			"alice-container": {Name: "alice-container", State: "Stopped", IPAddress: "10.0.0.42", AutoSleepEnabled: true},
		},
		routes, router)

	_, err := s.StartContainer(testCtx(), &pb.StartContainerRequest{Username: "alice"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := router.directCount(); got != 1 {
		t.Fatalf("SwapToDirect calls = %d, want 1", got)
	}
	if router.swapToDirect[0].container != "alice-container" {
		t.Errorf("SwapToDirect container = %q, want alice-container", router.swapToDirect[0].container)
	}
}

// TestStartContainer_DoesNotCallSwapToDirectWhenAutoSleepDisabled —
// wakeRouter set, AutoSleepEnabled=false → no SwapToDirect (the
// container couldn't have been in wake mode).
func TestStartContainer_DoesNotCallSwapToDirectWhenAutoSleepDisabled(t *testing.T) {
	router := &fakeWakeRouter{}
	routes := []*app.RouteRecord{{
		ContainerName: "alice-container",
		FullDomain:    "alice.example.test",
		TargetIP:      "10.0.0.42",
		TargetPort:    8080,
		Protocol:      "http",
	}}
	s, _ := newWakeHookTestServer(t,
		map[string]*incus.ContainerInfo{
			"alice-container": {Name: "alice-container", State: "Stopped", IPAddress: "10.0.0.42", AutoSleepEnabled: false},
		},
		routes, router)

	_, err := s.StartContainer(testCtx(), &pb.StartContainerRequest{Username: "alice"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := router.directCount(); got != 0 {
		t.Errorf("SwapToDirect calls = %d, want 0 when auto-sleep disabled", got)
	}
}

// TestStartContainer_NilWakeRouter_NoOp — backward compat: start still
// succeeds without a wakeRouter wired.
func TestStartContainer_NilWakeRouter_NoOp(t *testing.T) {
	s, _ := newWakeHookTestServer(t,
		map[string]*incus.ContainerInfo{
			"alice-container": {Name: "alice-container", State: "Stopped", IPAddress: "10.0.0.42", AutoSleepEnabled: true},
		},
		nil, nil) // nil router

	_, err := s.StartContainer(testCtx(), &pb.StartContainerRequest{Username: "alice"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestStartContainer_SwapToDirectError_DoesNotFailStart — Caddy
// mutation failure must not fail the start (the container is already
// running and RouteSync will reconverge).
func TestStartContainer_SwapToDirectError_DoesNotFailStart(t *testing.T) {
	router := &fakeWakeRouter{swapToDirectErr: errors.New("caddy 502")}
	routes := []*app.RouteRecord{{ContainerName: "alice-container", FullDomain: "alice.example.test", TargetIP: "10.0.0.42", TargetPort: 8080, Protocol: "http"}}
	s, _ := newWakeHookTestServer(t,
		map[string]*incus.ContainerInfo{
			"alice-container": {Name: "alice-container", State: "Stopped", IPAddress: "10.0.0.42", AutoSleepEnabled: true},
		},
		routes, router)

	_, err := s.StartContainer(testCtx(), &pb.StartContainerRequest{Username: "alice"})
	if err != nil {
		t.Fatalf("SwapToDirect failure must not fail the start: %v", err)
	}
}

// TestStartContainer_NoRoutes_NoSwapToDirect — auto-sleep is on but
// the container has no public routes → no SwapToDirect to make.
func TestStartContainer_NoRoutes_NoSwapToDirect(t *testing.T) {
	router := &fakeWakeRouter{}
	s, _ := newWakeHookTestServer(t,
		map[string]*incus.ContainerInfo{
			"alice-container": {Name: "alice-container", State: "Stopped", IPAddress: "10.0.0.42", AutoSleepEnabled: true},
		},
		nil, router) // routes empty

	_, err := s.StartContainer(testCtx(), &pb.StartContainerRequest{Username: "alice"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := router.directCount(); got != 0 {
		t.Errorf("SwapToDirect calls = %d, want 0 with no routes", got)
	}
}

// TestStopForAutoSleep_NoRouteStoreWired_NoSwap — daemon was started
// without --app-hosting, so routeStore is nil → SwapToWake is not
// attempted (nil-safe guard on the call site).
func TestStopForAutoSleep_NoRouteStoreWired_NoSwap(t *testing.T) {
	router := &fakeWakeRouter{}
	mock := incustest.NewMockBackend()
	mock.Containers["alice-container"] = &incus.ContainerInfo{Name: "alice-container", State: "Running"}
	s := &ContainerServer{
		manager:    container.NewWithBackend(mock),
		emitter:    events.NewEmitter(events.NewBus()),
		wakeRouter: router,
		// routeStore intentionally nil
	}
	if err := s.StopForAutoSleep(testCtx(), "alice", "idle 90m", 90); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := router.wakeCount(); got != 0 {
		t.Errorf("SwapToWake calls = %d, want 0 with nil routeStore", got)
	}
}

// TestSetWakeRouter_NilSafe — passing a typed-nil router via the
// setter must keep the field nil so the hooks short-circuit cleanly.
func TestSetWakeRouter_NilSafe(t *testing.T) {
	s := &ContainerServer{}
	var nilRouter WakeRouter
	s.SetWakeRouter(nilRouter)
	if s.wakeRouter != nil {
		t.Errorf("wakeRouter = %v, want nil", s.wakeRouter)
	}
}

// seededMock builds an incustest.MockBackend pre-populated with a
// single container in the given state.
func seededMock(name, state string) *incustest.MockBackend {
	mock := incustest.NewMockBackend()
	mock.Containers[name] = &incus.ContainerInfo{Name: name, State: state}
	return mock
}
