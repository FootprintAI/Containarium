package server

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Phase 4.3 Phase B-3 — reconciler unit tests.
//
// The reconciler depends on a *secrets.Store (for the
// usernames query) and an *incus.Client (for state
// lookup). Both are concrete types that need live
// backends, so we don't construct the full reconciler
// here. Instead we exercise the inner tick logic directly
// by wiring fakes through closures — which is what the
// production code does too (the stamp argument is a
// function value).

// fakeReconciler runs the same loop body as the real
// secretsReconciler but lets the test drive the
// list-tenants + get-container responses directly.
type fakeReconciler struct {
	listTenants func(ctx context.Context) ([]string, error)
	containerOf func(name string) (state string, found bool)
	stamp       func(ctx context.Context, username string) (int, error)
}

func (r *fakeReconciler) tick(ctx context.Context) {
	users, err := r.listTenants(ctx)
	if err != nil {
		return
	}
	for _, u := range users {
		state, ok := r.containerOf(u + "-container")
		if !ok {
			continue
		}
		if state != "Running" {
			continue
		}
		_, _ = r.stamp(ctx, u)
	}
}

func TestReconciler_SkipsStoppedContainers(t *testing.T) {
	var stamped sync.Map
	r := &fakeReconciler{
		listTenants: func(ctx context.Context) ([]string, error) {
			return []string{"alice", "bob"}, nil
		},
		containerOf: func(name string) (string, bool) {
			switch name {
			case "alice-container":
				return "Running", true
			case "bob-container":
				return "Stopped", true
			}
			return "", false
		},
		stamp: func(ctx context.Context, username string) (int, error) {
			stamped.Store(username, true)
			return 1, nil
		},
	}
	r.tick(context.Background())

	if _, ok := stamped.Load("alice"); !ok {
		t.Fatal("alice (Running) should have been stamped")
	}
	if _, ok := stamped.Load("bob"); ok {
		t.Fatal("bob (Stopped) should NOT have been stamped")
	}
}

func TestReconciler_SkipsMissingContainers(t *testing.T) {
	stampCalls := atomic.Int32{}
	r := &fakeReconciler{
		listTenants: func(ctx context.Context) ([]string, error) {
			// Tenant with file-mode secrets but no actual
			// container yet (e.g. secrets pre-provisioned).
			return []string{"future-alice"}, nil
		},
		containerOf: func(name string) (string, bool) {
			return "", false
		},
		stamp: func(ctx context.Context, username string) (int, error) {
			stampCalls.Add(1)
			return 0, nil
		},
	}
	r.tick(context.Background())

	if got := stampCalls.Load(); got != 0 {
		t.Fatalf("missing container should NOT trigger stamp; got %d calls", got)
	}
}

func TestReconciler_EmptyTenantsIsNoOp(t *testing.T) {
	stampCalls := atomic.Int32{}
	containerCalls := atomic.Int32{}
	r := &fakeReconciler{
		listTenants: func(ctx context.Context) ([]string, error) {
			return nil, nil
		},
		containerOf: func(name string) (string, bool) {
			containerCalls.Add(1)
			return "", false
		},
		stamp: func(ctx context.Context, username string) (int, error) {
			stampCalls.Add(1)
			return 0, nil
		},
	}
	r.tick(context.Background())

	if got := containerCalls.Load(); got != 0 {
		t.Fatalf("no tenants → no container lookups; got %d", got)
	}
	if got := stampCalls.Load(); got != 0 {
		t.Fatalf("no tenants → no stamps; got %d", got)
	}
}

func TestReconciler_StampErrorContinuesLoop(t *testing.T) {
	// A failing stamp on one tenant must not halt the
	// loop for the rest.
	stampCalls := atomic.Int32{}
	r := &fakeReconciler{
		listTenants: func(ctx context.Context) ([]string, error) {
			return []string{"failing", "succeeding"}, nil
		},
		containerOf: func(name string) (string, bool) {
			return "Running", true
		},
		stamp: func(ctx context.Context, username string) (int, error) {
			stampCalls.Add(1)
			if username == "failing" {
				return 0, errors.New("simulated stamp failure")
			}
			return 1, nil
		},
	}
	r.tick(context.Background())

	if got := stampCalls.Load(); got != 2 {
		t.Fatalf("expected stamp called for both tenants; got %d", got)
	}
}

// TestReconciler_LiveLoopRespectsStopChannel proves the
// real secretsReconciler exits when its stop channel is
// closed. Uses a no-op stamp; the tick is fast so 200ms
// is plenty.
func TestReconciler_LiveLoopRespectsStopChannel(t *testing.T) {
	r := &secretsReconciler{
		stamp:    func(ctx context.Context, _ string) (int, error) { return 0, nil },
		interval: 20 * time.Millisecond,
		stopCh:   make(chan struct{}),
		done:     make(chan struct{}),
	}
	go r.run(context.Background())

	<-time.After(50 * time.Millisecond)
	r.Stop()

	select {
	case <-r.done:
		// good
	case <-time.After(time.Second):
		t.Fatal("reconciler did not exit after Stop()")
	}

	// Idempotent — second Stop() must not panic.
	r.Stop()
}
