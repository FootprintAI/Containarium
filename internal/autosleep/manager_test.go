package autosleep

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// --- fakes ---

type fakeIncus struct {
	containers []incus.ContainerInfo
	err        error
}

func (f *fakeIncus) ListContainers() ([]incus.ContainerInfo, error) {
	return f.containers, f.err
}

type fakeTraffic struct {
	per map[string]time.Time
	err error
}

func (f *fakeTraffic) LastNetworkActivity(_ context.Context, name string) (time.Time, error) {
	if f.err != nil {
		return time.Time{}, f.err
	}
	return f.per[name], nil
}

type stopperCall struct {
	username    string
	reason      string
	idleMinutes int
}

type fakeStopper struct {
	mu    sync.Mutex
	calls []stopperCall
}

func (f *fakeStopper) StopForAutoSleep(_ context.Context, username, reason string, idleMinutes int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, stopperCall{username: username, reason: reason, idleMinutes: idleMinutes})
	return nil
}

func (f *fakeStopper) recorded() []stopperCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]stopperCall, len(f.calls))
	copy(out, f.calls)
	return out
}

type auditCall struct {
	event  string
	fields map[string]any
}

type fakeAudit struct {
	mu    sync.Mutex
	calls []auditCall
}

func (f *fakeAudit) Log(event string, fields map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, auditCall{event: event, fields: fields})
}

func (f *fakeAudit) recorded() []auditCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]auditCall, len(f.calls))
	copy(out, f.calls)
	return out
}

// --- tests ---

// TestManager_TickStopsIdleContainersAndAudits is the happy path:
// three containers in one tick — one idle user container sleeps, one
// recently-active user container is left alone, one core container is
// always left alone even with autosleep on (defense in depth — we
// shouldn't see core containers with the flag in practice).
func TestManager_TickStopsIdleContainersAndAudits(t *testing.T) {
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	inc := &fakeIncus{
		containers: []incus.ContainerInfo{
			{
				Name:                 "alice-container",
				State:                "Running",
				AutoSleepEnabled:     true,
				IdleThresholdMinutes: 15,
				LastStartedAt:        now.Add(-2 * time.Hour),
			},
			{
				Name:                 "bob-container",
				State:                "Running",
				AutoSleepEnabled:     true,
				IdleThresholdMinutes: 15,
				LastStartedAt:        now.Add(-2 * time.Hour),
			},
			{
				Name:                 "containarium-core-postgres",
				State:                "Running",
				AutoSleepEnabled:     true, // shouldn't matter — core gate dominates.
				IdleThresholdMinutes: 15,
				Role:                 incus.RolePostgres,
				LastStartedAt:        now.Add(-2 * time.Hour),
			},
		},
	}
	traffic := &fakeTraffic{
		per: map[string]time.Time{
			"alice-container": now.Add(-90 * time.Minute), // idle 90m -> sleep
			"bob-container":   now.Add(-2 * time.Minute),  // idle 2m -> nothing
		},
	}
	stopper := &fakeStopper{}
	audit := &fakeAudit{}

	m := NewManager(inc, traffic, stopper, audit, Options{
		Interval: time.Hour, // never fires; we call tick directly.
		Clock:    func() time.Time { return now },
	})
	m.tick(context.Background())

	calls := stopper.recorded()
	if len(calls) != 1 {
		t.Fatalf("expected 1 stop call, got %d: %+v", len(calls), calls)
	}
	if calls[0].username != "alice" {
		t.Errorf("stopped username = %q, want alice", calls[0].username)
	}
	if calls[0].idleMinutes < 90 {
		t.Errorf("idle minutes = %d, want >= 90", calls[0].idleMinutes)
	}

	audits := audit.recorded()
	if len(audits) != 1 {
		t.Fatalf("expected 1 audit entry, got %d", len(audits))
	}
	if audits[0].event != "autosleep.stopped" {
		t.Errorf("audit event = %q, want autosleep.stopped", audits[0].event)
	}
	if audits[0].fields["username"] != "alice" {
		t.Errorf("audit username = %v, want alice", audits[0].fields["username"])
	}
}

// TestManager_NilTrafficFallsBackToSinceStart locks down the "no
// traffic store wired" code path: Decide still produces a sleep
// based on since-start time and the manager honors it.
func TestManager_NilTrafficFallsBackToSinceStart(t *testing.T) {
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	inc := &fakeIncus{
		containers: []incus.ContainerInfo{
			{
				Name:                 "alice-container",
				State:                "Running",
				AutoSleepEnabled:     true,
				IdleThresholdMinutes: 15,
				LastStartedAt:        now.Add(-2 * time.Hour), // outside anti-thrash, way past threshold
			},
		},
	}
	stopper := &fakeStopper{}
	m := NewManager(inc, nil /* no traffic */, stopper, nil /* no audit, log.Printf fallback */, Options{
		Clock: func() time.Time { return now },
	})
	m.tick(context.Background())

	if calls := stopper.recorded(); len(calls) != 1 {
		t.Fatalf("expected 1 stop call, got %d", len(calls))
	}
}
