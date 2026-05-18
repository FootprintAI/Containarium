package autosleep

import (
	"bytes"
	"context"
	"errors"
	"log"
	"runtime"
	"sync"
	"sync/atomic"
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
	// errs, if non-nil, returns one error per call by index. A short
	// slice means later calls fall back to nil — same semantics as
	// "first call fails, rest succeed".
	errs []error
}

func (f *fakeStopper) StopForAutoSleep(_ context.Context, username, reason string, idleMinutes int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	idx := len(f.calls)
	f.calls = append(f.calls, stopperCall{username: username, reason: reason, idleMinutes: idleMinutes})
	if idx < len(f.errs) {
		return f.errs[idx]
	}
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

// TestManager_MultipleContainersSomeSleepSomeDont mixes the full menu
// in a single tick: opted-in & idle, opted-in & active, not opted-in,
// and a core container. The tick must produce exactly one Stop call
// and exactly one audit entry — the idle opt-in.
func TestManager_MultipleContainersSomeSleepSomeDont(t *testing.T) {
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	inc := &fakeIncus{
		containers: []incus.ContainerInfo{
			{ // sleeps
				Name:                 "alice-container",
				State:                "Running",
				AutoSleepEnabled:     true,
				IdleThresholdMinutes: 15,
				LastStartedAt:        now.Add(-2 * time.Hour),
			},
			{ // active, doesn't sleep
				Name:                 "bob-container",
				State:                "Running",
				AutoSleepEnabled:     true,
				IdleThresholdMinutes: 15,
				LastStartedAt:        now.Add(-2 * time.Hour),
			},
			{ // not opted in
				Name:                 "carol-container",
				State:                "Running",
				AutoSleepEnabled:     false,
				IdleThresholdMinutes: 15,
				LastStartedAt:        now.Add(-2 * time.Hour),
			},
			{ // core role
				Name:                 "containarium-core-postgres",
				State:                "Running",
				AutoSleepEnabled:     true,
				IdleThresholdMinutes: 15,
				Role:                 incus.RolePostgres,
				LastStartedAt:        now.Add(-2 * time.Hour),
			},
		},
	}
	traffic := &fakeTraffic{per: map[string]time.Time{
		"alice-container":   now.Add(-90 * time.Minute), // idle
		"bob-container":     now.Add(-1 * time.Minute),  // active
		"carol-container":   now.Add(-90 * time.Minute), // would-sleep, but not opted in
	}}
	stopper := &fakeStopper{}
	audit := &fakeAudit{}
	m := NewManager(inc, traffic, stopper, audit, Options{
		Interval: time.Hour,
		Clock:    func() time.Time { return now },
	})
	m.tick(context.Background())

	calls := stopper.recorded()
	if len(calls) != 1 {
		t.Fatalf("expected exactly 1 stop, got %d: %+v", len(calls), calls)
	}
	if calls[0].username != "alice" {
		t.Errorf("stopped username = %q, want alice", calls[0].username)
	}
	if audits := audit.recorded(); len(audits) != 1 {
		t.Fatalf("expected exactly 1 audit, got %d", len(audits))
	}
}

// TestManager_IncusListError_LogsAndContinues — ListContainers
// failure on tick #1 must not crash; tick #2 with a working list
// proceeds normally. Verifies the loop survives transient incus
// errors (the documented design).
func TestManager_IncusListError_LogsAndContinues(t *testing.T) {
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)

	inc := &fakeIncus{err: errors.New("incus offline")}
	stopper := &fakeStopper{}
	m := NewManager(inc, nil, stopper, nil, Options{
		Interval: time.Hour,
		Clock:    func() time.Time { return now },
	})
	// Tick #1: error path — must not panic and must not call Stop.
	m.tick(context.Background())
	if calls := stopper.recorded(); len(calls) != 0 {
		t.Fatalf("error tick must not call Stop, got %+v", calls)
	}

	// Tick #2: recover, normal eligible container should sleep.
	inc.err = nil
	inc.containers = []incus.ContainerInfo{{
		Name:                 "alice-container",
		State:                "Running",
		AutoSleepEnabled:     true,
		IdleThresholdMinutes: 15,
		LastStartedAt:        now.Add(-2 * time.Hour),
	}}
	m.tick(context.Background())
	if calls := stopper.recorded(); len(calls) != 1 {
		t.Fatalf("post-recovery tick should sleep once, got %d", len(calls))
	}
}

// TestManager_StopperError_ContinuesWithOthers — when the first
// stop fails, the second eligible container still gets stopped.
// One per-container failure must not poison the rest of the tick.
func TestManager_StopperError_ContinuesWithOthers(t *testing.T) {
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	inc := &fakeIncus{
		containers: []incus.ContainerInfo{
			{
				Name: "alice-container", State: "Running",
				AutoSleepEnabled: true, IdleThresholdMinutes: 15,
				LastStartedAt: now.Add(-2 * time.Hour),
			},
			{
				Name: "bob-container", State: "Running",
				AutoSleepEnabled: true, IdleThresholdMinutes: 15,
				LastStartedAt: now.Add(-2 * time.Hour),
			},
		},
	}
	traffic := &fakeTraffic{per: map[string]time.Time{
		"alice-container": now.Add(-90 * time.Minute),
		"bob-container":   now.Add(-90 * time.Minute),
	}}
	stopper := &fakeStopper{errs: []error{errors.New("stop boom")}}
	audit := &fakeAudit{}

	// Capture log output to verify the error is logged.
	var buf bytes.Buffer
	defer log.SetOutput(log.Writer())
	log.SetOutput(&buf)

	m := NewManager(inc, traffic, stopper, audit, Options{
		Interval: time.Hour,
		Clock:    func() time.Time { return now },
	})
	m.tick(context.Background())

	calls := stopper.recorded()
	if len(calls) != 2 {
		t.Fatalf("both containers should be attempted, got %d: %+v", len(calls), calls)
	}
	// The successful one (second) must produce an audit; failure (first) must not.
	if audits := audit.recorded(); len(audits) != 1 {
		t.Fatalf("expected exactly 1 audit (only the successful Stop), got %d", len(audits))
	}
	if !bytes.Contains(buf.Bytes(), []byte("stop boom")) {
		t.Errorf("stopper error not logged; output:\n%s", buf.String())
	}
}

// TestManager_NilTrafficSource_DegradesGracefully — nil TrafficSource
// must not panic; behavior collapses to Decide's rule 5 (no-signal
// fallback). Locks the constructor's "nil traffic is allowed" contract.
func TestManager_NilTrafficSource_DegradesGracefully(t *testing.T) {
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	inc := &fakeIncus{
		containers: []incus.ContainerInfo{
			{ // since-start path: 2h since start, threshold 15m → sleep
				Name: "alice-container", State: "Running",
				AutoSleepEnabled: true, IdleThresholdMinutes: 15,
				LastStartedAt: now.Add(-2 * time.Hour),
			},
			{ // no last-start either → undecidable
				Name: "bob-container", State: "Running",
				AutoSleepEnabled: true, IdleThresholdMinutes: 15,
			},
		},
	}
	stopper := &fakeStopper{}
	m := NewManager(inc, nil, stopper, nil, Options{
		Interval: time.Hour,
		Clock:    func() time.Time { return now },
	})
	m.tick(context.Background())
	calls := stopper.recorded()
	if len(calls) != 1 {
		t.Fatalf("expected exactly 1 stop (since-start path), got %d: %+v", len(calls), calls)
	}
	if calls[0].username != "alice" {
		t.Errorf("stopped %q, want alice", calls[0].username)
	}
}

// TestManager_NilAuditLogger_NoPanic — nil AuditLogger falls back to
// log.Printf; Stop still runs. Locks "audit is optional".
func TestManager_NilAuditLogger_NoPanic(t *testing.T) {
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	inc := &fakeIncus{
		containers: []incus.ContainerInfo{{
			Name: "alice-container", State: "Running",
			AutoSleepEnabled: true, IdleThresholdMinutes: 15,
			LastStartedAt: now.Add(-2 * time.Hour),
		}},
	}
	traffic := &fakeTraffic{per: map[string]time.Time{
		"alice-container": now.Add(-90 * time.Minute),
	}}
	stopper := &fakeStopper{}

	var buf bytes.Buffer
	defer log.SetOutput(log.Writer())
	log.SetOutput(&buf)

	m := NewManager(inc, traffic, stopper, nil, Options{
		Interval: time.Hour,
		Clock:    func() time.Time { return now },
	})
	m.tick(context.Background()) // must not panic
	if calls := stopper.recorded(); len(calls) != 1 {
		t.Fatalf("expected 1 stop, got %d", len(calls))
	}
	if !bytes.Contains(buf.Bytes(), []byte("[autosleep] stopped")) {
		t.Errorf("expected log.Printf fallback for audit, output:\n%s", buf.String())
	}
}

// TestManager_StopIsIdempotent — Stop called twice must not panic and
// must complete quickly both times. Uses a short interval so the
// ticker is actively firing during the Stop window, which is the
// stress shape that previously deadlocked Stop against the run loop.
func TestManager_StopIsIdempotent(t *testing.T) {
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	m := NewManager(&fakeIncus{}, nil, &fakeStopper{}, nil, Options{
		Interval: 25 * time.Millisecond,
		Clock:    func() time.Time { return now },
	})
	m.Start(context.Background())
	time.Sleep(75 * time.Millisecond) // let several ticks fire

	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		m.Stop()
	}()
	select {
	case <-firstDone:
	case <-time.After(2 * time.Second):
		t.Fatal("first Stop() blocked >2s")
	}

	secondDone := make(chan struct{})
	go func() {
		defer close(secondDone)
		m.Stop()
	}()
	select {
	case <-secondDone:
	case <-time.After(time.Second):
		t.Fatal("second Stop() blocked >1s; expected no-op")
	}
}

// TestManager_ContextCancellationStopsTicker — Start(ctx) with a
// canceled ctx exits the run loop within a tick interval.
func TestManager_ContextCancellationStopsTicker(t *testing.T) {
	before := runtime.NumGoroutine()
	ctx, cancel := context.WithCancel(context.Background())
	m := NewManager(&fakeIncus{}, nil, &fakeStopper{}, nil, Options{
		Interval: 25 * time.Millisecond,
	})
	m.Start(ctx)
	time.Sleep(75 * time.Millisecond) // let several ticks fire

	cancel()
	// Give the goroutine a chance to exit. The select wakes on ctx.Done().
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= before+1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// One residual goroutine tolerance — the test harness itself may
	// leave one floating depending on scheduling.
	if got := runtime.NumGoroutine(); got > before+1 {
		t.Errorf("goroutine leak: before=%d after=%d", before, got)
	}
	_ = m // keep ref alive until end of test to discourage GC paths
}

// TestManager_AntiThrashFalseNegativeWhenLastStartedAtUnset codifies
// the peer-forward gap noted in the Phase 2 design discussion: when a
// container has no LastStartedAt stamp (e.g. peer-forwarded
// StartContainer doesn't stamp the key), Decide treats it as zero and
// the anti-thrash window is bypassed. The container can then be
// sleep-bombed immediately. Skipped today; remove the skip if the
// peer-forward path is updated to stamp the key.
func TestManager_AntiThrashFalseNegativeWhenLastStartedAtUnset(t *testing.T) {
	t.Skip("known gap: peer-forward StartContainer doesn't stamp LastStartedAtKey, " +
		"so a freshly woken container on a peer has LastStartedAt=zero and " +
		"bypasses the anti-thrash window; track in a follow-up.")

	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	inc := &fakeIncus{containers: []incus.ContainerInfo{{
		Name: "alice-container", State: "Running",
		AutoSleepEnabled: true, IdleThresholdMinutes: 15,
		// LastStartedAt intentionally zero — peer wake skipped the stamp.
		LastStartedAt: time.Time{},
	}}}
	traffic := &fakeTraffic{per: map[string]time.Time{
		"alice-container": now.Add(-2 * time.Minute), // user *just* woke it
	}}
	stopper := &fakeStopper{}
	m := NewManager(inc, traffic, stopper, nil, Options{
		Interval: time.Hour,
		Clock:    func() time.Time { return now },
	})
	m.tick(context.Background())
	// If the gap is fixed, this assertion holds:
	if calls := stopper.recorded(); len(calls) != 0 {
		t.Errorf("anti-thrash should have protected a just-woken container, "+
			"but it was stopped: %+v", calls)
	}
}

// TestManager_StartIsNonBlocking — Start spawns the loop and returns
// immediately. A blocked Start would hang DualServer.Start.
func TestManager_StartIsNonBlocking(t *testing.T) {
	var ticks int64
	inc := &fakeIncusCounting{count: &ticks}
	m := NewManager(inc, nil, &fakeStopper{}, nil, Options{
		Interval: 25 * time.Millisecond,
	})
	startReturned := make(chan struct{})
	go func() {
		m.Start(context.Background())
		close(startReturned)
	}()
	select {
	case <-startReturned:
	case <-time.After(time.Second):
		t.Fatal("Start did not return within 1s — possible blocking call")
	}
	deadline := time.Now().Add(time.Second)
	for atomic.LoadInt64(&ticks) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if atomic.LoadInt64(&ticks) == 0 {
		t.Fatal("ticker never fired within 1s")
	}
	m.Stop()
}

// fakeIncusCounting counts ListContainers calls — used by the tick
// loop tests where we want to observe the ticker firing without the
// state of the rest of the manager.
type fakeIncusCounting struct {
	count *int64
}

func (f *fakeIncusCounting) ListContainers() ([]incus.ContainerInfo, error) {
	atomic.AddInt64(f.count, 1)
	return nil, nil
}
