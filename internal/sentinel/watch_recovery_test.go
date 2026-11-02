package sentinel

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/compute/apiv1/computepb"
)

func TestWatchOnly_AddedBackendNeverEntersProxyPool(t *testing.T) {
	m := NewManager(Config{}, &fakeRecoveryProvider{status: StatusRunning})
	p := &fakeRecoveryProvider{status: StatusRunning}
	m.AddWatchOnlyBackend("other-host", p)

	if m.backends.Count() != 0 {
		t.Fatalf("watch-only backend must not be added to the HTTP proxy pool; backends.Count() = %d", m.backends.Count())
	}
	if got := m.backends.Get("other-host"); got != nil {
		t.Fatalf("watch-only backend must not be reachable via backends.Get; got %+v", got)
	}
	if len(m.watchOnly) != 1 || m.watchOnly[0].id != "other-host" {
		t.Fatalf("expected exactly one watch-only entry \"other-host\", got %+v", m.watchOnly)
	}
}

func TestWatchOnly_StoppedTargetGetsStarted(t *testing.T) {
	p := &fakeRecoveryProvider{status: StatusStopped}
	m := NewManager(Config{RecoveryBackoffInitial: 30 * time.Second, RecoveryBackoffMax: 5 * time.Minute}, &fakeRecoveryProvider{})
	m.AddWatchOnlyBackend("ase1-prod", p)
	wb := m.watchOnly[0]

	m.diagnoseAndRecoverWatchOnly(context.Background(), wb)

	if p.startCalls != 1 {
		t.Fatalf("startCalls = %d, want 1", p.startCalls)
	}
	if !wb.down {
		t.Fatal("wb.down should be true after observing StatusStopped")
	}
}

func TestWatchOnly_FailedStartGrowsBackoffIndependentlyOfPrimary(t *testing.T) {
	primary := &fakeRecoveryProvider{status: StatusTerminated, startErr: errors.New("primary down too")}
	watched := &fakeRecoveryProvider{status: StatusTerminated, startErr: errors.New("no spot capacity")}
	cfg := Config{RecoveryBackoffInitial: 30 * time.Second, RecoveryBackoffMax: 5 * time.Minute}

	m, primaryBackend := newMaintenanceManager(t, primary, cfg)
	m.AddWatchOnlyBackend("ase1-prod", watched)
	wb := m.watchOnly[0]
	ctx := context.Background()

	// Drive the PRIMARY backend's recovery once — must not perturb the
	// watch-only target's independent timeline.
	m.diagnoseAndRecover(ctx, primaryBackend)
	if wb.recoveryBackoff != 0 {
		t.Fatalf("watch-only backoff should be untouched by primary recovery; got %v", wb.recoveryBackoff)
	}

	m.diagnoseAndRecoverWatchOnly(ctx, wb)
	if watched.startCalls != 1 {
		t.Fatalf("startCalls = %d, want 1", watched.startCalls)
	}
	if wb.recoveryBackoff != 30*time.Second {
		t.Fatalf("backoff after first failure = %v, want 30s", wb.recoveryBackoff)
	}
	// The primary's own backoff must likewise be unaffected by the
	// watch-only attempt.
	if m.recoveryBackoff != 30*time.Second {
		t.Fatalf("primary backoff should reflect only its own failure; got %v", m.recoveryBackoff)
	}

	// Before the window elapses, a retry must not fire again.
	m.maybeRetryWatchOnlyRecovery(ctx, wb)
	if watched.startCalls != 1 {
		t.Fatalf("re-attempt before backoff window: startCalls = %d, want still 1", watched.startCalls)
	}

	// Force the window open → re-attempts and doubles the backoff.
	wb.nextRecoveryAttempt = time.Now().Add(-time.Second)
	m.maybeRetryWatchOnlyRecovery(ctx, wb)
	if watched.startCalls != 2 {
		t.Fatalf("after window elapsed, startCalls = %d, want 2", watched.startCalls)
	}
	if wb.recoveryBackoff != 60*time.Second {
		t.Fatalf("backoff after second failure = %v, want 60s (doubled)", wb.recoveryBackoff)
	}
}

func TestWatchOnly_RecoversOnceRunning(t *testing.T) {
	p := &fakeRecoveryProvider{status: StatusTerminated, startErr: errors.New("x")}
	m := NewManager(Config{RecoveryBackoffInitial: 30 * time.Second, RecoveryBackoffMax: 5 * time.Minute}, &fakeRecoveryProvider{})
	m.AddWatchOnlyBackend("ase1-prod", p)
	wb := m.watchOnly[0]
	ctx := context.Background()

	m.diagnoseAndRecoverWatchOnly(ctx, wb)
	if !wb.down || wb.recoveryBackoff == 0 {
		t.Fatal("precondition: target should be marked down with a backoff scheduled")
	}

	p.status = StatusRunning
	m.diagnoseAndRecoverWatchOnly(ctx, wb)

	if wb.down {
		t.Fatal("wb.down should be false once StatusRunning is observed")
	}
	if wb.recoveredCount != 1 {
		t.Fatalf("recoveredCount = %d, want 1", wb.recoveredCount)
	}
	if wb.recoveryBackoff != 0 || !wb.nextRecoveryAttempt.IsZero() {
		t.Fatalf("recovery schedule should be cleared on recovery; backoff=%v next=%v", wb.recoveryBackoff, wb.nextRecoveryAttempt)
	}
}

func TestWatchOnly_RunningTargetNeverCallsStart(t *testing.T) {
	p := &fakeRecoveryProvider{status: StatusRunning}
	m := NewManager(Config{}, &fakeRecoveryProvider{})
	m.AddWatchOnlyBackend("ase1-prod", p)
	wb := m.watchOnly[0]

	m.diagnoseAndRecoverWatchOnly(context.Background(), wb)
	if p.startCalls != 0 {
		t.Fatalf("StartInstance must not be called for an already-running target; startCalls = %d", p.startCalls)
	}
}

// A watch-only target whose FIRST observed status is Provisioning (e.g.
// this sentinel started while the VM was already mid-boot) must still be
// re-checked later if it stalls or falls back to Stopped — nothing else
// drives a re-check for a watch-only target (no TCP health check, and
// EventStarted is log-only).
func TestWatchOnly_ProvisioningFirstStatusStillGetsRetried(t *testing.T) {
	p := &fakeRecoveryProvider{status: StatusProvisioning}
	m := NewManager(Config{RecoveryBackoffInitial: 30 * time.Second, RecoveryBackoffMax: 5 * time.Minute}, &fakeRecoveryProvider{})
	m.AddWatchOnlyBackend("ase1-prod", p)
	wb := m.watchOnly[0]
	ctx := context.Background()

	m.diagnoseAndRecoverWatchOnly(ctx, wb)
	if !wb.down {
		t.Fatal("wb.down should be true after observing StatusProvisioning, so a later stall/fallback still gets retried")
	}

	// Provisioning stalled and fell back to stopped.
	p.status = StatusStopped
	wb.nextRecoveryAttempt = time.Now().Add(-time.Second) // force the backoff window open
	m.maybeRetryWatchOnlyRecovery(ctx, wb)

	if p.startCalls != 1 {
		t.Fatalf("startCalls = %d, want 1 — the stall/fallback to Stopped should have been re-checked and triggered a start", p.startCalls)
	}
}

func TestWatchOnly_MultipleTargetsHaveIndependentTimelines(t *testing.T) {
	pA := &fakeRecoveryProvider{status: StatusTerminated, startErr: errors.New("a down")}
	pB := &fakeRecoveryProvider{status: StatusRunning}
	m := NewManager(Config{RecoveryBackoffInitial: 30 * time.Second, RecoveryBackoffMax: 5 * time.Minute}, &fakeRecoveryProvider{})
	m.AddWatchOnlyBackend("host-a", pA)
	m.AddWatchOnlyBackend("host-b", pB)
	ctx := context.Background()

	m.diagnoseAndRecoverWatchOnly(ctx, m.watchOnly[0])
	m.diagnoseAndRecoverWatchOnly(ctx, m.watchOnly[1])

	if !m.watchOnly[0].down || m.watchOnly[0].recoveryBackoff == 0 {
		t.Fatal("host-a should be down with a backoff scheduled")
	}
	if m.watchOnly[1].down || m.watchOnly[1].recoveryBackoff != 0 {
		t.Fatalf("host-b is healthy and must be untouched by host-a's failure; down=%v backoff=%v",
			m.watchOnly[1].down, m.watchOnly[1].recoveryBackoff)
	}
	if pB.startCalls != 0 {
		t.Fatalf("StartInstance must never be called on the healthy target; startCalls = %d", pB.startCalls)
	}
}

// A Spot preemption is recorded by GCE as its own zone operation type,
// compute.instances.preempted, not as a stop (cloud#3377). The watcher must list it and map it
// to EventPreempted, or a preempted watch-only target is never restarted.
func TestOperationToEvent_PreemptedOperation(t *testing.T) {
	g := &GCPProvider{}
	op := &computepb.Operation{OperationType: ptr("compute.instances.preempted")}
	ev := g.operationToEvent(op, time.Unix(100, 0))
	if ev == nil || ev.Type != EventPreempted {
		t.Fatalf("compute.instances.preempted must map to EventPreempted; got %+v", ev)
	}
}

func TestOperationToEvent_StopAndStartUnchanged(t *testing.T) {
	g := &GCPProvider{}
	if ev := g.operationToEvent(&computepb.Operation{OperationType: ptr("compute.instances.stop")}, time.Now()); ev == nil || ev.Type != EventStopped {
		t.Fatalf("a plain stop must stay EventStopped; got %+v", ev)
	}
	msg := "Instance was preempted."
	if ev := g.operationToEvent(&computepb.Operation{OperationType: ptr("compute.instances.stop"), StatusMessage: &msg}, time.Now()); ev == nil || ev.Type != EventPreempted {
		t.Fatalf("a stop whose message says preempted must stay EventPreempted; got %+v", ev)
	}
	if ev := g.operationToEvent(&computepb.Operation{OperationType: ptr("compute.instances.start")}, time.Now()); ev == nil || ev.Type != EventStarted {
		t.Fatalf("a start must stay EventStarted; got %+v", ev)
	}
}

func TestOperationFilter_ListsPreemptedOperations(t *testing.T) {
	f := operationFilter("vm-1")
	for _, want := range []string{"compute.instances.stop", "compute.instances.start", "compute.instances.delete", "compute.instances.preempted", "*/instances/vm-1"} {
		if !strings.Contains(f, want) {
			t.Fatalf("operation filter %q does not mention %q", f, want)
		}
	}
}

// Safety net: when no event arrives (a new operation type, a gap in the operations list, a
// sentinel restart that missed the window), the ticker still reads the instance status
// at most once per watchOnlyStatusPollInterval and starts a VM that is down.
func TestWatchOnly_StatusPollStartsATargetWhoseEventWasMissed(t *testing.T) {
	p := &fakeRecoveryProvider{status: StatusRunning}
	m := NewManager(Config{RecoveryBackoffInitial: 30 * time.Second, RecoveryBackoffMax: 5 * time.Minute}, &fakeRecoveryProvider{})
	m.AddWatchOnlyBackend("host-a", p)
	wb := m.watchOnly[0]
	ctx := context.Background()

	m.diagnoseAndRecoverWatchOnly(ctx, wb) // startup check: running
	if wb.down {
		t.Fatal("precondition: target is up")
	}

	p.status = StatusTerminated // preempted; no event delivered
	m.maybeRetryWatchOnlyRecovery(ctx, wb)
	if p.startCalls != 0 {
		t.Fatalf("a poll right after the last status read must not hit the API again; startCalls = %d", p.startCalls)
	}

	wb.lastStatusCheck = time.Now().Add(-2 * watchOnlyStatusPollInterval)
	m.maybeRetryWatchOnlyRecovery(ctx, wb)
	if p.startCalls != 1 {
		t.Fatalf("the status poll must start a terminated target; startCalls = %d, want 1", p.startCalls)
	}
	if !wb.down {
		t.Fatal("wb.down should be true after the poll found the target terminated")
	}
	if wb.preemptCount != 1 {
		t.Fatalf("a missed outage must still be counted; preemptCount = %d, want 1", wb.preemptCount)
	}
}

func TestWatchOnly_StatusPollOnAHealthyTargetStartsNothing(t *testing.T) {
	p := &fakeRecoveryProvider{status: StatusRunning}
	m := NewManager(Config{}, &fakeRecoveryProvider{})
	m.AddWatchOnlyBackend("host-a", p)
	wb := m.watchOnly[0]
	wb.lastStatusCheck = time.Now().Add(-2 * watchOnlyStatusPollInterval)

	m.maybeRetryWatchOnlyRecovery(context.Background(), wb)

	if p.startCalls != 0 || wb.down || wb.preemptCount != 0 {
		t.Fatalf("a running target must be left alone; startCalls=%d down=%v preemptCount=%d", p.startCalls, wb.down, wb.preemptCount)
	}
}
