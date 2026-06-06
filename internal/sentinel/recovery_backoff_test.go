package sentinel

import (
	"context"
	"errors"
	"testing"
	"time"
)

// fakeRecoveryProvider is a CloudProvider whose status and StartInstance
// behavior the test drives, counting StartInstance calls. Used to exercise
// the #514 periodic-recovery + backoff logic without a real cloud.
type fakeRecoveryProvider struct {
	status     InstanceStatus
	startErr   error // returned by StartInstance (nil = accepted)
	startCalls int
}

func (f *fakeRecoveryProvider) GetInstanceStatus(context.Context) (InstanceStatus, error) {
	return f.status, nil
}
func (f *fakeRecoveryProvider) GetInstanceIP(context.Context) (string, error) { return "10.0.0.1", nil }
func (f *fakeRecoveryProvider) StartInstance(context.Context) error {
	f.startCalls++
	return f.startErr
}

// newMaintenanceManager builds a Manager pinned in maintenance with a
// single provider-backed GCP backend, ready to exercise recovery.
func newMaintenanceManager(t *testing.T, p *fakeRecoveryProvider, cfg Config) (*Manager, *Backend) {
	t.Helper()
	m := NewManager(cfg, p)
	m.state.Store(StateMaintenance)
	b := &Backend{ID: "gcp", Type: BackendGCP, IP: "10.0.0.1", Provider: p, Healthy: false}
	m.backends.Add(b)
	return m, b
}

func TestRecovery_DefaultsApplied(t *testing.T) {
	m := NewManager(Config{}, &fakeRecoveryProvider{})
	if m.config.RecoveryBackoffInitial != 30*time.Second {
		t.Errorf("initial default = %v, want 30s", m.config.RecoveryBackoffInitial)
	}
	if m.config.RecoveryBackoffMax != 5*time.Minute {
		t.Errorf("max default = %v, want 5m", m.config.RecoveryBackoffMax)
	}
	// Max < Initial is clamped up to Initial.
	m2 := NewManager(Config{RecoveryBackoffInitial: time.Minute, RecoveryBackoffMax: time.Second}, &fakeRecoveryProvider{})
	if m2.config.RecoveryBackoffMax < m2.config.RecoveryBackoffInitial {
		t.Errorf("max (%v) should be clamped >= initial (%v)", m2.config.RecoveryBackoffMax, m2.config.RecoveryBackoffInitial)
	}
}

func TestRecovery_FailedStartGrowsBackoffAndRetries(t *testing.T) {
	p := &fakeRecoveryProvider{status: StatusTerminated, startErr: errors.New("no spot capacity")}
	cfg := Config{RecoveryBackoffInitial: 30 * time.Second, RecoveryBackoffMax: 5 * time.Minute}
	m, _ := newMaintenanceManager(t, p, cfg)
	ctx := context.Background()

	// First attempt (the transition-time call).
	m.diagnoseAndRecover(ctx, m.backends.Get("gcp"))
	if p.startCalls != 1 {
		t.Fatalf("after first attempt, startCalls = %d, want 1", p.startCalls)
	}
	if m.recoveryBackoff != 30*time.Second {
		t.Fatalf("backoff after first failure = %v, want 30s", m.recoveryBackoff)
	}

	// Before the window elapses, maybeRetryRecovery must NOT re-attempt.
	m.maybeRetryRecovery(ctx)
	if p.startCalls != 1 {
		t.Fatalf("re-attempt before backoff window: startCalls = %d, want still 1", p.startCalls)
	}

	// Force the window open → it re-attempts and doubles the backoff.
	m.nextRecoveryAttempt = time.Now().Add(-time.Second)
	m.maybeRetryRecovery(ctx)
	if p.startCalls != 2 {
		t.Fatalf("after window elapsed, startCalls = %d, want 2", p.startCalls)
	}
	if m.recoveryBackoff != 60*time.Second {
		t.Fatalf("backoff after second failure = %v, want 60s (doubled)", m.recoveryBackoff)
	}
}

func TestRecovery_BackoffCapsAtMax(t *testing.T) {
	p := &fakeRecoveryProvider{status: StatusTerminated, startErr: errors.New("no capacity")}
	cfg := Config{RecoveryBackoffInitial: time.Minute, RecoveryBackoffMax: 3 * time.Minute}
	m, _ := newMaintenanceManager(t, p, cfg)
	ctx := context.Background()

	// Drive many failures; backoff must never exceed Max (1→2→3→3→3...).
	m.diagnoseAndRecover(ctx, m.backends.Get("gcp")) // 1m
	for i := 0; i < 6; i++ {
		m.nextRecoveryAttempt = time.Now().Add(-time.Second)
		m.maybeRetryRecovery(ctx)
		if m.recoveryBackoff > cfg.RecoveryBackoffMax {
			t.Fatalf("backoff %v exceeded max %v", m.recoveryBackoff, cfg.RecoveryBackoffMax)
		}
	}
	if m.recoveryBackoff != cfg.RecoveryBackoffMax {
		t.Fatalf("backoff settled at %v, want the cap %v", m.recoveryBackoff, cfg.RecoveryBackoffMax)
	}
}

func TestRecovery_NoOpOutsideMaintenance(t *testing.T) {
	p := &fakeRecoveryProvider{status: StatusTerminated, startErr: errors.New("x")}
	m, _ := newMaintenanceManager(t, p, Config{})
	m.state.Store(StateProxy) // not in maintenance
	m.maybeRetryRecovery(context.Background())
	if p.startCalls != 0 {
		t.Fatalf("maybeRetryRecovery should be a no-op outside maintenance; startCalls = %d", p.startCalls)
	}
}

func TestRecovery_SuccessfulStartSchedulesInitial(t *testing.T) {
	p := &fakeRecoveryProvider{status: StatusTerminated, startErr: nil} // start accepted
	cfg := Config{RecoveryBackoffInitial: 30 * time.Second, RecoveryBackoffMax: 5 * time.Minute}
	m, _ := newMaintenanceManager(t, p, cfg)

	m.diagnoseAndRecover(context.Background(), m.backends.Get("gcp"))
	if p.startCalls != 1 {
		t.Fatalf("startCalls = %d, want 1", p.startCalls)
	}
	// A successful start re-probes at the initial interval (not grown).
	if m.recoveryBackoff != cfg.RecoveryBackoffInitial {
		t.Fatalf("backoff after successful start = %v, want initial %v", m.recoveryBackoff, cfg.RecoveryBackoffInitial)
	}
	if m.nextRecoveryAttempt.IsZero() {
		t.Fatal("a next attempt should be scheduled after a successful start")
	}
}

func TestRecovery_ResetClearsSchedule(t *testing.T) {
	p := &fakeRecoveryProvider{status: StatusTerminated, startErr: errors.New("x")}
	m, _ := newMaintenanceManager(t, p, Config{})
	m.diagnoseAndRecover(context.Background(), m.backends.Get("gcp"))
	if m.nextRecoveryAttempt.IsZero() || m.recoveryBackoff == 0 {
		t.Fatal("precondition: a schedule should exist after a failed attempt")
	}
	m.resetRecovery()
	if !m.nextRecoveryAttempt.IsZero() || m.recoveryBackoff != 0 {
		t.Fatalf("resetRecovery should clear the schedule; got backoff=%v next=%v", m.recoveryBackoff, m.nextRecoveryAttempt)
	}
}

func TestRecovery_RunningStatusDoesNotStart(t *testing.T) {
	// Cloud says running but TCP health failed — starting won't help and
	// must not be attempted.
	p := &fakeRecoveryProvider{status: StatusRunning}
	m, _ := newMaintenanceManager(t, p, Config{})
	m.diagnoseAndRecover(context.Background(), m.backends.Get("gcp"))
	if p.startCalls != 0 {
		t.Fatalf("StartInstance must not be called for a running backend; startCalls = %d", p.startCalls)
	}
}
