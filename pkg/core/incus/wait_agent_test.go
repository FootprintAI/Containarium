package incus

import (
	"errors"
	"testing"
	"time"
)

// TestWaitForAgent_ImmediateSuccessDoesNotSleep: an agent that is already
// reachable returns on the first attempt without polling at all.
func TestWaitForAgent_ImmediateSuccessDoesNotSleep(t *testing.T) {
	calls := 0
	start := time.Now()
	err := waitForAgent(30*time.Second, func() error {
		calls++
		return nil
	})
	if err != nil {
		t.Fatalf("waitForAgent err = %v, want nil", err)
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1", calls)
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Errorf("elapsed = %v, want ~0 for an immediate success", elapsed)
	}
}

// TestWaitForAgent_RetriesUntilTheAgentComesUp is the regression test for
// #1862: the guest agent is not reachable on the first attempts (mirroring
// Incus's "VM agent isn't currently running") and becomes reachable a few
// polls later. Unlike waitForIP, every error here is a retry signal, not
// an immediate failure.
func TestWaitForAgent_RetriesUntilTheAgentComesUp(t *testing.T) {
	agentOffline := errors.New("VM agent isn't currently running")
	calls := 0
	err := waitForAgent(30*time.Second, func() error {
		calls++
		if calls < 4 {
			return agentOffline
		}
		return nil
	})
	if err != nil {
		t.Fatalf("waitForAgent err = %v, want nil", err)
	}
	if calls != 4 {
		t.Errorf("calls = %d, want 4 — the agent-offline error must be retried, not returned immediately", calls)
	}
}

// TestWaitForAgent_TimesOutAndWrapsTheLastError: an agent that never comes
// up within budget must fail with a timeout that still carries the
// underlying cause, not swallow it.
func TestWaitForAgent_TimesOutAndWrapsTheLastError(t *testing.T) {
	agentOffline := errors.New("VM agent isn't currently running")
	err := waitForAgent(300*time.Millisecond, func() error {
		return agentOffline
	})
	if err == nil {
		t.Fatal("waitForAgent err = nil, want timeout")
	}
	if !errors.Is(err, agentOffline) {
		t.Errorf("err = %v, want it to wrap %v", err, agentOffline)
	}
}

// TestWaitForAgent_HonorsDeadlineWithoutOvershooting mirrors
// TestWaitForIP_HonorsDeadlineWithoutOvershooting: the clamp means a
// budget is not exceeded by a full poll interval.
func TestWaitForAgent_HonorsDeadlineWithoutOvershooting(t *testing.T) {
	start := time.Now()
	err := waitForAgent(300*time.Millisecond, func() error {
		return errors.New("not ready")
	})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("waitForAgent err = nil, want timeout")
	}
	if elapsed < 300*time.Millisecond {
		t.Errorf("elapsed = %v, want >= the 300ms budget", elapsed)
	}
	if elapsed > 400*time.Millisecond {
		t.Errorf("elapsed = %v, want the budget not overshot by a full interval", elapsed)
	}
}

// TestWaitForAgent_ZeroBudgetNeverAttempts is the regression test for the
// gap IncusHost.WaitReady can hit when WaitForNetwork alone consumes the
// whole shared timeout, handing waitForAgent zero (or negative) remaining
// time: attempt has no bound of its own, so starting it anyway could block
// for an arbitrary, unbudgeted amount of wall-clock time. A zero budget
// must fail immediately without ever calling attempt.
func TestWaitForAgent_ZeroBudgetNeverAttempts(t *testing.T) {
	calls := 0
	err := waitForAgent(0, func() error {
		calls++
		return nil
	})
	if err == nil {
		t.Fatal("waitForAgent err = nil, want timeout")
	}
	if calls != 0 {
		t.Errorf("calls = %d, want 0 — a zero budget must never start an attempt", calls)
	}
}

// TestWaitForAgent_SuccessAfterDeadlineIsStillATimeout: an attempt that
// was already in flight when the deadline passed, and then succeeds, must
// not report success — that would silently let the caller's budget be
// overrun by however long the in-flight attempt took.
func TestWaitForAgent_SuccessAfterDeadlineIsStillATimeout(t *testing.T) {
	err := waitForAgent(50*time.Millisecond, func() error {
		// Simulate an exec that is slower than the whole budget but
		// eventually succeeds — e.g. Incus's own internal exec retry
		// backoff on a different transient error.
		time.Sleep(100 * time.Millisecond)
		return nil
	})
	if err == nil {
		t.Fatal("waitForAgent err = nil, want timeout — success arrived after the deadline")
	}
}
