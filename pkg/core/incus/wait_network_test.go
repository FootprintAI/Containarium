package incus

import (
	"errors"
	"testing"
	"time"
)

// noWaitNetBackoff shrinks the poll bounds for the duration of a test so the
// polling loop doesn't actually sleep for meaningful wall-clock time.
func noWaitNetBackoff(t *testing.T) {
	t.Helper()
	oldMin, oldMax := waitNetPollMin, waitNetPollMax
	waitNetPollMin, waitNetPollMax = 0, 0
	t.Cleanup(func() { waitNetPollMin, waitNetPollMax = oldMin, oldMax })
}

// TestWaitForIP_ReturnsAsSoonAsTheLeaseLands is the regression test for the
// flat 1s sleep. The fake leases on the 2nd attempt; with the old loop that
// took ~1s regardless, so an assertion well under 1s fails against it and
// passes against the backoff.
func TestWaitForIP_ReturnsAsSoonAsTheLeaseLands(t *testing.T) {
	calls := 0
	get := func() (string, error) {
		calls++
		if calls < 2 {
			return "", nil
		}
		return "10.0.0.5", nil
	}

	start := time.Now()
	ip, err := waitForIP(30*time.Second, get)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("waitForIP err = %v, want nil", err)
	}
	if ip != "10.0.0.5" {
		t.Errorf("ip = %q, want 10.0.0.5", ip)
	}
	// The first backoff is waitNetPollMin (25ms). A generous ceiling that is
	// still far below the 1s quantum this replaces.
	if elapsed > 200*time.Millisecond {
		t.Errorf("elapsed = %v, want < 200ms — a lease on the 2nd poll must not cost a full quantum", elapsed)
	}
}

// TestWaitForIP_ImmediateHitDoesNotSleep: an address already present returns
// on the first attempt without polling at all.
func TestWaitForIP_ImmediateHitDoesNotSleep(t *testing.T) {
	calls := 0
	start := time.Now()
	ip, err := waitForIP(30*time.Second, func() (string, error) {
		calls++
		return "10.0.0.9", nil
	})
	if err != nil {
		t.Fatalf("waitForIP err = %v, want nil", err)
	}
	if ip != "10.0.0.9" {
		t.Errorf("ip = %q, want 10.0.0.9", ip)
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1", calls)
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Errorf("elapsed = %v, want ~0 for an immediate hit", elapsed)
	}
}

// TestWaitForIP_BacksOffToTheCap: the interval must grow, otherwise a 120s
// Windows VM wait becomes thousands of round-trips on the Incus socket. With
// the real bounds (25ms doubling to 500ms), a 1s budget admits far fewer
// polls than a flat 25ms cadence would.
func TestWaitForIP_BacksOffToTheCap(t *testing.T) {
	calls := 0
	_, err := waitForIP(1*time.Second, func() (string, error) {
		calls++
		return "", nil
	})
	if err == nil {
		t.Fatal("waitForIP err = nil, want timeout")
	}
	// 25+50+100+200+400 = 775ms covers 5 sleeps; the 6th is clamped to the
	// remainder. A flat 25ms poll would be ~40 calls.
	if calls > 10 {
		t.Errorf("calls = %d, want <= 10 — the interval is not backing off", calls)
	}
	if calls < 3 {
		t.Errorf("calls = %d, want >= 3 — the interval is not opening small", calls)
	}
}

// TestWaitForIP_HonorsDeadlineWithoutOvershooting: the clamp means a budget
// is not exceeded by a full poll interval.
func TestWaitForIP_HonorsDeadlineWithoutOvershooting(t *testing.T) {
	start := time.Now()
	_, err := waitForIP(300*time.Millisecond, func() (string, error) {
		return "", nil
	})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("waitForIP err = nil, want timeout")
	}
	if elapsed < 300*time.Millisecond {
		t.Errorf("elapsed = %v, want >= the 300ms budget", elapsed)
	}
	if elapsed > 400*time.Millisecond {
		t.Errorf("elapsed = %v, want the budget not overshot by a full interval", elapsed)
	}
}

// TestWaitForIP_ReturnsLookupErrorImmediately: a failing lookup is not a
// container that hasn't leased yet — it must not be retried until timeout.
func TestWaitForIP_ReturnsLookupErrorImmediately(t *testing.T) {
	noWaitNetBackoff(t)

	wantErr := errors.New("connection refused")
	calls := 0
	_, err := waitForIP(30*time.Second, func() (string, error) {
		calls++
		return "", wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Errorf("err = %v, want %v", err, wantErr)
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1 — a lookup error must not be polled through", calls)
	}
}
