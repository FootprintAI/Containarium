package sentinel

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// #953: both sync loops drove attempts off a plain ticker, so one transient
// failure cost a full interval of staleness — up to 6h for certsync.
//
// The schedule tests below are the load-bearing ones: they pin the two
// properties that make a single shared schedule safe for a 2m loop and
// useful for a 6h one.

func TestSyncRetryDelays_KeysyncBurstFitsInsideItsInterval(t *testing.T) {
	const interval = 2 * time.Minute
	delays := syncRetryDelays(interval)

	if len(delays) == 0 {
		t.Fatal("no fast retries for the 2m keysync loop: a transient failure would " +
			"still cost a full interval, which is the bug (#953)")
	}

	var total time.Duration
	for _, d := range delays {
		total += d
	}
	// The burst must finish before the next regular tick. Otherwise
	// attempts stack on top of each other and the loop runs two
	// overlapping sync schedules.
	if total >= interval {
		t.Errorf("retry burst totals %s for a %s interval — it would outlive its own "+
			"interval and stack attempts; delays=%v", total, interval, delays)
	}
}

func TestSyncRetryDelays_CertsyncRecoversInMinutesNotHours(t *testing.T) {
	const interval = 6 * time.Hour
	delays := syncRetryDelays(interval)

	if len(delays) != maxSyncFastRetries {
		t.Errorf("got %d retries for a %s interval, want the full %d — a long interval "+
			"is precisely where the burst matters", len(delays), interval, maxSyncFastRetries)
	}

	var total time.Duration
	for _, d := range delays {
		total += d
	}
	// The point of the issue: a blip must not cost most of a day.
	if total > 30*time.Minute {
		t.Errorf("retry burst spans %s; that is too close to just waiting for the tick", total)
	}
	if total < time.Minute {
		t.Errorf("retry burst spans only %s — too short to survive a daemon restart, "+
			"which is the failure this exists to absorb", total)
	}
}

// Delays must grow. A flat schedule either hammers a down backend or gives
// up too soon; the doubling is what lets one schedule serve both loops.
func TestSyncRetryDelays_AreNonDecreasingAndCapped(t *testing.T) {
	delays := syncRetryDelays(6 * time.Hour)
	for i := 1; i < len(delays); i++ {
		if delays[i] < delays[i-1] {
			t.Errorf("delay %d (%s) is shorter than delay %d (%s); the schedule must back off",
				i, delays[i], i-1, delays[i-1])
		}
	}
	for i, d := range delays {
		if d > syncRetryMax {
			t.Errorf("delay %d is %s, above the %s cap", i, d, syncRetryMax)
		}
	}
	if len(delays) > 0 && delays[0] != syncRetryInitial {
		t.Errorf("first retry is %s, want %s", delays[0], syncRetryInitial)
	}
}

// The invariant the whole design rests on, checked across the range of
// intervals a loop could plausibly be configured with rather than just the
// two in use today.
//
// If a burst ever outlived its interval, time.Ticker would buffer a tick
// (its channel holds one) and fire it the instant the burst returned —
// stacking a fresh cycle straight onto the previous one and running two
// overlapping schedules against the same backend.
func TestSyncRetryDelays_BurstNeverExceedsInterval(t *testing.T) {
	for _, interval := range []time.Duration{
		time.Second, 10 * time.Second, 30 * time.Second, time.Minute,
		2 * time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour,
		3 * time.Hour, 6 * time.Hour, 24 * time.Hour,
	} {
		var total time.Duration
		for _, d := range syncRetryDelays(interval) {
			total += d
		}
		if total >= interval {
			t.Errorf("interval=%s burst=%s — the burst must stay strictly under the interval, "+
				"or ticks buffer and cycles stack", interval, total)
		}
	}
}

// An interval shorter than the first retry gets no burst at all, rather
// than a retry scheduled after the next tick would already have run.
func TestSyncRetryDelays_ShortIntervalGetsNoBurst(t *testing.T) {
	if got := syncRetryDelays(time.Second); len(got) != 0 {
		t.Errorf("got %v for a 1s interval, want none — the tick is sooner than any retry", got)
	}
}

// recordingAttempt returns an attempt func that fails the first failures
// times, then succeeds, recording how many times it ran.
func recordingAttempt(failures int) (func() error, func() int) {
	var (
		mu sync.Mutex
		n  int
	)
	return func() error {
			mu.Lock()
			defer mu.Unlock()
			n++
			if n <= failures {
				return errors.New("transient")
			}
			return nil
		}, func() int {
			mu.Lock()
			defer mu.Unlock()
			return n
		}
}

// The behaviour the issue asks for: a failed attempt is retried promptly
// instead of waiting for the next tick.
func TestRunSyncLoop_RetriesAfterAFailure(t *testing.T) {
	attempt, count := recordingAttempt(2)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// A long interval so a passing test cannot be explained by the
		// regular tick firing — only retries can produce >1 attempt here.
		runSyncLoop(ctx, "test", time.Hour,
			[]time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}, attempt)
	}()

	waitFor(t, func() bool { return count() == 3 })
	cancel()
	<-done

	if got := count(); got != 3 {
		t.Errorf("attempts = %d, want 3 (initial + 2 retries)", got)
	}
}

// Steady state must be untouched: on success there are no extra requests.
// A regression here would multiply request volume against every backend.
func TestRunSyncLoop_SuccessCostsExactlyOneAttempt(t *testing.T) {
	attempt, count := recordingAttempt(0)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		runSyncLoop(ctx, "test", time.Hour,
			[]time.Duration{time.Millisecond, time.Millisecond}, attempt)
	}()

	waitFor(t, func() bool { return count() >= 1 })
	time.Sleep(50 * time.Millisecond) // long enough for the retries to have fired
	cancel()
	<-done

	if got := count(); got != 1 {
		t.Errorf("attempts = %d, want exactly 1 — a successful sync must not retry", got)
	}
}

// The burst is bounded. An unreachable backend must not become an infinite
// retry loop hammering it.
func TestRunSyncLoop_BurstIsBounded(t *testing.T) {
	attempt, count := recordingAttempt(1000) // never succeeds

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		runSyncLoop(ctx, "test", time.Hour,
			[]time.Duration{time.Millisecond, time.Millisecond}, attempt)
	}()

	waitFor(t, func() bool { return count() == 3 })
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done

	if got := count(); got != 3 {
		t.Errorf("attempts = %d, want 3 (initial + 2 retries, then stop)", got)
	}
}

// A cancelled context must abandon the burst promptly — the sentinel should
// not linger for minutes on shutdown waiting out a retry delay.
func TestRunSyncLoop_CancelInterruptsTheRetryWait(t *testing.T) {
	attempt, count := recordingAttempt(1000)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runSyncLoop(ctx, "test", time.Hour, []time.Duration{time.Hour, time.Hour}, attempt)
	}()

	waitFor(t, func() bool { return count() >= 1 })
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runSyncLoop did not return after cancel: it is blocked on a retry delay")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("timed out waiting for condition")
}
