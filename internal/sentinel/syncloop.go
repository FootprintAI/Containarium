package sentinel

import (
	"context"
	"log"
	"time"
)

// Fast retry after a failed sync (#953).
//
// Both sentinel sync loops used to drive their attempts off a plain
// time.Ticker, so a single transient failure — a "connection refused"
// landing in the daemon's restart window, a network blip, anything — cost a
// FULL interval of staleness with no attempt in between.
//
// For keysync (2m interval) that is a minor delay. For certsync it is 6h:
// one momentarily-closed listener could leave certificates stale for most
// of a day. Hosts carrying the incus#755 restart-timer mitigation restart
// the daemon every 3h, so they take that dice-roll repeatedly.
//
// The fix is a bounded burst of retries after a failure, deliberately NOT a
// shorter steady-state interval. Those are different jobs: the interval
// bounds normal-case request volume, while this bounds recovery time from a
// failure we already know is usually transient. Shortening the interval
// would pay for recovery with permanent extra load.
const (
	// syncRetryInitial is the first retry delay. Long enough that a daemon
	// restart has a real chance to finish before we try again (so the retry
	// is not simply spent hitting the same closed listener), short enough
	// that recovery still feels immediate.
	syncRetryInitial = 15 * time.Second

	// syncRetryMax caps the delay growth, matching the RecoveryBackoffMax
	// precedent in manager.go.
	syncRetryMax = 5 * time.Minute

	// maxSyncFastRetries bounds the burst. With the doubling schedule this
	// is ~13 minutes of retrying for certsync, after which the regular
	// interval takes over — an outage longer than the burst is no longer
	// the transient blip this exists to absorb.
	maxSyncFastRetries = 6
)

// syncRetryDelays returns the fast-retry schedule for a loop running at the
// given interval: doubling from syncRetryInitial, capped per-delay at
// syncRetryMax and in count at maxSyncFastRetries.
//
// It also truncates the schedule so no retry is scheduled at or after the
// next regular tick — past that point the ticker does the same work anyway,
// and a burst that outlived its own interval would stack attempts on top of
// each other. That truncation is what keeps this safe for the 2m keysync
// loop and useful for the 6h certsync loop with one shared schedule.
func syncRetryDelays(interval time.Duration) []time.Duration {
	var (
		delays  []time.Duration
		elapsed time.Duration
	)
	for d := syncRetryInitial; len(delays) < maxSyncFastRetries; d *= 2 {
		if d > syncRetryMax {
			d = syncRetryMax
		}
		if elapsed+d >= interval {
			break
		}
		delays = append(delays, d)
		elapsed += d
	}
	return delays
}

// runSyncLoop calls attempt every interval, and after any failed attempt
// retries on the supplied schedule until one succeeds or the schedule is
// exhausted. Blocks until ctx is done.
//
// attempt does its own success/failure logging (the two callers report
// different things); the error is used only to decide whether to retry.
//
// The regular ticker is independent of the retry burst, so a recovered
// failure does not shift the steady-state cadence — on the success path
// this is byte-for-byte the old behaviour.
func runSyncLoop(ctx context.Context, name string, interval time.Duration, delays []time.Duration, attempt func() error) {
	runOnce := func() {
		if err := attempt(); err == nil {
			return
		}
		for i, d := range delays {
			select {
			case <-ctx.Done():
				return
			case <-time.After(d):
			}
			log.Printf("[%s] retrying after a failed sync (fast retry %d/%d, waited %s)",
				name, i+1, len(delays), d)
			if err := attempt(); err == nil {
				log.Printf("[%s] recovered on fast retry %d — without this the next attempt "+
					"would have been up to %s away", name, i+1, interval)
				return
			}
		}
		if len(delays) > 0 {
			log.Printf("[%s] %d fast retries did not recover; falling back to the regular %s interval",
				name, len(delays), interval)
		}
	}

	runOnce()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runOnce()
		}
	}
}
