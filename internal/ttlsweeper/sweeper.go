package ttlsweeper

import "time"

// ContainerView is the slice of container state the sweeper actually
// reads. Decoupled from incus.ContainerInfo (and from the generated
// pb.Container) so this package has zero dependency on either — easier
// to test, and the daemon-wiring follow-up can adapt whichever source
// it picks (Incus user.* config keys, SQLite row, etc.) at the call
// site without touching the decision logic.
type ContainerView struct {
	// Name is the Incus container name (e.g. "alice-container").
	// Echoed back in Decide's returned slice and used by the wiring
	// PR's Deleter as the delete key.
	Name string

	// TTLExpiresAt is the wall-clock time at which the container
	// should be auto-deleted. nil = no TTL set (container persists
	// indefinitely). Pointer-not-zero-value so we can distinguish
	// "unset" from "set to the zero time" — important because Decide
	// must treat unset as "skip" rather than "delete immediately".
	TTLExpiresAt *time.Time

	// Stopped is true when the container is in the STOPPED state. Only a
	// stopped box is eligible for the stopped→delete timer (#525); a running
	// box is reaped only by the absolute TTLExpiresAt above.
	Stopped bool

	// StoppedAt is when the box most recently became STOPPED (cleared on
	// start, so a woken box resets the clock). nil = not known to be stopped.
	// The stopped→delete timer runs from here.
	StoppedAt *time.Time

	// DeleteAfterStopped is the per-box stopped→delete window (#525). nil =
	// the box never opted into stopped→delete (the safe default — a
	// scale-to-zero box that merely sleeps is never reaped for being
	// stopped). Set + Stopped + StoppedAt+window elapsed → delete.
	DeleteAfterStopped *time.Duration

	// Protected marks a box that must never be auto-reaped (#284, delete-policy
	// = protected — e.g. a persistent runner). When true, Decide skips the box
	// regardless of any TTL or stopped→delete window. Defense in depth: a
	// protected box should never carry a TTL, but if one is stamped by mistake
	// the box still survives the sweeper.
	Protected bool
}

// graceMargin is subtracted from the comparison clock before checking
// whether ttl_expires_at has elapsed. Protects against minor clock
// skew between the daemon host and whatever set the TTL (the GHA
// runner, a developer's laptop, etc.). 30s is generous compared to
// typical NTP skew (sub-second) and comfortably less than 1% of the
// smallest realistic TTL window — see the package doc for the
// reasoning. Exported as a package constant rather than a tunable so
// the same value shows up in tests and operator-facing docs.
const graceMargin = 30 * time.Second

// Decide returns the names of containers that should be deleted now
// (accounting for graceMargin). Pure function — no IO, no clock, no
// locks. Safe to call from a goroutine; safe to call repeatedly with
// the same inputs (idempotent, deterministic).
//
// A container is deleted if EITHER timer has elapsed:
//
//   - Absolute TTL (#523): TTLExpiresAt set and at/before now-graceMargin.
//     Fires regardless of running/stopped — the box's hard death date.
//   - Stopped→delete (#525): the box is Stopped, has a StoppedAt, opted into
//     a DeleteAfterStopped window, and StoppedAt+window is at/before
//     now-graceMargin. This is the disk-reclaim half of the two-phase
//     lifecycle: idle→stop (#524, autosleep) frees CPU/RAM, then a box left
//     stopped past its window is deleted to free disk. Waking the box clears
//     StoppedAt (→ nil here), which resets this timer.
//
// Unset/missing fields skip the corresponding rule, so a box with neither a
// TTL nor a stopped→delete window is never reaped. A name matching both rules
// is returned once (the two rules share the append-and-continue). A box marked
// Protected (#284) is skipped entirely, regardless of either timer.
func Decide(containers []ContainerView, now time.Time) []string {
	cutoff := now.Add(-graceMargin)
	var expired []string
	for _, c := range containers {
		// Protected boxes (#284) are never auto-reaped — skip before any timer
		// check so a stray TTL on a protected box can't delete it.
		if c.Protected {
			continue
		}
		// Absolute TTL.
		if c.TTLExpiresAt != nil && !c.TTLExpiresAt.After(cutoff) {
			expired = append(expired, c.Name)
			continue
		}
		// Stopped→delete: only for a stopped box that opted in.
		if c.Stopped && c.StoppedAt != nil && c.DeleteAfterStopped != nil {
			deadline := c.StoppedAt.Add(*c.DeleteAfterStopped)
			if !deadline.After(cutoff) {
				expired = append(expired, c.Name)
				continue
			}
		}
	}
	return expired
}
