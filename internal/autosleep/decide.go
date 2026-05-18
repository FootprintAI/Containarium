// Package autosleep ticks once a minute and stops user containers whose
// network activity has gone quiet for longer than their per-container
// idle threshold. Wake-on-request is a separate concern (Phase 3); this
// package only decides when to stop.
package autosleep

import (
	"fmt"
	"time"
)

// DecideAction is the verb the ticker should execute for a single
// container after evaluating its inputs. Kept as a typed string so the
// audit log can record it verbatim and tests can compare against
// constants instead of magic literals.
type DecideAction string

const (
	ActionNothing DecideAction = "nothing"
	ActionSleep   DecideAction = "sleep"
)

// DecideInput is the snapshot Decide consumes for one container. All
// observation happens in the caller (the Manager's tick loop); this
// struct is deliberately a plain value type so Decide stays pure and
// testable without any IO or clock dependency.
type DecideInput struct {
	// Username is the container's user-facing handle (Incus container
	// name with the "-container" suffix trimmed). Carried through to
	// the audit log on a sleep so operators can correlate.
	Username string

	// State is the Incus instance status string, e.g. "Running" or
	// "Stopped". Anything other than Running short-circuits to nothing.
	State string

	// AutoSleepEnabled mirrors the Phase 1 opt-in flag.
	AutoSleepEnabled bool

	// IdleThresholdMinutes is the per-container threshold; the daemon
	// applies a default at toggle time, so we trust the value here.
	IdleThresholdMinutes int32

	// IsCoreRole guards platform infra (postgres, caddy, victoriametrics,
	// …) — they never sleep regardless of the flag.
	IsCoreRole bool

	// LastStartedAt is when StartContainer last stamped the Incus user
	// config key. Zero value = unknown (never started during this
	// daemon's awareness of the container).
	LastStartedAt time.Time

	// LastNetworkActivity is the max(last_seen) over the container's
	// traffic_connections rows. Zero value = no traffic ever recorded
	// (clean container, or traffic collector disabled).
	LastNetworkActivity time.Time

	// Now is injected by the caller so unit tests can pin a clock.
	Now time.Time
}

// Decision is the result of evaluating one container's inputs.
type Decision struct {
	Action      DecideAction
	Reason      string // human-readable; the per-sleep audit log records it.
	IdleMinutes int    // populated when Action == ActionSleep, else 0.
}

// Decide turns one DecideInput into a Decision. Pure function: no IO,
// no clock — every "now" comes from the input. The rules are ordered
// from cheapest predicate to most expensive computation so the common
// "no opt-in" case short-circuits immediately.
func Decide(in DecideInput) Decision {
	// Rule 1: opt-in gate. The whole feature is off by default.
	if !in.AutoSleepEnabled {
		return Decision{Action: ActionNothing, Reason: "auto-sleep not enabled"}
	}

	// Rule 2: core containers are infrastructure. Sleeping postgres or
	// caddy would brick the daemon — never touch them.
	if in.IsCoreRole {
		return Decision{Action: ActionNothing, Reason: "core container"}
	}

	// Rule 3: state gate. Only Running containers are candidates;
	// already-stopped / freezing / errored containers are someone
	// else's problem.
	if in.State != "Running" {
		return Decision{Action: ActionNothing, Reason: "state " + in.State + " not running"}
	}

	threshold := int(in.IdleThresholdMinutes)

	// Rule 4: anti-thrash window. If Phase 3 (or an operator) just woke
	// the container, give it 2× threshold before we even consider
	// sleeping it again — otherwise a single tick after wake could
	// immediately re-sleep something nobody's had time to use yet.
	if !in.LastStartedAt.IsZero() {
		sinceStart := in.Now.Sub(in.LastStartedAt)
		if sinceStart < 2*time.Duration(threshold)*time.Minute {
			return Decision{Action: ActionNothing, Reason: "recently started"}
		}
	}

	// Rule 5: no traffic record. Either the container has never been
	// dialed, or the traffic collector isn't running. Fall back to
	// "active since last start" if we know that — otherwise we can't
	// decide and we leave the container alone.
	if in.LastNetworkActivity.IsZero() {
		if in.LastStartedAt.IsZero() {
			return Decision{Action: ActionNothing, Reason: "no traffic signal and no last-start"}
		}
		idle := int(in.Now.Sub(in.LastStartedAt).Minutes())
		if idle >= threshold {
			return Decision{
				Action:      ActionSleep,
				Reason:      fmt.Sprintf("idle %dm >= threshold %dm (no network signal, since-start)", idle, threshold),
				IdleMinutes: idle,
			}
		}
		return Decision{Action: ActionNothing, Reason: "below threshold (since-start)"}
	}

	// Rule 6: the normal path. Idle = time since last packet.
	idle := int(in.Now.Sub(in.LastNetworkActivity).Minutes())
	if idle >= threshold {
		return Decision{
			Action:      ActionSleep,
			Reason:      fmt.Sprintf("idle %dm >= threshold %dm", idle, threshold),
			IdleMinutes: idle,
		}
	}
	return Decision{Action: ActionNothing, Reason: "below threshold"}
}
