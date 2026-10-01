package anonbox

import (
	"context"
	"time"
)

// FunnelKind is one step of the `ssh new.<domain>` journey (#2201, PRD
// story 6). The daemon records every step through Config.Funnel; the
// server's sink turns each into an EVENT_TYPE_ANON_* event and a
// containarium_anon_<kind>_total counter, one for one.
type FunnelKind string

const (
	FunnelConnect           FunnelKind = "connect"            // a key knocked, before any decision
	FunnelShellReady        FunnelKind = "shell_ready"        // a new box was created and provisioned
	FunnelReconnect         FunnelKind = "reconnect"          // an existing box was handed back
	FunnelClaimLinkIssued   FunnelKind = "claim_link_issued"  // the claim-url was written into the guest
	FunnelClaimCompleted    FunnelKind = "claim_completed"    // Claim succeeded
	FunnelExpired           FunnelKind = "expired"            // a box is gone after its TTL
	FunnelKilledAbuse       FunnelKind = "killed_abuse"       // a box is gone before its TTL (operator deleted it)
	FunnelRejectedCapacity  FunnelKind = "rejected_capacity"  // refused: global cap
	FunnelRejectedRateLimit FunnelKind = "rejected_ratelimit" // refused: per-key / per-IP rate limit
	FunnelRejectedDoor      FunnelKind = "rejected_door"      // refused: door closed or key banned
)

// AllFunnelKinds is every kind the daemon can record, for sinks that
// pre-register one instrument per kind.
var AllFunnelKinds = []FunnelKind{
	FunnelConnect, FunnelShellReady, FunnelReconnect, FunnelClaimLinkIssued, FunnelClaimCompleted,
	FunnelExpired, FunnelKilledAbuse, FunnelRejectedCapacity, FunnelRejectedRateLimit, FunnelRejectedDoor,
}

// FunnelEvent is one recorded step.
type FunnelEvent struct {
	Kind    FunnelKind
	FPHash  string // sha256 hex of the fingerprint — never the fingerprint or key
	BoxName string // empty when no box was involved (a rejection)
	Reason  string // rejections / kills: the one-line reason
	// Duration is set for FunnelShellReady only: knock → provisioned.
	Duration time.Duration
}

// Funnel receives steps. Record must never block the door: a slow sink
// drops, it does not stall an SSH login.
type Funnel interface {
	Record(FunnelEvent)
}

// NopFunnel discards everything (the default).
type NopFunnel struct{}

// Record implements Funnel.
func (NopFunnel) Record(FunnelEvent) {}

// record is the Manager's guarded call.
func (m *Manager) record(ev FunnelEvent) {
	if m.cfg.Funnel != nil {
		m.cfg.Funnel.Record(ev)
	}
}

// Observe compares the anonymous boxes the daemon currently has with the
// set it knew at the previous call and reports every disappearance:
// after the box's TTL → FunnelExpired (the sweeper reaped it), before it →
// FunnelKilledAbuse (an operator deleted it). Meant to run on a ticker.
// The daemon cannot observe its own host being preempted — that event
// comes from the sentinel's spot watcher — so a restart simply re-seeds
// the known set from what is live.
func (m *Manager) Observe(ctx context.Context) error {
	all, err := m.boxes.List(ctx)
	if err != nil {
		return err
	}
	now := m.cfg.Now()
	live := map[string]knownBox{}
	for i := range all {
		if all[i].Labels[LabelFingerprint] == "" {
			continue
		}
		live[all[i].Ref.Name] = knownBox{fpHash: all[i].Labels[LabelFPHash], expiresAt: all[i].TTLExpiresAt, claimed: all[i].Labels[LabelClaimedAt] != ""}
	}

	m.mu.Lock()
	prev := m.known
	m.known = live
	m.mu.Unlock()

	for name, k := range prev {
		if _, still := live[name]; still {
			continue
		}
		switch {
		case k.claimed:
			// A claimed box is the tenant's; its deletion is not part of
			// the funnel.
		case !k.expiresAt.IsZero() && !now.Before(k.expiresAt):
			m.record(FunnelEvent{Kind: FunnelExpired, FPHash: k.fpHash, BoxName: name})
		default:
			m.record(FunnelEvent{Kind: FunnelKilledAbuse, FPHash: k.fpHash, BoxName: name, Reason: "deleted before its TTL"})
		}
	}
	return nil
}

// knownBox is what Observe remembers between ticks.
type knownBox struct {
	fpHash    string
	expiresAt time.Time
	claimed   bool
}
