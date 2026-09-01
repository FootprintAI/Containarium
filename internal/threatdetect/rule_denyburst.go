package threatdetect

import (
	"sync"
	"time"

	"github.com/footprintai/containarium/internal/netbpf"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Default N/M for DenyBurstRule (design doc: "N default 20, M default 5
// minutes"). Operator-tunable via CONTAINARIUM_THREAT_DENY_BURST_N /
// CONTAINARIUM_THREAT_DENY_BURST_WINDOW_MINUTES (see internal/config) — no
// daemon rebuild required, just a restart with the new env var. Live tuning
// via an UpdateThreatRuleConfig RPC without a restart is #1643's scope.
const (
	DefaultDenyBurstN      = 20
	DefaultDenyBurstWindow = 5 * time.Minute
)

// denyBurstRecord is one deny event's evidence, kept in a tenant's sliding
// window until it ages out.
type denyBurstRecord struct {
	at     time.Time
	dst    string
	dport  uint32
	proto  string
	reason string
}

// DenyBurstRule fires a MEDIUM "fence probing" finding when one tenant
// accumulates >= N deny events within an M-minute sliding window — the
// signal that a tenant is testing the fence rather than having already
// breached it (CrossTenantFlowRule catches an actual breach). Per the
// engine's Rule.Sweep doc and the design doc's "deny-burst adds ≤ 30s sweep
// granularity", this rule accumulates on OnDeny but only evaluates and
// fires on Sweep — not on every OnDeny call — so a burst that never grows
// past a stale window doesn't keep re-alerting on the mere passage of time,
// and a quiet window doesn't emit anything between ticks.
type DenyBurstRule struct {
	n      int
	window time.Duration

	mu      sync.Mutex
	records map[string][]denyBurstRecord // tenantID -> window records, oldest first
	dirty   map[string]bool              // tenantID -> at least one OnDeny since the last Sweep
}

// NewDenyBurstRule builds the rule with N deny events within window
// triggering a finding. n<=0 or window<=0 falls back to the design doc's
// defaults rather than constructing a rule that can never fire (n=0) or
// fires on every single deny (window=0).
func NewDenyBurstRule(n int, window time.Duration) *DenyBurstRule {
	if n <= 0 {
		n = DefaultDenyBurstN
	}
	if window <= 0 {
		window = DefaultDenyBurstWindow
	}
	return &DenyBurstRule{
		n:       n,
		window:  window,
		records: make(map[string][]denyBurstRecord),
		dirty:   make(map[string]bool),
	}
}

func (r *DenyBurstRule) ID() pb.ThreatRuleId { return pb.ThreatRuleId_THREAT_RULE_ID_DENY_BURST }

// OnFlows: deny-burst is a deny-shaped rule; flow records carry no denial
// information.
func (r *DenyBurstRule) OnFlows(RuleContext, []netbpf.FlowRecord) []RawFinding { return nil }

// OnDeny records the event into the source tenant's window. Never fires
// directly — see the type doc for why evaluation is deferred to Sweep. An
// event whose source IP doesn't resolve to a known tenant is dropped: a
// probe from an unrecognized IP has no tenant to attribute the burst to.
func (r *DenyBurstRule) OnDeny(ctx RuleContext, ev netbpf.DenyEvent) []RawFinding {
	tenantID, ok := ctx.TenantForIP(ev.Src())
	if !ok {
		return nil
	}
	now := ctx.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records[tenantID] = append(r.records[tenantID], denyBurstRecord{
		at:     now,
		dst:    ev.Dst().String(),
		dport:  uint32(ev.Dport),
		proto:  protoName(ev.Proto),
		reason: denyReasonName(ev.Reason),
	})
	r.dirty[tenantID] = true
	return nil
}

// Sweep prunes every tracked tenant's window to [now-window, now] and, for
// a tenant with new denies since the last Sweep (dirty) whose pruned window
// still holds >= n records, returns a MEDIUM finding. Window expiry — the
// pruned count dropping below n with no new denies — naturally stops future
// findings until fresh denies re-cross the threshold, without any separate
// "reset" bookkeeping.
func (r *DenyBurstRule) Sweep(_ RuleContext, now time.Time) []RawFinding {
	r.mu.Lock()
	defer r.mu.Unlock()

	var out []RawFinding
	for tenantID, records := range r.records {
		cutoff := now.Add(-r.window)
		kept := records[:0]
		for _, rec := range records {
			if rec.at.After(cutoff) {
				kept = append(kept, rec)
			}
		}
		if len(kept) == 0 {
			delete(r.records, tenantID)
			delete(r.dirty, tenantID)
			continue
		}
		r.records[tenantID] = kept

		fire := r.dirty[tenantID] && len(kept) >= r.n
		r.dirty[tenantID] = false
		if !fire {
			continue
		}

		out = append(out, RawFinding{
			Rule:     pb.ThreatRuleId_THREAT_RULE_ID_DENY_BURST,
			Severity: pb.ThreatSeverity_THREAT_SEVERITY_MEDIUM,
			TenantID: tenantID,
			// Subject "" — the dedupe scope is the whole tenant, not a
			// single peer/destination (a probe typically fans out across
			// many destinations).
			Subject:  "",
			Evidence: Evidence{Denies: denyEvidenceFromRecords(kept)},
		})
	}
	return out
}

// denyEvidenceFromRecords aggregates window records into DenyEvidence rows
// grouped by (dst, dport, proto, reason), most-recent group last — Capped()
// (applied by the store on write) keeps only the most recent EvidenceCap
// groups.
func denyEvidenceFromRecords(records []denyBurstRecord) []DenyEvidence {
	type key struct {
		dst, proto, reason string
		dport              uint32
	}
	order := make([]key, 0, len(records))
	counts := make(map[key]int64, len(records))
	for _, rec := range records {
		k := key{dst: rec.dst, proto: rec.proto, reason: rec.reason, dport: rec.dport}
		if _, seen := counts[k]; !seen {
			order = append(order, k)
		}
		counts[k]++
	}
	out := make([]DenyEvidence, 0, len(order))
	for _, k := range order {
		out = append(out, DenyEvidence{
			DstIP:    k.dst,
			DstPort:  k.dport,
			Protocol: k.proto,
			Reason:   k.reason,
			Count:    counts[k],
		})
	}
	return out
}
