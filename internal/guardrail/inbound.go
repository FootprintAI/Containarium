package guardrail

import (
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// IsInboundKind reports whether k is scanned on model output (as opposed to
// the outbound PII and secret kinds).
func IsInboundKind(k pb.GuardrailKind) bool {
	return k == pb.GuardrailKind_GUARDRAIL_KIND_UNSAFE_CODE || k == pb.GuardrailKind_GUARDRAIL_KIND_PROMPT_INJECTION
}

// InboundBlockKinds returns the inbound kinds the server policy blocks, each
// once, in rule order. Empty means no inbound scan is in force.
func InboundBlockKinds(p *pb.ServerGuardrailPolicy) []pb.GuardrailKind {
	var kinds []pb.GuardrailKind
	seen := map[pb.GuardrailKind]bool{}
	for _, r := range p.GetPolicy().GetRules() {
		k := r.GetKind()
		if !IsInboundKind(k) || r.GetAction() != pb.GuardrailAction_GUARDRAIL_ACTION_BLOCK || seen[k] {
			continue
		}
		seen[k] = true
		kinds = append(kinds, k)
	}
	return kinds
}

// InboundReason is why an inbound scan (model output on its way into a
// box) passed or blocked. Typed, not a string: an audit entry and a counter
// key on it (docs/architecture/guardrail-inbound-and-server-policy.md).
type InboundReason int

const (
	InboundReasonClean             InboundReason = iota
	InboundReasonFinding                         // a BLOCK-action kind matched
	InboundReasonCoverageGap                     // engine could not scan a unit
	InboundReasonEngineError                     // unreachable, timeout, or unsupported kind
	InboundReasonOverLimit                       // held message exceeded the byte limit
	InboundReasonPolicyUnavailable               // policy store could not be read
)

var inboundReasonNames = map[InboundReason]string{
	InboundReasonClean:             "clean",
	InboundReasonFinding:           "finding",
	InboundReasonCoverageGap:       "coverage_gap",
	InboundReasonEngineError:       "engine_error",
	InboundReasonOverLimit:         "over_limit",
	InboundReasonPolicyUnavailable: "policy_unavailable",
}

// String is the stable name used in logs, counters and audit details.
func (r InboundReason) String() string {
	if s, ok := inboundReasonNames[r]; ok {
		return s
	}
	return "unknown"
}

// InboundDecision is the typed block decision for one model response.
//
// It carries counts and kinds only. No field can hold the flagged span or
// any response text (TestInboundDecision_NoTextBearingField enforces this
// by reflection); EngineID is the engine's own identifier.
type InboundDecision struct {
	Blocked  bool
	Kinds    []pb.GuardrailKind // kinds with at least one finding, sorted
	Findings int
	Gaps     int
	EngineID string
	Reason   InboundReason
}

// DecideInbound turns one engine Scan result into a decision under policy.
//
// Every failure mode blocks: an engine error (including FAILED_PRECONDITION
// for an unsupported kind, and a nil response), a coverage gap, or a
// finding of a kind whose rule is BLOCK. Findings of a kind without a BLOCK
// rule are counted but do not block. When several apply, the reason is the
// first of EngineError, Finding, CoverageGap; the counts record the rest.
func DecideInbound(resp *pb.GuardrailScanResponse, scanErr error, policy *pb.GuardrailPolicy) InboundDecision {
	if scanErr != nil || resp == nil {
		return InboundBlocked(InboundReasonEngineError)
	}
	blocking := map[pb.GuardrailKind]bool{}
	for _, r := range policy.GetRules() {
		if r.GetAction() == pb.GuardrailAction_GUARDRAIL_ACTION_BLOCK {
			blocking[r.GetKind()] = true
		}
	}
	d := InboundDecision{
		EngineID: resp.GetEngineId(),
		Findings: len(resp.GetFindings()),
		Gaps:     len(resp.GetGaps()),
	}
	perKind := map[pb.GuardrailKind]int64{}
	hit := false
	for _, f := range resp.GetFindings() {
		perKind[f.GetKind()]++
		if blocking[f.GetKind()] {
			hit = true
		}
	}
	if len(perKind) > 0 {
		d.Kinds = sortedKinds(perKind)
	}
	switch {
	case hit:
		d.Blocked, d.Reason = true, InboundReasonFinding
	case d.Gaps > 0:
		d.Blocked, d.Reason = true, InboundReasonCoverageGap
	default:
		d.Reason = InboundReasonClean
	}
	return d
}

// InboundBlocked is a block decided without a usable scan result: the
// engine failed, the held message went over its byte limit, or the policy
// could not be read.
func InboundBlocked(reason InboundReason) InboundDecision {
	return InboundDecision{Blocked: true, Reason: reason}
}
