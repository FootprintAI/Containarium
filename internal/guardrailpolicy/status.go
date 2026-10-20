package guardrailpolicy

import (
	"errors"
	"fmt"
	"strings"

	"github.com/footprintai/containarium/internal/guardrail"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// EffectiveStatus derives what scans model responses from one read of the
// policy store (#2737; decided as Q13 on #2727). p and readErr are what
// Store.Get returned:
//   - ErrNotConfigured: BASELINE, the built-in log-only rules (#2736).
//   - a policy with at least one inbound BLOCK rule: ADMIN.
//   - any other policy (empty, outbound rules only): NONE, because a
//     configured policy turns the baseline off and nothing else scans.
//   - any other error: returned, never reported as NONE or BASELINE.
//
// It mirrors the model gateway's own choice (modeOf in
// internal/modelgateway/inbound.go), which uses the same InboundBlockKinds.
func EffectiveStatus(p *pb.ServerGuardrailPolicy, readErr error) (*pb.GetGuardrailStatusResponse, error) {
	switch {
	case errors.Is(readErr, ErrNotConfigured):
		resp := &pb.GetGuardrailStatusResponse{ResponsePolicy: pb.GuardrailEffectivePolicy_GUARDRAIL_EFFECTIVE_POLICY_BASELINE}
		for _, r := range guardrail.BaselineRules() {
			resp.BaselineRuleIds = append(resp.BaselineRuleIds, string(r.ID))
		}
		return resp, nil
	case readErr != nil:
		return nil, readErr
	}
	resp := &pb.GetGuardrailStatusResponse{
		ResponsePolicy: pb.GuardrailEffectivePolicy_GUARDRAIL_EFFECTIVE_POLICY_NONE,
		PolicyRevision: p.GetRevision(),
	}
	if kinds := guardrail.InboundBlockKinds(p); len(kinds) > 0 {
		resp.ResponsePolicy = pb.GuardrailEffectivePolicy_GUARDRAIL_EFFECTIVE_POLICY_ADMIN
		resp.InboundBlockKinds = kinds
	}
	return resp, nil
}

// DescribeStatus renders a GetGuardrailStatusResponse for a person: the text
// `containarium guardrail status` prints.
func DescribeStatus(resp *pb.GetGuardrailStatusResponse) string {
	var b strings.Builder
	switch resp.GetResponsePolicy() {
	case pb.GuardrailEffectivePolicy_GUARDRAIL_EFFECTIVE_POLICY_BASELINE:
		b.WriteString("Response policy: baseline (no admin policy has been set)\n")
		b.WriteString("  Model responses are scanned with the built-in rules, log-only: a match is\n")
		b.WriteString("  audited and logged, and the response is delivered unchanged.\n")
		fmt.Fprintf(&b, "  Rules (%d):\n", len(resp.GetBaselineRuleIds()))
		for _, id := range resp.GetBaselineRuleIds() {
			fmt.Fprintf(&b, "    %s\n", id)
		}
	case pb.GuardrailEffectivePolicy_GUARDRAIL_EFFECTIVE_POLICY_ADMIN:
		fmt.Fprintf(&b, "Response policy: admin (policy revision %d)\n", resp.GetPolicyRevision())
		b.WriteString("  Model responses are scanned and blocked on these kinds; the baseline is off:\n")
		for _, k := range resp.GetInboundBlockKinds() {
			fmt.Fprintf(&b, "    %s\n", strings.TrimPrefix(k.String(), "GUARDRAIL_KIND_"))
		}
	case pb.GuardrailEffectivePolicy_GUARDRAIL_EFFECTIVE_POLICY_NONE:
		fmt.Fprintf(&b, "Response policy: none (policy revision %d)\n", resp.GetPolicyRevision())
		b.WriteString("  Model responses are not scanned: the admin policy has no inbound BLOCK rule,\n")
		b.WriteString("  and a configured policy turns the baseline off.\n")
	default:
		b.WriteString("Response policy: unknown (the daemon did not report one)\n")
	}
	return b.String()
}
