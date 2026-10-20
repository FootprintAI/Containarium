package guardrailpolicy

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/guardrail"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func statusPolicy(revision int64, rules ...*pb.GuardrailRule) *pb.ServerGuardrailPolicy {
	return &pb.ServerGuardrailPolicy{Policy: &pb.GuardrailPolicy{Rules: rules}, Revision: revision}
}

func rule(k pb.GuardrailKind, a pb.GuardrailAction) *pb.GuardrailRule {
	return &pb.GuardrailRule{Kind: k, Action: a}
}

func allBaselineRuleIDs() []string {
	var ids []string
	for _, r := range guardrail.BaselineRules() {
		ids = append(ids, string(r.ID))
	}
	return ids
}

// TestEffectiveStatus: each store state maps to the effective response
// policy decided on #2737 (Q13 on #2727). A read error is an error, never
// NONE or BASELINE.
func TestEffectiveStatus(t *testing.T) {
	const (
		pii    = pb.GuardrailKind_GUARDRAIL_KIND_PII
		secret = pb.GuardrailKind_GUARDRAIL_KIND_SECRET
		code   = pb.GuardrailKind_GUARDRAIL_KIND_UNSAFE_CODE
		inject = pb.GuardrailKind_GUARDRAIL_KIND_PROMPT_INJECTION
		block  = pb.GuardrailAction_GUARDRAIL_ACTION_BLOCK
		redact = pb.GuardrailAction_GUARDRAIL_ACTION_REDACT
		allow  = pb.GuardrailAction_GUARDRAIL_ACTION_ALLOW
	)
	cases := []struct {
		name      string
		policy    *pb.ServerGuardrailPolicy
		err       error
		want      pb.GuardrailEffectivePolicy
		revision  int64
		kinds     []pb.GuardrailKind
		baseline  []string
		wantError bool
	}{
		{name: "never set", err: ErrNotConfigured,
			want: pb.GuardrailEffectivePolicy_GUARDRAIL_EFFECTIVE_POLICY_BASELINE, baseline: allBaselineRuleIDs()},
		{name: "wrapped not configured", err: errors.Join(errors.New("ctx"), ErrNotConfigured),
			want: pb.GuardrailEffectivePolicy_GUARDRAIL_EFFECTIVE_POLICY_BASELINE, baseline: allBaselineRuleIDs()},
		{name: "inbound block", policy: statusPolicy(3, rule(pii, redact), rule(code, block)),
			want: pb.GuardrailEffectivePolicy_GUARDRAIL_EFFECTIVE_POLICY_ADMIN, revision: 3, kinds: []pb.GuardrailKind{code}},
		{name: "both inbound kinds in rule order", policy: statusPolicy(4, rule(inject, block), rule(code, block)),
			want: pb.GuardrailEffectivePolicy_GUARDRAIL_EFFECTIVE_POLICY_ADMIN, revision: 4, kinds: []pb.GuardrailKind{inject, code}},
		{name: "empty policy", policy: statusPolicy(1),
			want: pb.GuardrailEffectivePolicy_GUARDRAIL_EFFECTIVE_POLICY_NONE, revision: 1},
		{name: "outbound rules only", policy: statusPolicy(2, rule(pii, redact), rule(secret, block)),
			want: pb.GuardrailEffectivePolicy_GUARDRAIL_EFFECTIVE_POLICY_NONE, revision: 2},
		{name: "inbound kind not blocked", policy: statusPolicy(5, rule(code, allow)),
			want: pb.GuardrailEffectivePolicy_GUARDRAIL_EFFECTIVE_POLICY_NONE, revision: 5},
		{name: "read error", err: errors.New("db down"), wantError: true},
		{name: "read error with a stale policy", policy: statusPolicy(6, rule(code, block)), err: errors.New("db down"), wantError: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := EffectiveStatus(tc.policy, tc.err)
			if tc.wantError {
				if err == nil || got != nil {
					t.Fatalf("EffectiveStatus = (%v, %v), want an error and no status", got, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("EffectiveStatus: %v", err)
			}
			if got.GetResponsePolicy() != tc.want {
				t.Errorf("response_policy = %v, want %v", got.GetResponsePolicy(), tc.want)
			}
			if got.GetPolicyRevision() != tc.revision {
				t.Errorf("policy_revision = %d, want %d", got.GetPolicyRevision(), tc.revision)
			}
			if !slices.Equal(got.GetInboundBlockKinds(), tc.kinds) {
				t.Errorf("inbound_block_kinds = %v, want %v", got.GetInboundBlockKinds(), tc.kinds)
			}
			if !slices.Equal(got.GetBaselineRuleIds(), tc.baseline) {
				t.Errorf("baseline_rule_ids = %v, want %v", got.GetBaselineRuleIds(), tc.baseline)
			}
		})
	}
}

// TestDescribeStatus: the text `guardrail status` prints names the effective
// policy in the lowercase word the Verify steps look for, and what it means.
func TestDescribeStatus(t *testing.T) {
	cases := []struct {
		name string
		resp *pb.GetGuardrailStatusResponse
		want []string
	}{
		{"baseline", &pb.GetGuardrailStatusResponse{
			ResponsePolicy:  pb.GuardrailEffectivePolicy_GUARDRAIL_EFFECTIVE_POLICY_BASELINE,
			BaselineRuleIds: allBaselineRuleIDs(),
		}, append([]string{"Response policy: baseline", "log-only", "no admin policy"}, allBaselineRuleIDs()...)},
		{"admin", &pb.GetGuardrailStatusResponse{
			ResponsePolicy:    pb.GuardrailEffectivePolicy_GUARDRAIL_EFFECTIVE_POLICY_ADMIN,
			PolicyRevision:    7,
			InboundBlockKinds: []pb.GuardrailKind{pb.GuardrailKind_GUARDRAIL_KIND_UNSAFE_CODE},
		}, []string{"Response policy: admin", "revision 7", "UNSAFE_CODE"}},
		{"none", &pb.GetGuardrailStatusResponse{
			ResponsePolicy: pb.GuardrailEffectivePolicy_GUARDRAIL_EFFECTIVE_POLICY_NONE,
			PolicyRevision: 2,
		}, []string{"Response policy: none", "revision 2", "not scanned"}},
		{"unspecified", &pb.GetGuardrailStatusResponse{}, []string{"Response policy: unknown"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := DescribeStatus(tc.resp)
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("DescribeStatus missing %q:\n%s", w, out)
				}
			}
		})
	}
}
