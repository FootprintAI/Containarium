package server

import (
	"context"
	"slices"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// TestGetGuardrailStatus_ReportsEachEffectivePolicy (#2737): a fresh daemon
// reports BASELINE; a policy with an inbound BLOCK rule reports ADMIN; a
// policy without one reports NONE. Any authenticated caller may read it.
func TestGetGuardrailStatus_ReportsEachEffectivePolicy(t *testing.T) {
	s, _ := newGPServer()
	get := func(ctx context.Context) *pb.GetGuardrailStatusResponse {
		t.Helper()
		resp, err := s.GetGuardrailStatus(ctx, &pb.GetGuardrailStatusRequest{})
		if err != nil {
			t.Fatalf("GetGuardrailStatus: %v", err)
		}
		return resp
	}

	if got := get(gpUserCtx()); got.GetResponsePolicy() != pb.GuardrailEffectivePolicy_GUARDRAIL_EFFECTIVE_POLICY_BASELINE ||
		!slices.Contains(got.GetBaselineRuleIds(), "baseline.pem_private_key") || got.GetPolicyRevision() != 0 {
		t.Fatalf("fresh daemon status = %v, want BASELINE with the baseline rule ids and revision 0", got)
	}

	inbound := &pb.SetGuardrailPolicyRequest{Policy: &pb.GuardrailPolicy{Rules: []*pb.GuardrailRule{
		{Kind: pb.GuardrailKind_GUARDRAIL_KIND_UNSAFE_CODE, Action: pb.GuardrailAction_GUARDRAIL_ACTION_BLOCK},
	}}}
	if _, err := s.SetGuardrailPolicy(gpAdminCtx(), inbound); err != nil {
		t.Fatalf("Set inbound policy: %v", err)
	}
	if got := get(gpUserCtx()); got.GetResponsePolicy() != pb.GuardrailEffectivePolicy_GUARDRAIL_EFFECTIVE_POLICY_ADMIN ||
		got.GetPolicyRevision() != 1 || len(got.GetBaselineRuleIds()) != 0 ||
		!slices.Equal(got.GetInboundBlockKinds(), []pb.GuardrailKind{pb.GuardrailKind_GUARDRAIL_KIND_UNSAFE_CODE}) {
		t.Fatalf("status after inbound BLOCK policy = %v, want ADMIN revision 1 blocking UNSAFE_CODE", got)
	}

	// gpRequest has outbound rules only (PII REDACT, SECRET BLOCK).
	if _, err := s.SetGuardrailPolicy(gpAdminCtx(), gpRequest(0)); err != nil {
		t.Fatalf("Set outbound-only policy: %v", err)
	}
	if got := get(gpAdminCtx()); got.GetResponsePolicy() != pb.GuardrailEffectivePolicy_GUARDRAIL_EFFECTIVE_POLICY_NONE ||
		got.GetPolicyRevision() != 2 || len(got.GetInboundBlockKinds()) != 0 || len(got.GetBaselineRuleIds()) != 0 {
		t.Fatalf("status after outbound-only policy = %v, want NONE revision 2", got)
	}
}

// TestGetGuardrailStatus_Refusals: no subject is UNAUTHENTICATED, and a
// store that cannot be read is an error, never NONE or BASELINE.
func TestGetGuardrailStatus_Refusals(t *testing.T) {
	s, _ := newGPServer()
	if _, err := s.GetGuardrailStatus(context.Background(), &pb.GetGuardrailStatusRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unauthenticated GetGuardrailStatus = %v, want Unauthenticated", err)
	}

	s.SetStore(unavailableGuardrailPolicyStore{})
	resp, err := s.GetGuardrailStatus(gpUserCtx(), &pb.GetGuardrailStatusRequest{})
	if status.Code(err) != codes.Internal || resp != nil {
		t.Fatalf("GetGuardrailStatus on an unreadable store = (%v, %v), want Internal and no status", resp, err)
	}
}
