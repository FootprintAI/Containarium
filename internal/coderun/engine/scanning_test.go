package engine

import (
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func policyWith(kind pb.GuardrailKind, action pb.GuardrailAction) *pb.ServerGuardrailPolicy {
	return &pb.ServerGuardrailPolicy{Policy: &pb.GuardrailPolicy{Rules: []*pb.GuardrailRule{{Kind: kind, Action: action}}}}
}

func TestModelTrafficScanning(t *testing.T) {
	block := pb.GuardrailAction_GUARDRAIL_ACTION_BLOCK
	cases := []struct {
		name   string
		cred   Kind
		policy *pb.ServerGuardrailPolicy
		known  bool
		want   pb.CodeModelTrafficScanning
	}{
		{"tenant key never scanned, even with a rule", KindSecret, policyWith(pb.GuardrailKind_GUARDRAIL_KIND_PROMPT_INJECTION, block), true, pb.CodeModelTrafficScanning_CODE_MODEL_TRAFFIC_SCANNING_UNSCANNED_TENANT_KEY},
		{"gateway with inbound block rule", KindGateway, policyWith(pb.GuardrailKind_GUARDRAIL_KIND_UNSAFE_CODE, block), true, pb.CodeModelTrafficScanning_CODE_MODEL_TRAFFIC_SCANNING_SCANNED},
		{"gateway, inbound kind but not BLOCK", KindGateway, policyWith(pb.GuardrailKind_GUARDRAIL_KIND_UNSAFE_CODE, pb.GuardrailAction_GUARDRAIL_ACTION_ALLOW), true, pb.CodeModelTrafficScanning_CODE_MODEL_TRAFFIC_SCANNING_UNSCANNED_NO_POLICY},
		{"gateway, outbound-only block", KindGateway, policyWith(pb.GuardrailKind_GUARDRAIL_KIND_SECRET, block), true, pb.CodeModelTrafficScanning_CODE_MODEL_TRAFFIC_SCANNING_UNSCANNED_NO_POLICY},
		{"gateway, no policy configured", KindGateway, nil, true, pb.CodeModelTrafficScanning_CODE_MODEL_TRAFFIC_SCANNING_UNSCANNED_NO_POLICY},
		{"gateway, policy unreadable", KindGateway, nil, false, pb.CodeModelTrafficScanning_CODE_MODEL_TRAFFIC_SCANNING_UNSPECIFIED},
		{"unknown credential", Kind("x"), nil, true, pb.CodeModelTrafficScanning_CODE_MODEL_TRAFFIC_SCANNING_UNSPECIFIED},
	}
	for _, tc := range cases {
		if got := ModelTrafficScanning(tc.cred, tc.policy, tc.known); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestScanningLineNamesEveryState(t *testing.T) {
	seen := map[string]bool{}
	for v := range pb.CodeModelTrafficScanning_name {
		l := ScanningLine(pb.CodeModelTrafficScanning(v))
		if !strings.HasPrefix(l, "model traffic:") || seen[l] {
			t.Errorf("state %d line %q is wrong or duplicate", v, l)
		}
		seen[l] = true
	}
}
