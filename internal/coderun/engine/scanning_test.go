package engine

import (
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestModelTrafficScanning(t *testing.T) {
	const (
		unknown  = pb.GuardrailEffectivePolicy_GUARDRAIL_EFFECTIVE_POLICY_UNSPECIFIED
		none     = pb.GuardrailEffectivePolicy_GUARDRAIL_EFFECTIVE_POLICY_NONE
		baseline = pb.GuardrailEffectivePolicy_GUARDRAIL_EFFECTIVE_POLICY_BASELINE
		admin    = pb.GuardrailEffectivePolicy_GUARDRAIL_EFFECTIVE_POLICY_ADMIN
	)
	cases := []struct {
		name      string
		cred      Kind
		effective pb.GuardrailEffectivePolicy
		want      pb.CodeModelTrafficScanning
	}{
		{"tenant key never scanned, even with an admin policy", KindSecret, admin, pb.CodeModelTrafficScanning_CODE_MODEL_TRAFFIC_SCANNING_UNSCANNED_TENANT_KEY},
		{"tenant key never scanned, even with the baseline", KindSecret, baseline, pb.CodeModelTrafficScanning_CODE_MODEL_TRAFFIC_SCANNING_UNSCANNED_TENANT_KEY},
		{"gateway, admin policy with an inbound block rule", KindGateway, admin, pb.CodeModelTrafficScanning_CODE_MODEL_TRAFFIC_SCANNING_SCANNED},
		{"gateway, no policy configured: baseline scan", KindGateway, baseline, pb.CodeModelTrafficScanning_CODE_MODEL_TRAFFIC_SCANNING_BASELINE},
		{"gateway, policy without an inbound block rule", KindGateway, none, pb.CodeModelTrafficScanning_CODE_MODEL_TRAFFIC_SCANNING_UNSCANNED_NO_POLICY},
		{"gateway, policy unreadable", KindGateway, unknown, pb.CodeModelTrafficScanning_CODE_MODEL_TRAFFIC_SCANNING_UNSPECIFIED},
		{"unknown credential", Kind("x"), baseline, pb.CodeModelTrafficScanning_CODE_MODEL_TRAFFIC_SCANNING_UNSPECIFIED},
	}
	for _, tc := range cases {
		if got := ModelTrafficScanning(tc.cred, tc.effective); got != tc.want {
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
