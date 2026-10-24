package netpolicy

import (
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// egress_mode is carried through Compile as given: UNSPECIFIED stays
// UNSPECIFIED (it means "follow mode", resolved where the BPF config is
// built), and an explicit value is kept even when it differs from mode.
func TestCompile_EgressModeCarriedAsGiven(t *testing.T) {
	for _, m := range []pb.NetworkPolicyMode{
		pb.NetworkPolicyMode_NETWORK_POLICY_MODE_UNSPECIFIED,
		pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY,
		pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE,
	} {
		got, err := Compile(&pb.NetworkPolicy{
			Tenant:     "t",
			Mode:       pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE,
			EgressMode: m,
		})
		if err != nil {
			t.Fatalf("Compile(egress_mode=%v): %v", m, err)
		}
		if got.EgressMode != m {
			t.Errorf("egress_mode=%v: compiled EgressMode = %v", m, got.EgressMode)
		}
		if got.Mode != pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE {
			t.Errorf("egress_mode=%v must not change Mode, got %v", m, got.Mode)
		}
		if back := got.ToProto().GetEgressMode(); back != m {
			t.Errorf("ToProto egress_mode = %v, want %v", back, m)
		}
	}
}

func TestCompile_EgressModeUnknownRejected(t *testing.T) {
	if _, err := Compile(&pb.NetworkPolicy{Tenant: "t", EgressMode: pb.NetworkPolicyMode(99)}); err == nil {
		t.Error("an unknown egress_mode must be rejected, like an unknown mode")
	}
}

// EffectiveEgressMode is the one place "unset follows mode" is decided.
func TestCompiledPolicy_EffectiveEgressMode(t *testing.T) {
	const (
		unset   = pb.NetworkPolicyMode_NETWORK_POLICY_MODE_UNSPECIFIED
		logOnly = pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY
		enforce = pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE
	)
	cases := []struct {
		name       string
		mode, egr  pb.NetworkPolicyMode
		wantEgress pb.NetworkPolicyMode
	}{
		{"unset follows enforce", enforce, unset, enforce},
		{"unset follows log-only", logOnly, unset, logOnly},
		{"unset mode and egress resolve to log-only", unset, unset, logOnly},
		{"enforce with log-only egress", enforce, logOnly, logOnly},
		{"log-only with enforce egress", logOnly, enforce, enforce},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := Compile(&pb.NetworkPolicy{Tenant: "t", Mode: tc.mode, EgressMode: tc.egr})
			if err != nil {
				t.Fatal(err)
			}
			if got := c.EffectiveEgressMode(); got != tc.wantEgress {
				t.Errorf("EffectiveEgressMode() = %v, want %v", got, tc.wantEgress)
			}
		})
	}
}
