package netpolicy

import (
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestCompile_OK(t *testing.T) {
	got, err := Compile(&pb.NetworkPolicy{
		Tenant:           "alice",
		AllowIntraTenant: true,
		EgressCidrs:      []string{"10.0.0.0/8", "1.2.3.4/24", "10.0.0.0/8"}, // dup + non-network
		EgressDomains:    []string{"API.github.com", "api.github.com.", " pypi.org "},
		Mode:             pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE,
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if got.Tenant != "alice" || !got.AllowIntraTenant {
		t.Errorf("tenant/allow_intra wrong: %+v", got)
	}
	// 1.2.3.4/24 masked → 1.2.3.0/24; 10.0.0.0/8 deduped → 2 unique.
	if len(got.EgressCIDRs) != 2 {
		t.Fatalf("want 2 CIDRs, got %d: %v", len(got.EgressCIDRs), got.EgressCIDRs)
	}
	if got.EgressCIDRs[0].String() != "1.2.3.0/24" || got.EgressCIDRs[1].String() != "10.0.0.0/8" {
		t.Errorf("CIDRs not masked/sorted: %v", got.EgressCIDRs)
	}
	// Domains lowercased, trailing dot stripped, trimmed, deduped → 2 unique.
	if len(got.EgressDomains) != 2 || got.EgressDomains[0] != "api.github.com" || got.EgressDomains[1] != "pypi.org" {
		t.Errorf("domains not normalized/deduped: %v", got.EgressDomains)
	}
	if got.Mode != pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE || got.LogOnly {
		t.Errorf("ENFORCE should not be log-only: mode=%v logOnly=%v", got.Mode, got.LogOnly)
	}
}

func TestCompile_ModeDefaultsToLogOnly(t *testing.T) {
	for _, m := range []pb.NetworkPolicyMode{
		pb.NetworkPolicyMode_NETWORK_POLICY_MODE_UNSPECIFIED,
		pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY,
	} {
		got, err := Compile(&pb.NetworkPolicy{Tenant: "t", Mode: m})
		if err != nil {
			t.Fatalf("Compile(mode=%v): %v", m, err)
		}
		if got.Mode != pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY || !got.LogOnly {
			t.Errorf("mode=%v should resolve to LOG_ONLY + LogOnly=true, got mode=%v logOnly=%v", m, got.Mode, got.LogOnly)
		}
	}
}

func TestCompile_Errors(t *testing.T) {
	cases := []struct {
		name string
		p    *pb.NetworkPolicy
		want string
	}{
		{"nil", nil, "nil"},
		{"empty tenant", &pb.NetworkPolicy{Tenant: "  "}, "tenant is required"},
		{"bad cidr", &pb.NetworkPolicy{Tenant: "t", EgressCidrs: []string{"not-a-cidr"}}, "invalid egress CIDR"},
		{"bad cidr bits", &pb.NetworkPolicy{Tenant: "t", EgressCidrs: []string{"10.0.0.0/40"}}, "invalid egress CIDR"},
		{"domain with scheme", &pb.NetworkPolicy{Tenant: "t", EgressDomains: []string{"https://x.com"}}, "bare hostname"},
		{"domain with port", &pb.NetworkPolicy{Tenant: "t", EgressDomains: []string{"x.com:443"}}, "bare hostname"},
		{"unknown mode", &pb.NetworkPolicy{Tenant: "t", Mode: pb.NetworkPolicyMode(99)}, "unknown mode"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Compile(tc.p)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.want)
			}
			// Validate mirrors Compile.
			if Validate(tc.p) == nil {
				t.Errorf("Validate should also reject %s", tc.name)
			}
		})
	}
}

func TestCompile_EmptyListsAreFine(t *testing.T) {
	got, err := Compile(&pb.NetworkPolicy{Tenant: "t"})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(got.EgressCIDRs) != 0 || len(got.EgressDomains) != 0 {
		t.Errorf("expected empty egress sets, got %+v", got)
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
