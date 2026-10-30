package server

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/netpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// GetNetworkPolicyStatus says whether a tenant runs the host's default egress
// allow-list or a stored policy (#2996).
func TestNetworkPolicyStatus_PolicySource(t *testing.T) {
	def, err := netpolicy.DefaultPolicy("acme", netpolicy.DefaultEgressExtras{})
	if err != nil {
		t.Fatal(err)
	}
	views := []containerView{{Name: "acme-container", Tenant: "acme", TenantID: 1, Ifindex: 11, HasVeth: true, Running: true}}
	cases := []struct {
		name     string
		policies map[string]netpolicy.CompiledPolicy
		want     pb.NetworkPolicySource
	}{
		{"host default", map[string]netpolicy.CompiledPolicy{"acme": def}, pb.NetworkPolicySource_NETWORK_POLICY_SOURCE_HOST_DEFAULT},
		{"stored policy", map[string]netpolicy.CompiledPolicy{"acme": compiled(t, &pb.NetworkPolicy{Tenant: "acme", Mode: stLogOnly})}, pb.NetworkPolicySource_NETWORK_POLICY_SOURCE_STORED},
		{"default posture off, no policy", map[string]netpolicy.CompiledPolicy{}, pb.NetworkPolicySource_NETWORK_POLICY_SOURCE_UNSPECIFIED},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			applied := appliedPass(t, views, tc.policies, false)
			st := npStatusFor(t, fakeAppliedSource{fresh(applied["acme"])}, false, "acme")
			if st.GetPolicySource() != tc.want {
				t.Errorf("policy_source = %v, want %v", st.GetPolicySource(), tc.want)
			}
		})
	}
}

// With nothing loaded the source is unknown, never guessed.
func TestNetworkPolicyStatus_PolicySourceUnknownWhenNotLoaded(t *testing.T) {
	st := npStatusFor(t, nil, false, "acme")
	if st.GetPolicySource() != pb.NetworkPolicySource_NETWORK_POLICY_SOURCE_UNSPECIFIED {
		t.Errorf("policy_source = %v, want UNSPECIFIED", st.GetPolicySource())
	}
}

// The default policy is marked as such; a compiled stored policy is not.
func TestDefaultPolicy_IsMarkedDefault(t *testing.T) {
	def, err := netpolicy.DefaultPolicy("acme", netpolicy.DefaultEgressExtras{})
	if err != nil {
		t.Fatal(err)
	}
	if !def.IsHostDefault {
		t.Error("DefaultPolicy is not marked IsHostDefault")
	}
	if compiled(t, &pb.NetworkPolicy{Tenant: "acme"}).IsHostDefault {
		t.Error("a stored policy is marked IsHostDefault")
	}
}

// The plan does not subtract the host default allow-list, and says so (#2996).
func TestPlanNetworkPolicy_SaysItDoesNotSubtractTheHostDefault(t *testing.T) {
	s := newNPServer()
	s.SetPlanSources(&fakeAuditQuery{}, netip.Addr{})
	resp, err := s.PlanNetworkPolicy(npAdminCtx(), &pb.PlanNetworkPolicyRequest{Tenant: "fresh"})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.GetNotes()) == 0 || !strings.Contains(resp.GetNotes()[0], "default egress allow-list") || !strings.Contains(resp.GetNotes()[0], "not subtracted") {
		t.Errorf("notes = %v", resp.GetNotes())
	}
}
