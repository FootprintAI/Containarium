package codeegress

import (
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

const (
	logOnly = pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY
	enforce = pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE
)

func TestNormalize(t *testing.T) {
	cases := []struct {
		name        string
		in          *pb.CodingToolEgressPolicy
		wantErr     string
		wantCIDRs   []string
		wantDomains []string
		wantMode    pb.NetworkPolicyMode
	}{
		{
			name: "masks, dedups and sorts CIDRs, IPv4 and IPv6",
			in: &pb.CodingToolEgressPolicy{Tenant: "alice", Mode: enforce,
				EgressCidrs: []string{"10.0.0.0/8", "1.2.3.4/24", "10.0.0.0/8", "2001:db8::1/32"}},
			wantCIDRs: []string{"1.2.3.0/24", "10.0.0.0/8", "2001:db8::/32"},
			wantMode:  enforce,
		},
		{
			name: "normalizes domains",
			in: &pb.CodingToolEgressPolicy{Tenant: "alice", Mode: logOnly,
				EgressDomains: []string{"API.Example.com", "api.example.com.", " models.example.org "}},
			wantDomains: []string{"api.example.com", "models.example.org"},
			wantMode:    logOnly,
		},
		{
			name:     "cluster default (empty tenant) is valid",
			in:       &pb.CodingToolEgressPolicy{Mode: enforce},
			wantMode: enforce,
		},
		{name: "log_only is stored as given", in: &pb.CodingToolEgressPolicy{Tenant: "t", Mode: logOnly}, wantMode: logOnly},
		// No default mode (unlike NetworkPolicy): a forgotten mode must not
		// store a policy that drops nothing.
		{name: "unspecified mode is rejected", in: &pb.CodingToolEgressPolicy{Tenant: "t"}, wantErr: "mode must be LOG_ONLY or ENFORCE"},
		{name: "unspecified mode is rejected even with destinations", in: &pb.CodingToolEgressPolicy{Tenant: "t", EgressCidrs: []string{"192.0.2.0/24"}}, wantErr: "no default mode"},
		{name: "nil", in: nil, wantErr: "policy is required"},
		{name: "bad cidr", in: &pb.CodingToolEgressPolicy{Mode: logOnly, EgressCidrs: []string{"not-a-cidr"}}, wantErr: "invalid egress CIDR"},
		{name: "bad cidr bits", in: &pb.CodingToolEgressPolicy{Mode: logOnly, EgressCidrs: []string{"10.0.0.0/40"}}, wantErr: "invalid egress CIDR"},
		{name: "bad ipv6 bits", in: &pb.CodingToolEgressPolicy{Mode: logOnly, EgressCidrs: []string{"2001:db8::/129"}}, wantErr: "invalid egress CIDR"},
		{name: "domain with scheme", in: &pb.CodingToolEgressPolicy{Mode: logOnly, EgressDomains: []string{"https://x.example.com"}}, wantErr: "bare hostname"},
		{name: "domain with port", in: &pb.CodingToolEgressPolicy{Mode: logOnly, EgressDomains: []string{"x.example.com:443"}}, wantErr: "bare hostname"},
		{name: "unknown mode", in: &pb.CodingToolEgressPolicy{Mode: pb.NetworkPolicyMode(99)}, wantErr: "mode must be LOG_ONLY or ENFORCE"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Normalize(tc.in)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Normalize err = %v, want one containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Normalize: %v", err)
			}
			if got.GetTenant() != tc.in.GetTenant() {
				t.Errorf("tenant = %q, want %q", got.GetTenant(), tc.in.GetTenant())
			}
			if !equal(got.GetEgressCidrs(), tc.wantCIDRs) {
				t.Errorf("cidrs = %v, want %v", got.GetEgressCidrs(), tc.wantCIDRs)
			}
			if !equal(got.GetEgressDomains(), tc.wantDomains) {
				t.Errorf("domains = %v, want %v", got.GetEgressDomains(), tc.wantDomains)
			}
			if got.GetMode() != tc.wantMode {
				t.Errorf("mode = %v, want %v", got.GetMode(), tc.wantMode)
			}
		})
	}
}

func TestNormalize_IgnoresServerAssignedFields(t *testing.T) {
	got, err := Normalize(&pb.CodingToolEgressPolicy{Tenant: "t", Mode: logOnly, Revision: 42, UpdatedBy: "someone"})
	if err != nil {
		t.Fatal(err)
	}
	if got.GetRevision() != 0 || got.GetUpdatedBy() != "" || got.GetUpdatedAt() != nil {
		t.Errorf("caller-supplied revision/updated_* must be dropped, got %+v", got)
	}
}

func TestEffectivePolicy(t *testing.T) {
	imp := Implicit{GatewayEndpoint: "gateway.example.internal:8080"}
	def := &pb.CodingToolEgressPolicy{Mode: logOnly, EgressDomains: []string{"default.example.com"}, Revision: 3}
	ten := &pb.CodingToolEgressPolicy{Tenant: "alice", Mode: enforce, EgressCidrs: []string{"192.0.2.0/24"}, Revision: 7}
	emptyEnforce := &pb.CodingToolEgressPolicy{Tenant: "alice", Mode: enforce, Revision: 9}
	emptyLogOnly := &pb.CodingToolEgressPolicy{Tenant: "alice", Mode: logOnly, Revision: 10}

	cases := []struct {
		name           string
		tenantPol      *pb.CodingToolEgressPolicy
		defaultPol     *pb.CodingToolEgressPolicy
		wantSource     pb.CodingToolEgressPolicySource
		wantRestricted bool
		wantDenyAll    bool
		wantMode       pb.NetworkPolicyMode
		wantCIDRs      []string
		wantDomains    []string
		wantRevision   int64
	}{
		{name: "unset is unrestricted", wantSource: pb.CodingToolEgressPolicySource_CODING_TOOL_EGRESS_POLICY_SOURCE_NONE},
		{name: "cluster default applies", defaultPol: def,
			wantSource:     pb.CodingToolEgressPolicySource_CODING_TOOL_EGRESS_POLICY_SOURCE_CLUSTER_DEFAULT,
			wantRestricted: true, wantMode: logOnly, wantDomains: []string{"default.example.com"}, wantRevision: 3},
		{name: "tenant replaces cluster default, no merge", tenantPol: ten, defaultPol: def,
			wantSource:     pb.CodingToolEgressPolicySource_CODING_TOOL_EGRESS_POLICY_SOURCE_TENANT,
			wantRestricted: true, wantMode: enforce, wantCIDRs: []string{"192.0.2.0/24"}, wantRevision: 7},
		{name: "tenant without a default", tenantPol: ten,
			wantSource:     pb.CodingToolEgressPolicySource_CODING_TOOL_EGRESS_POLICY_SOURCE_TENANT,
			wantRestricted: true, wantMode: enforce, wantCIDRs: []string{"192.0.2.0/24"}, wantRevision: 7},
		{name: "set and empty under ENFORCE is deny-all", tenantPol: emptyEnforce, defaultPol: def,
			wantSource:     pb.CodingToolEgressPolicySource_CODING_TOOL_EGRESS_POLICY_SOURCE_TENANT,
			wantRestricted: true, wantDenyAll: true, wantMode: enforce, wantRevision: 9},
		{name: "set and empty under LOG_ONLY is not deny-all", tenantPol: emptyLogOnly,
			wantSource:     pb.CodingToolEgressPolicySource_CODING_TOOL_EGRESS_POLICY_SOURCE_TENANT,
			wantRestricted: true, wantMode: logOnly, wantRevision: 10},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Effective("alice", tc.tenantPol, tc.defaultPol, imp)
			if got.GetTenant() != "alice" {
				t.Errorf("tenant = %q", got.GetTenant())
			}
			if got.GetSource() != tc.wantSource {
				t.Errorf("source = %v, want %v", got.GetSource(), tc.wantSource)
			}
			if got.GetRestricted() != tc.wantRestricted {
				t.Errorf("restricted = %v, want %v", got.GetRestricted(), tc.wantRestricted)
			}
			if got.GetDenyAll() != tc.wantDenyAll {
				t.Errorf("deny_all = %v, want %v", got.GetDenyAll(), tc.wantDenyAll)
			}
			if got.GetMode() != tc.wantMode {
				t.Errorf("mode = %v, want %v", got.GetMode(), tc.wantMode)
			}
			if !equal(got.GetEgressCidrs(), tc.wantCIDRs) || !equal(got.GetEgressDomains(), tc.wantDomains) {
				t.Errorf("lists = %v / %v, want %v / %v", got.GetEgressCidrs(), got.GetEgressDomains(), tc.wantCIDRs, tc.wantDomains)
			}
			if got.GetRevision() != tc.wantRevision {
				t.Errorf("revision = %d, want %d", got.GetRevision(), tc.wantRevision)
			}

			// Implicit entries: present exactly when a policy is in effect.
			kinds := map[pb.CodingToolEgressImplicitKind]*pb.CodingToolEgressImplicitEntry{}
			for _, e := range got.GetImplicit() {
				kinds[e.GetKind()] = e
			}
			if !tc.wantRestricted {
				if len(got.GetImplicit()) != 0 {
					t.Errorf("unrestricted must list no implicit entries, got %v", got.GetImplicit())
				}
				return
			}
			dns := kinds[pb.CodingToolEgressImplicitKind_CODING_TOOL_EGRESS_IMPLICIT_KIND_DNS_RESOLVER]
			gw := kinds[pb.CodingToolEgressImplicitKind_CODING_TOOL_EGRESS_IMPLICIT_KIND_MODEL_GATEWAY]
			if dns == nil || gw == nil || len(got.GetImplicit()) != 2 {
				t.Fatalf("want DNS and gateway implicit entries, got %v", got.GetImplicit())
			}
			if gw.GetDestination() != imp.GatewayEndpoint {
				t.Errorf("gateway destination = %q, want %q", gw.GetDestination(), imp.GatewayEndpoint)
			}
			if dns.GetDescription() == "" || gw.GetDescription() == "" {
				t.Errorf("implicit entries must say what they are: %v", got.GetImplicit())
			}
		})
	}
}

func TestEffectivePolicy_DoesNotAliasStoredLists(t *testing.T) {
	ten := &pb.CodingToolEgressPolicy{Tenant: "alice", Mode: enforce, EgressCidrs: []string{"192.0.2.0/24"}}
	got := Effective("alice", ten, nil, Implicit{})
	got.EgressCidrs[0] = "0.0.0.0/0"
	if ten.GetEgressCidrs()[0] != "192.0.2.0/24" {
		t.Fatal("effective policy shares its slice with the stored policy")
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
