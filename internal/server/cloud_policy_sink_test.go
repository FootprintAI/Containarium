package server

import (
	"context"
	"net/netip"
	"testing"

	"github.com/footprintai/containarium/internal/netpolicy"
	cloudv1 "github.com/footprintai/containarium/pkg/pb/containarium/cloud/v1"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// syncOne runs one cloud batch through the sink and returns the stored policy.
func syncOne(t *testing.T, in *cloudv1.NetworkPolicy) *pb.NetworkPolicy {
	t.Helper()
	np := NewNetworkPolicyServer(NewMemNetworkPolicyStore())
	if err := newCloudPolicySink(np).SyncNetworkPolicies(context.Background(), []*cloudv1.NetworkPolicy{in}); err != nil {
		t.Fatalf("SyncNetworkPolicies: %v", err)
	}
	got, err := np.Store().Get(context.Background(), in.GetOrgId())
	if err != nil {
		t.Fatalf("policy not stored: %v", err)
	}
	return got
}

// #2994: a cloud-sourced policy gets the ALLOW_LIST_ONLY preset, matching the
// locally authored default, whatever mode the batch carries.
func TestCloudPolicySink_ForcesAllowListOnlyPreset(t *testing.T) {
	for _, mode := range []cloudv1.NetworkPolicyMode{
		cloudv1.NetworkPolicyMode_NETWORK_POLICY_MODE_UNSPECIFIED,
		cloudv1.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY,
		cloudv1.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE,
	} {
		t.Run(mode.String(), func(t *testing.T) {
			got := syncOne(t, &cloudv1.NetworkPolicy{OrgId: "org-p", Mode: mode})
			if got.GetEgressPreset() != pb.EgressPreset_EGRESS_PRESET_ALLOW_LIST_ONLY {
				t.Errorf("egress preset = %v, want EGRESS_PRESET_ALLOW_LIST_ONLY", got.GetEgressPreset())
			}
		})
	}
}

// #2994: a narrow cloud-authored allow-list must still let the box reach the
// host's bridge gateway (DNS resolver, model gateway), while anything the list
// does not name stays outside the allow-set.
func TestCloudPolicySink_NarrowListStillAllowsHostGateway(t *testing.T) {
	got := syncOne(t, &cloudv1.NetworkPolicy{
		OrgId:       "org-n",
		EgressCidrs: []string{"203.0.113.10/32"},
		Mode:        cloudv1.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE,
	})
	c, err := netpolicy.Compile(got)
	if err != nil {
		t.Fatalf("Compile stored cloud policy: %v", err)
	}
	gateway := netip.MustParseAddr("192.0.2.1")
	implicit := netpolicy.ImplicitEgress(c, gateway)

	for _, tc := range []struct {
		dst  string
		want bool
	}{
		{"192.0.2.1", true},     // host gateway: implicit via the preset
		{"203.0.113.10", true},  // listed by the cloud
		{"198.51.100.7", false}, // not listed: still outside the allow-set
	} {
		if gotAllow := c.Allows(netip.MustParseAddr(tc.dst), implicit); gotAllow != tc.want {
			t.Errorf("Allows(%s) = %v, want %v", tc.dst, gotAllow, tc.want)
		}
	}
}

// #2994 / #2976: the vendored wire message has no egress_mode yet, so the sink
// stores it unset, which means "follow mode": an ENFORCE batch enforces the
// allow-list and a LOG_ONLY batch only logs it.
func TestCloudPolicySink_UnsetEgressModeFollowsMode(t *testing.T) {
	for _, tc := range []struct {
		mode cloudv1.NetworkPolicyMode
		want pb.NetworkPolicyMode
	}{
		{cloudv1.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE, pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE},
		{cloudv1.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY, pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY},
		{cloudv1.NetworkPolicyMode_NETWORK_POLICY_MODE_UNSPECIFIED, pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY},
	} {
		t.Run(tc.mode.String(), func(t *testing.T) {
			got := syncOne(t, &cloudv1.NetworkPolicy{OrgId: "org-m", Mode: tc.mode})
			if got.GetEgressMode() != pb.NetworkPolicyMode_NETWORK_POLICY_MODE_UNSPECIFIED {
				t.Errorf("stored egress_mode = %v, want UNSPECIFIED (follow mode)", got.GetEgressMode())
			}
			c, err := netpolicy.Compile(got)
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			if eff := c.EffectiveEgressMode(); eff != tc.want {
				t.Errorf("effective egress mode = %v, want %v", eff, tc.want)
			}
		})
	}
}

func TestCloudPolicySink_WritesIntoStore(t *testing.T) {
	np := NewNetworkPolicyServer(NewMemNetworkPolicyStore())
	sink := newCloudPolicySink(np)

	err := sink.SyncNetworkPolicies(context.Background(), []*cloudv1.NetworkPolicy{
		{
			OrgId:         "org-7",
			EgressCidrs:   []string{"8.8.8.8/32"},
			EgressDomains: []string{"api.github.com"},
			AllowMetadata: false,
			Mode:          cloudv1.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE,
		},
		{OrgId: ""}, // skipped (no org)
	})
	if err != nil {
		t.Fatalf("SyncNetworkPolicies: %v", err)
	}

	got, err := np.Store().Get(context.Background(), "org-7")
	if err != nil {
		t.Fatalf("policy not stored under org tenant: %v", err)
	}
	if got.GetMode() != pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE {
		t.Errorf("mode not mapped to ENFORCE: %v", got.GetMode())
	}
	if len(got.GetEgressCidrs()) != 1 || got.GetEgressCidrs()[0] != "8.8.8.8/32" {
		t.Errorf("egress not stored: %v", got.GetEgressCidrs())
	}
	if got.GetAllowMetadata() {
		t.Errorf("metadata must stay denied")
	}
	if got.GetSource() != cloudPolicySource {
		t.Errorf("cloud-synced policy must be tagged source=cloud, got %q", got.GetSource())
	}
}

func TestCloudPolicySink_ConvergesWithoutClobberingCLI(t *testing.T) {
	np := NewNetworkPolicyServer(NewMemNetworkPolicyStore())
	ctx := context.Background()
	store := np.Store()

	// An operator's CLI-authored policy (empty source) + an initial cloud policy.
	if err := store.Set(ctx, &pb.NetworkPolicy{Tenant: "local-team", EgressCidrs: []string{"10.0.0.0/8"}}); err != nil {
		t.Fatal(err)
	}
	sink := newCloudPolicySink(np)
	if err := sink.SyncNetworkPolicies(ctx, []*cloudv1.NetworkPolicy{
		{OrgId: "org-a"}, {OrgId: "org-b"},
	}); err != nil {
		t.Fatal(err)
	}

	// Next batch drops org-b → it must be deleted; org-a kept; local-team untouched.
	if err := sink.SyncNetworkPolicies(ctx, []*cloudv1.NetworkPolicy{{OrgId: "org-a"}}); err != nil {
		t.Fatal(err)
	}

	if _, err := store.Get(ctx, "org-a"); err != nil {
		t.Errorf("org-a should remain: %v", err)
	}
	if _, err := store.Get(ctx, "org-b"); err == nil {
		t.Errorf("org-b should be converged away (removed cloud-side)")
	}
	if _, err := store.Get(ctx, "local-team"); err != nil {
		t.Errorf("CLI-authored local-team must NOT be clobbered by cloud convergence: %v", err)
	}
}

// #2994: the cloud's egress_mode reaches the stored policy, so an org that soaks
// its allow-list in LOG_ONLY (cross-org traffic still ENFORCE) is not enforced
// on a cloud-managed host.
func TestCloudPolicySink_CarriesEgressMode(t *testing.T) {
	for _, tc := range []struct {
		name        string
		mode        cloudv1.NetworkPolicyMode
		egress      cloudv1.EgressMode
		wantStored  pb.NetworkPolicyMode
		wantEffMode pb.NetworkPolicyMode
	}{
		{"enforce with a log-only soak",
			cloudv1.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE, cloudv1.EgressMode_EGRESS_MODE_LOG_ONLY,
			pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY, pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY},
		{"enforce with enforced egress",
			cloudv1.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE, cloudv1.EgressMode_EGRESS_MODE_ENFORCE,
			pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE, pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE},
		{"log-only mode with enforced egress",
			cloudv1.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY, cloudv1.EgressMode_EGRESS_MODE_ENFORCE,
			pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE, pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE},
		{"unset follows mode",
			cloudv1.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE, cloudv1.EgressMode_EGRESS_MODE_UNSPECIFIED,
			pb.NetworkPolicyMode_NETWORK_POLICY_MODE_UNSPECIFIED, pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE},
		{"a value this host does not know follows mode",
			cloudv1.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE, cloudv1.EgressMode(99),
			pb.NetworkPolicyMode_NETWORK_POLICY_MODE_UNSPECIFIED, pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := syncOne(t, &cloudv1.NetworkPolicy{OrgId: "org-e", Mode: tc.mode, EgressMode: tc.egress})
			if got.GetMode() != pb.NetworkPolicyMode(int32(tc.mode)) {
				t.Errorf("stored mode = %v, want %v (egress_mode must not change the cross-tenant mode)", got.GetMode(), tc.mode)
			}
			if got.GetEgressMode() != tc.wantStored {
				t.Errorf("stored egress_mode = %v, want %v", got.GetEgressMode(), tc.wantStored)
			}
			c, err := netpolicy.Compile(got)
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			if eff := c.EffectiveEgressMode(); eff != tc.wantEffMode {
				t.Errorf("effective egress mode = %v, want %v", eff, tc.wantEffMode)
			}
		})
	}
}
