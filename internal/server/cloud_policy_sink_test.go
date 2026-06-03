package server

import (
	"context"
	"testing"

	cloudv1 "github.com/footprintai/containarium/pkg/pb/containarium/cloud/v1"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

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
