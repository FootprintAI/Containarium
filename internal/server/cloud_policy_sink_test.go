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
}
