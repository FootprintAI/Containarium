package server

import (
	"context"

	cloudv1 "github.com/footprintai/containarium/pkg/pb/containarium/cloud/v1"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// cloudPolicySink implements cloud.PolicySink: it writes per-org egress policies
// received from the cloud-actuation channel into the NetworkPolicyServer's store
// (keyed by org as the tenant), where the eBPF enforcer's reconcile loop applies
// them. This is the OSS end of the #315 cloud extension — it closes the loop
// from cloud-authored policy to on-box enforcement.
//
// It holds the *NetworkPolicyServer (not the store directly) so it always writes
// to the current store, even after the startup-time Postgres swap.
type cloudPolicySink struct {
	np *NetworkPolicyServer
}

func newCloudPolicySink(np *NetworkPolicyServer) *cloudPolicySink {
	return &cloudPolicySink{np: np}
}

// SyncNetworkPolicies upserts each org's policy into the store. The org_id is the
// tenant key — cloud containers are labelled user.containarium.tenant=<org_id>
// (container reconcile, a follow-up), so the enforcer matches them. Upsert-only:
// a policy removed cloud-side is not deleted locally yet (distinguishing
// cloud-authored from CLI-authored policies needs a source marker — a follow-up);
// upsert keeps the common rollout path correct without risking clobbering a
// self-hosted operator's CLI-authored policy.
func (s *cloudPolicySink) SyncNetworkPolicies(ctx context.Context, policies []*cloudv1.NetworkPolicy) error {
	store := s.np.Store()
	if store == nil {
		return nil
	}
	for _, np := range policies {
		if np.GetOrgId() == "" {
			continue
		}
		if err := store.Set(ctx, &pb.NetworkPolicy{
			Tenant:           np.GetOrgId(),
			AllowIntraTenant: np.GetAllowIntraTenant(),
			EgressCidrs:      np.GetEgressCidrs(),
			EgressDomains:    np.GetEgressDomains(),
			AllowMetadata:    np.GetAllowMetadata(),
			Mode:             pb.NetworkPolicyMode(int32(np.GetMode())), // same enum values (vendored from one source)
		}); err != nil {
			return err
		}
	}
	return nil
}
