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

// cloudPolicySource marks a stored policy as cloud-authored, so convergence
// only ever deletes the cloud's own policies — never an operator's CLI-authored
// one (which carries an empty source). Matches pb.NetworkPolicy.Source.
const cloudPolicySource = "cloud"

func newCloudPolicySink(np *NetworkPolicyServer) *cloudPolicySink {
	return &cloudPolicySink{np: np}
}

// SyncNetworkPolicies converges the store to the cloud's current set: upsert
// each org's policy (tagged source="cloud"; org_id is the tenant key, matching
// the user.containarium.tenant label the container reconcile stamps), then
// delete any previously cloud-authored policy no longer in the batch. Policies
// authored locally via the CLI (empty source) are never touched — so a mixed
// host (cloud + operator policies) stays correct.
func (s *cloudPolicySink) SyncNetworkPolicies(ctx context.Context, policies []*cloudv1.NetworkPolicy) error {
	store := s.np.Store()
	if store == nil {
		return nil
	}
	desired := make(map[string]bool, len(policies))
	for _, np := range policies {
		if np.GetOrgId() == "" {
			continue
		}
		desired[np.GetOrgId()] = true
		if err := store.Set(ctx, &pb.NetworkPolicy{
			Tenant:           np.GetOrgId(),
			AllowIntraTenant: np.GetAllowIntraTenant(),
			EgressCidrs:      np.GetEgressCidrs(),
			EgressDomains:    np.GetEgressDomains(),
			AllowMetadata:    np.GetAllowMetadata(),
			Mode:             pb.NetworkPolicyMode(int32(np.GetMode())), // same enum values (vendored from one source)
			Source:           cloudPolicySource,
		}); err != nil {
			return err
		}
	}

	// Convergence: drop cloud-authored policies the cloud no longer sends.
	existing, err := store.List(ctx)
	if err != nil {
		return err
	}
	for _, p := range existing {
		if p.GetSource() == cloudPolicySource && !desired[p.GetTenant()] {
			if err := store.Delete(ctx, p.GetTenant()); err != nil {
				return err
			}
		}
	}
	return nil
}
