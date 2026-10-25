package server

import (
	"context"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

const nativeTenantContract = "boxweave.tenant-network/v1"

// A fresh successful pass is evidence of availability, never a TCP test.
// Each create still performs the required synchronous pre-Start attachment.
func nativeTenantGuardReady(g *pb.GuardStatus, now time.Time) bool {
	if g == nil || g.Mode != pb.GuardMode_GUARD_MODE_ENFORCE || g.FirewallDriver != "nftables" || g.Unsupported || g.LastError != "" || g.StaleSince != "" || len(g.Unresolved) > 0 {
		return false
	}
	stamp, err := time.Parse(time.RFC3339, g.LastPass)
	if err != nil || now.Sub(stamp) > 180*time.Second || now.Sub(stamp) < -30*time.Second {
		return false
	}
	for _, e := range g.Entries {
		if e == nil || !e.Attached || e.LastError != "" {
			return false
		}
	}
	return true
}

func (s *NetworkServer) GetNetworkTenantCapabilities(ctx context.Context, _ *pb.GetNetworkTenantCapabilitiesRequest) (*pb.GetNetworkTenantCapabilitiesResponse, error) {
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	if err := auth.RequireScope(ctx, auth.ScopeContainersRead); err != nil {
		return nil, err
	}
	ready := s.nativeTenantLocal && s.nativeTenantReady != nil && s.nativeTenantReady() && auth.RequireScope(ctx, auth.ScopeContainersWrite) == nil
	out := &pb.GetNetworkTenantCapabilitiesResponse{Contract: nativeTenantContract, NativeMembershipRead: s.nativeTenantLocal, SharedTenantCreate: ready, BackendScope: "local-lxc"}
	if !ready {
		out.Reason = "local Linux LXC, durable policy source and fresh supported enforced Tenant Guard and containers:write required"
	}
	// This PR implements A only. Existing allow_from_tenants remains untouched.
	// Never advertise B merely because a legacy full-policy endpoint exists.
	out.AtomicTenantAccess = false
	out.NetworkPolicyWrite = false
	return out, nil
}
