package server

import (
	"context"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// NativeTenantContractID is the stable capability-handshake identifier, and
// NativeTenantBackendScope the scope of its creation evidence. Both live in
// pkg/core/incus so clients and the daemon compare the same constants.
const (
	nativeTenantContract     = incus.NativeTenantContractID
	nativeTenantBackendScope = incus.NativeTenantBackendScope
)

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
	out := &pb.GetNetworkTenantCapabilitiesResponse{Contract: nativeTenantContract, NativeMembershipRead: s.nativeTenantLocal, SharedTenantCreate: ready, BackendScope: nativeTenantBackendScope}
	if !ready {
		out.Reason = "local Linux LXC, durable policy source and fresh supported enforced Tenant Guard and containers:write required"
	}
	out.AtomicTenantAccess = s.nativeTenantLocal && s.atomicTenantAccessReady != nil && s.atomicTenantAccessReady()
	out.NetworkPolicyWrite = out.AtomicTenantAccess && auth.RequireScope(ctx, auth.ScopeNetworkPolicyWrite) == nil

	return out, nil
}
