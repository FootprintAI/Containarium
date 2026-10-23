package server

import (
	"context"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/netbpf"
	"github.com/footprintai/containarium/internal/netpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// tenantApplied is what one reconcile pass actually loaded into the kernel for
// a tenant: the per-veth config written for its running boxes (after the
// host's enforce guard) and how many of those boxes it reached.
type tenantApplied struct {
	Mode           uint8 // netbpf.ModeLogOnly | netbpf.ModeEnforce, as written to veth_policy
	EgressMode     uint8 // as written to veth_policy
	BoxesLoaded    int   // running boxes whose config was written and program attached
	BoxesNotLoaded int   // running boxes with no loaded config (no veth, write or attach failed)
	HasDomains     bool  // the loaded allow-list includes resolved egress_domains
	AppliedAt      time.Time
}

// appliedSnapshot is the enforcer's answer for one tenant.
type appliedSnapshot struct {
	Running    bool // the BPF program is loaded on this daemon
	Reconciled bool // at least one reconcile pass has applied the maps
	Found      bool // the last pass saw a running box of this tenant
	Tenant     tenantApplied
}

// appliedStateSource is the slice of the enforcer GetNetworkPolicyStatus reads.
// *NetworkPolicyEnforcer satisfies it.
type appliedStateSource interface {
	AppliedState(tenant string) appliedSnapshot
}

// appliedFromPass builds the per-tenant applied state from one reconcile pass:
// the plan it applied and, per planned veth, whether the config write and the
// attach both succeeded. A running box without a resolved veth never reaches
// the plan's veth map, so it is counted as not loaded from the views.
func appliedFromPass(views []containerView, plan reconcilePlan, loaded map[int]bool, policies map[string]netpolicy.CompiledPolicy, now time.Time) map[string]tenantApplied {
	out := make(map[string]tenantApplied)
	for _, v := range views {
		if !v.Running {
			continue
		}
		a := out[v.Tenant]
		cfg, planned := plan.vethPolicy[v.Ifindex]
		if v.HasVeth && planned && loaded[v.Ifindex] {
			a.Mode, a.EgressMode = cfg.Mode, cfg.EgressMode
			a.BoxesLoaded++
			a.AppliedAt = now
			a.HasDomains = len(policies[v.Tenant].EgressDomains) > 0
		} else {
			a.BoxesNotLoaded++
		}
		out[v.Tenant] = a
	}
	return out
}

// SetEnforcementArmed records whether this host arms enforcement
// (CONTAINARIUM_NETWORK_POLICY_ENFORCE). Startup-only.
func (s *NetworkPolicyServer) SetEnforcementArmed(armed bool) { s.enforceArmed = armed }

// SetAppliedStateSource wires the enforcer whose loaded state
// GetNetworkPolicyStatus reports. Startup-only; nil (the default) reports the
// enforcer as not running.
func (s *NetworkPolicyServer) SetAppliedStateSource(src appliedStateSource) { s.applied = src }

// GetNetworkPolicyStatus reports what this daemon has loaded for a tenant. It
// never falls back to the stored policy: a state it cannot read is reported as
// unknown (UNSPECIFIED modes).
func (s *NetworkPolicyServer) GetNetworkPolicyStatus(ctx context.Context, req *pb.GetNetworkPolicyStatusRequest) (*pb.GetNetworkPolicyStatusResponse, error) {
	if err := auth.RequireRoleOrScope(ctx, auth.RoleAdmin, auth.ScopeNetworkPolicyRead); err != nil {
		return nil, err
	}
	tenant := strings.TrimSpace(req.GetTenant())
	if tenant == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant is required")
	}
	var snap appliedSnapshot
	if s.applied != nil {
		snap = s.applied.AppliedState(tenant)
	}
	return &pb.GetNetworkPolicyStatusResponse{Status: buildPolicyStatus(tenant, snap, s.enforceArmed)}, nil
}

func buildPolicyStatus(tenant string, snap appliedSnapshot, armed bool) *pb.NetworkPolicyStatus {
	st := &pb.NetworkPolicyStatus{
		Tenant:           tenant,
		EnforcementArmed: armed,
		// The program parses IPv4 only, whatever is loaded.
		UncoveredPaths: []pb.NetworkPolicyUncoveredPath{pb.NetworkPolicyUncoveredPath_NETWORK_POLICY_UNCOVERED_PATH_IPV6},
	}
	switch {
	case !snap.Running:
		st.State = pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_ENFORCER_NOT_RUNNING
		return st
	case !snap.Reconciled:
		st.State = pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_UNSPECIFIED
		return st
	}
	a := snap.Tenant
	if snap.Found {
		st.BoxesLoaded = uint32(max(a.BoxesLoaded, 0))       // #nosec G115 -- clamped, box counts are small
		st.BoxesNotLoaded = uint32(max(a.BoxesNotLoaded, 0)) // #nosec G115 -- clamped, box counts are small
	}
	if !snap.Found || a.BoxesLoaded == 0 {
		st.State = pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_NOT_LOADED
		return st
	}
	st.State = pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_LOADED
	st.EffectiveMode = bpfModeToProto(a.Mode)
	st.EffectiveEgressMode = bpfModeToProto(a.EgressMode)
	st.LastAppliedAt = timestamppb.New(a.AppliedAt)
	if a.HasDomains {
		st.UncoveredPaths = append(st.UncoveredPaths, pb.NetworkPolicyUncoveredPath_NETWORK_POLICY_UNCOVERED_PATH_DOMAIN_REFRESH_LAG)
	}
	return st
}

// bpfModeToProto maps a veth_policy mode byte to the proto enum; anything
// else is unknown.
func bpfModeToProto(m uint8) pb.NetworkPolicyMode {
	switch m {
	case netbpf.ModeLogOnly:
		return pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY
	case netbpf.ModeEnforce:
		return pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE
	default:
		return pb.NetworkPolicyMode_NETWORK_POLICY_MODE_UNSPECIFIED
	}
}
