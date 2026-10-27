package server

import (
	"context"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/hostcheck"
	"github.com/footprintai/containarium/internal/netbpf"
	"github.com/footprintai/containarium/internal/netpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// tenantApplied is what one reconcile pass actually loaded into the kernel for
// a tenant: the per-veth config written for its running boxes (after the
// host's enforce guard) and how many of those boxes it reached.
type tenantApplied struct {
	Mode           uint8                  // netbpf.ModeLogOnly | netbpf.ModeEnforce, as written to veth_policy
	EgressMode     uint8                  // as written to veth_policy
	BoxesLoaded    int                    // running boxes whose config was written and program attached
	BoxesNotLoaded int                    // running boxes with no loaded config (no veth, write or attach failed)
	HasDomains     bool                   // the loaded allow-list includes resolved egress_domains
	Source         pb.NetworkPolicySource // the host default or a stored policy; UNSPECIFIED when neither is known
	// EgressIncomplete: an add or removal in the tenant's egress allow-list
	// failed this pass, so the kernel list differs from the policy (#2983).
	EgressIncomplete bool
}

// appliedSnapshot is the enforcer's answer for one tenant.
type appliedSnapshot struct {
	Running    bool // the BPF program is loaded on this daemon
	Reconciled bool // at least one reconcile pass has applied the maps
	Found      bool // the last pass saw a running box of this tenant
	Tenant     tenantApplied
	// ReconciledAt is when the last completed pass ended; Interval is the
	// enforcer's reconcile interval, which decides when that pass is stale.
	ReconciledAt time.Time
	Interval     time.Duration
}

// staleAfterPasses is how many reconcile intervals the last completed pass may
// age before the status stops trusting it.
const staleAfterPasses = 3

// appliedStateSource is the slice of the enforcer GetNetworkPolicyStatus reads.
// *NetworkPolicyEnforcer satisfies it.
type appliedStateSource interface {
	AppliedState(tenant string) appliedSnapshot
}

// appliedFromPass builds the per-tenant applied state from one reconcile pass:
// the plan it applied and, per planned veth, whether the config write and the
// attach both succeeded. A running box without a resolved veth never reaches
// the plan's veth map, so it is counted as not loaded from the views.
//
// egressIncomplete marks a tenant id whose allow-list write failed this pass,
// and egressNames names it. The mark is keyed by the failed entry's tenant, not
// by the running views (#3051): a tenant with only stopped boxes, or with no box
// left after its policy was removed, still gets a record carrying it.
func appliedFromPass(views []containerView, plan reconcilePlan, loaded map[int]bool, policies map[string]netpolicy.CompiledPolicy, egressIncomplete map[uint32]bool, egressNames map[uint32]string) map[string]tenantApplied {
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
			a.HasDomains = len(policies[v.Tenant].EgressDomains) > 0
			a.Source = policySource(policies, v.Tenant)
		} else {
			a.BoxesNotLoaded++
		}
		out[v.Tenant] = a
	}
	for id, bad := range egressIncomplete {
		name, ok := egressNames[id]
		if !bad || !ok {
			continue
		}
		a := out[name]
		a.EgressIncomplete = true
		out[name] = a
	}
	return out
}

// policySource says where a tenant's loaded policy came from. A tenant with no
// entry (default posture off, nothing stored) is unknown, not "default".
func policySource(policies map[string]netpolicy.CompiledPolicy, tenant string) pb.NetworkPolicySource {
	c, ok := policies[tenant]
	switch {
	case !ok:
		return pb.NetworkPolicySource_NETWORK_POLICY_SOURCE_UNSPECIFIED
	case c.IsHostDefault:
		return pb.NetworkPolicySource_NETWORK_POLICY_SOURCE_HOST_DEFAULT
	default:
		return pb.NetworkPolicySource_NETWORK_POLICY_SOURCE_STORED
	}
}

// SetEnforcementArmed records whether this host arms enforcement
// (CONTAINARIUM_NETWORK_POLICY_ENFORCE). Startup-only.
func (s *NetworkPolicyServer) SetEnforcementArmed(armed bool) { s.enforceArmed = armed }

// SetAppliedStateSource wires the enforcer whose loaded state
// GetNetworkPolicyStatus reports. Startup-only; nil (the default) reports the
// enforcer as not running.
func (s *NetworkPolicyServer) SetAppliedStateSource(src appliedStateSource) { s.applied = src }

// now is the status clock; tests replace clock.
func (s *NetworkPolicyServer) now() time.Time {
	if s.clock != nil {
		return s.clock()
	}
	return time.Now()
}

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
	return &pb.GetNetworkPolicyStatusResponse{Status: buildPolicyStatus(tenant, snap, s.enforceArmed, s.now(), s.hostKernelUnsupported())}, nil
}

// hostKernelUnsupported asks the injected probe, or the host itself.
func (s *NetworkPolicyServer) hostKernelUnsupported() bool {
	if s.kernelUnsupported != nil {
		return s.kernelUnsupported()
	}
	return hostcheck.EgressKernelUnsupported()
}

func buildPolicyStatus(tenant string, snap appliedSnapshot, armed bool, now time.Time, kernelUnsupported bool) *pb.NetworkPolicyStatus {
	st := &pb.NetworkPolicyStatus{
		Tenant:           tenant,
		EnforcementArmed: armed,
		// The program parses IPv4 only, whatever is loaded.
		UncoveredPaths: []pb.NetworkPolicyUncoveredPath{pb.NetworkPolicyUncoveredPath_NETWORK_POLICY_UNCOVERED_PATH_IPV6},
	}
	// A kernel below 6.6 cannot attach the egress program at all, whatever the
	// enforcer reports (#2972); said in every state, including enforcer-not-running.
	if kernelUnsupported {
		st.UncoveredPaths = append(st.UncoveredPaths, pb.NetworkPolicyUncoveredPath_NETWORK_POLICY_UNCOVERED_PATH_KERNEL_UNSUPPORTED)
	}
	switch {
	case !snap.Running:
		st.State = pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_ENFORCER_NOT_RUNNING
		return st
	case !snap.Reconciled:
		st.State = pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_UNSPECIFIED
		return st
	}
	// A pass completed: its time is reported in every state below, so an
	// operator can see how old the record is.
	st.LastReconciledAt = timestamppb.New(snap.ReconciledAt)
	// Failing passes leave the last record in place; past a few intervals it
	// no longer says what the kernel holds (boxes may have started since).
	interval := snap.Interval
	if interval <= 0 {
		interval = defaultNetPolicyReconcileInterval
	}
	if now.Sub(snap.ReconciledAt) > staleAfterPasses*interval {
		st.State = pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_STALE
		return st
	}
	a := snap.Tenant
	if snap.Found {
		st.BoxesLoaded = uint32(max(a.BoxesLoaded, 0))       // #nosec G115 -- clamped, box counts are small
		st.BoxesNotLoaded = uint32(max(a.BoxesNotLoaded, 0)) // #nosec G115 -- clamped, box counts are small
	}
	if !snap.Found || a.BoxesLoaded == 0 {
		st.State = pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_NOT_LOADED
		// No box is loaded, but the tenant's allow-list entries are written
		// regardless (#3051), so a failed write still matters.
		if snap.Found && a.EgressIncomplete {
			st.UncoveredPaths = append(st.UncoveredPaths, pb.NetworkPolicyUncoveredPath_NETWORK_POLICY_UNCOVERED_PATH_EGRESS_ALLOWLIST_INCOMPLETE)
		}
		return st
	}
	// LOADED only when every running box is covered; otherwise the modes are
	// true for the loaded boxes alone.
	st.State = pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_LOADED
	if a.BoxesNotLoaded > 0 {
		st.State = pb.NetworkPolicyAppliedState_NETWORK_POLICY_APPLIED_STATE_PARTIALLY_LOADED
	}
	st.PolicySource = a.Source
	st.EffectiveMode = bpfModeToProto(a.Mode)
	// A 0 egress byte is "follow mode" in the program (#2970), so the kernel
	// applies the mode byte to the allow-list too.
	egress := a.EgressMode
	if egress == 0 {
		egress = a.Mode
	}
	st.EffectiveEgressMode = bpfModeToProto(egress)
	if a.HasDomains {
		st.UncoveredPaths = append(st.UncoveredPaths, pb.NetworkPolicyUncoveredPath_NETWORK_POLICY_UNCOVERED_PATH_DOMAIN_REFRESH_LAG)
	}
	if a.EgressIncomplete {
		st.UncoveredPaths = append(st.UncoveredPaths, pb.NetworkPolicyUncoveredPath_NETWORK_POLICY_UNCOVERED_PATH_EGRESS_ALLOWLIST_INCOMPLETE)
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
