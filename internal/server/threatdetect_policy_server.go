package server

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/threatdetect"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Get/SetProcessPolicy and ReleaseProcessAction (#2636) — the process
// guardrail's policy and release RPCs on ThreatDetectionServer. Kept in their
// own file: the status/findings/bad-destination handlers in
// threatdetect_server.go are shared with sibling stories.

// SetProcessPolicyStore wires the policy store. Independent of whether the
// sentry is armed — an operator sets the policy before flipping
// CONTAINARIUM_THREAT_SENTRY on, the way the bad-destination list works.
// nil is valid (no store); the two policy handlers report Unavailable.
func (s *ThreatDetectionServer) SetProcessPolicyStore(store *threatdetect.ProcessPolicyStore) {
	s.policies = store
}

// SetMiningThresholdsConfig wires the mining-behavior thresholds the rule
// reads, so `process-policy set` can tune them (ProcessPolicy.mining_behavior).
func (s *ThreatDetectionServer) SetMiningThresholdsConfig(c *threatdetect.MiningThresholdsConfig) {
	s.miningCfg = c
}

// withEffectiveThresholds returns a copy of p carrying the mining-behavior
// thresholds the rule is actually using (stored values over built-in
// defaults), so a read never shows them empty even when nothing was set.
func (s *ThreatDetectionServer) withEffectiveThresholds(p *pb.ProcessPolicy) *pb.ProcessPolicy {
	if s.miningCfg == nil {
		return p
	}
	out := &pb.ProcessPolicy{}
	if p != nil {
		out = proto.Clone(p).(*pb.ProcessPolicy)
	}
	t := s.miningCfg.Effective()
	out.MiningBehavior = &pb.MiningBehaviorThresholds{
		MinCores:           t.MinCores,
		MinFractionOfLimit: t.MinFractionOfLimit,
		Window:             durationpb.New(t.Window),
		FlowMinAge:         durationpb.New(t.FlowMinAge),
		StratumPorts:       t.StratumPorts,
	}
	return out
}

// SetProcessResponder wires the responder ReleaseProcessAction calls. nil is
// valid (sentry off or unavailable); the handler reports Unavailable.
func (s *ThreatDetectionServer) SetProcessResponder(r *ProcessResponder) {
	s.responder = r
}

// GetProcessPolicy returns the policy stored at one level and the effective
// policy there.
func (s *ThreatDetectionServer) GetProcessPolicy(ctx context.Context, req *pb.GetProcessPolicyRequest) (*pb.GetProcessPolicyResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeSecurityRead); err != nil {
		return nil, err
	}
	if s.policies == nil {
		return nil, status.Errorf(codes.Unavailable, "process policy store not available")
	}
	container := req.GetContainer()
	var stored *pb.ProcessPolicy
	var err error
	if container == "" {
		stored, err = s.policies.Default(ctx)
	} else {
		stored, err = s.policies.Override(ctx, container)
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read process policy: %v", err)
	}
	effective, err := s.policies.Effective(ctx, container)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "resolve process policy: %v", err)
	}
	if container == "" && s.miningCfg != nil && stored != nil {
		stored.MiningBehavior = s.miningCfg.Get()
	}
	effective = s.withEffectiveThresholds(effective)
	return &pb.GetProcessPolicyResponse{
		Policy:     stored,
		IsOverride: container != "" && stored != nil,
		Effective:  effective,
	}, nil
}

// SetProcessPolicy writes the backend default or one container's override.
// Both gates, like the bad-destination mutations: the policy decides what
// happens to a tenant's box, so a scoped non-admin token may not set it.
func (s *ThreatDetectionServer) SetProcessPolicy(ctx context.Context, req *pb.SetProcessPolicyRequest) (*pb.SetProcessPolicyResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeSecurityWrite); err != nil {
		return nil, err
	}
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	if s.policies == nil {
		return nil, status.Errorf(codes.Unavailable, "process policy store not available")
	}
	container := req.GetContainer()
	switch {
	case req.GetClearOverride():
		if container == "" {
			return nil, status.Errorf(codes.InvalidArgument, "clear_override requires container")
		}
		if err := s.policies.ClearOverride(ctx, container); err != nil {
			return nil, status.Errorf(codes.Internal, "clear process policy override: %v", err)
		}
	default:
		if err := threatdetect.ValidateProcessPolicy(req.GetPolicy()); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		if mb := req.GetPolicy().GetMiningBehavior(); mb != nil {
			if container != "" {
				return nil, status.Errorf(codes.InvalidArgument, "mining_behavior thresholds are backend-wide; omit container")
			}
			if s.miningCfg == nil {
				return nil, status.Errorf(codes.Unavailable, "mining-behavior thresholds not available")
			}
			if err := s.miningCfg.Set(ctx, mb); err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "%v", err)
			}
		}
		// Thresholds live under their own config key; keep the stored
		// policy free of a second copy.
		pol := proto.Clone(req.GetPolicy()).(*pb.ProcessPolicy)
		pol.MiningBehavior = nil
		var err error
		if container == "" {
			err = s.policies.SetDefault(ctx, pol)
		} else {
			err = s.policies.SetOverride(ctx, container, pol)
		}
		if err != nil {
			return nil, status.Errorf(codes.Internal, "set process policy: %v", err)
		}
	}
	effective, err := s.policies.Effective(ctx, container)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "resolve process policy: %v", err)
	}
	return &pb.SetProcessPolicyResponse{Effective: s.withEffectiveThresholds(effective)}, nil
}

// ReleaseProcessAction undoes the open action on a container. Admin-only
// like SetProcessPolicy: it changes a tenant's box.
func (s *ThreatDetectionServer) ReleaseProcessAction(ctx context.Context, req *pb.ReleaseProcessActionRequest) (*pb.ReleaseProcessActionResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeSecurityWrite); err != nil {
		return nil, err
	}
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	if s.responder == nil {
		return nil, status.Errorf(codes.Unavailable, "process responder not available (sentry off, unavailable, or no persistence)")
	}
	if req.GetContainer() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "container is required")
	}
	f, err := s.responder.Release(ctx, req.GetContainer())
	if err != nil {
		if errors.Is(err, threatdetect.ErrNoOpenAction) {
			return nil, status.Errorf(codes.NotFound, "%v", err)
		}
		return nil, status.Errorf(codes.Internal, "release process action: %v", err)
	}
	resp := &pb.ReleaseProcessActionResponse{}
	if f != nil {
		resp.Finding = f.ToProto()
	}
	return resp, nil
}
