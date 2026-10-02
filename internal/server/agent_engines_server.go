package server

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/agentengine"
	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/modelgateway"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// ListAgentEngines reports, for each AgentEngine, whether a run naming it
// would be refused right now (#2223) — the exact same check
// provisionSkillBoxWith's refusal enforces, read-only. It never performs a
// live model call or inspects the box's runtime bundle: readiness is
// computed from state the daemon already holds (s.gateway's engines view),
// the same inputs agentengine.Resolve uses on the run path.
func (s *AgentSkillServer) ListAgentEngines(ctx context.Context, _ *pb.ListAgentEnginesRequest) (*pb.ListAgentEnginesResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeAgentsRead); err != nil {
		return nil, err
	}

	// Per-owner resolution matches MintGatewayToken (#2223 AC): a tenant sees
	// readiness for THEIR key owner; an admin with no owner scope sees the
	// global view (empty keyOwner — agentengine.Resolve/Statuses then checks
	// only GlobalProviders, never consulting the per-owner KeyResolver for an
	// owner nobody named). This mirrors ListGatewayModels's own "no box named"
	// branch, except admin additionally gets the global view rather than its
	// own UserKeyOwner — an admin account is not itself a billed owner.
	subject, roles, ok := auth.SubjectFromGRPCContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no authenticated subject")
	}
	var keyOwner string
	if !auth.HasRole(roles, auth.RoleAdmin) {
		keyOwner = modelgateway.UserKeyOwner(subject)
		if verr := modelgateway.ValidateKeyOwner(keyOwner); verr != nil {
			return nil, status.Errorf(codes.Internal, "the caller's own key owner is malformed: %v", verr)
		}
	}

	var gw *agentengine.Gateway
	if s.gateway != nil {
		gw = &s.gateway.engines
	}

	skillsList := s.catalog.List()
	skills := make([]agentengine.SkillEngine, 0, len(skillsList))
	for _, sk := range skillsList {
		skills = append(skills, agentengine.SkillEngine{ID: sk.GetId(), Engine: sk.GetEngine()})
	}

	return &pb.ListAgentEnginesResponse{
		Engines:  agentengine.Statuses(ctx, keyOwner, gw, skills),
		KeyOwner: keyOwner,
	}, nil
}
