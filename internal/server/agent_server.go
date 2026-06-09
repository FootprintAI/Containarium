package server

import (
	"context"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/skills"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// agentTokenTTL bounds the lifetime of the JWT minted for a skill's in-box
// agent loop. Short by design: a skill run is a bounded task, not a session.
const agentTokenTTL = 30 * time.Minute

// agentSeedDir is where RunAgentSkill writes the skill's system prompt, scoped
// token, and task input inside the box. The in-box agent loop (the
// agent-runtime image's job — Phase 0 integration seam) reads from here.
const agentSeedDir = "/etc/containarium/agent"

// AgentSkillServer implements the gRPC AgentSkillService (Phase 0:
// agent-as-a-box). It is pure orchestration: RunAgentSkill resolves a skill
// from the catalog, provisions its box by reusing RecipeServer.deploy, mints a
// JWT scoped to exactly the skill's allowed_scopes, and seeds the box. The
// in-box agent loop that consumes the seed and produces an artifact is the
// agent-runtime image's responsibility and is intentionally out of scope for
// Phase 0 (artifact_json is returned empty until that lands).
type AgentSkillServer struct {
	pb.UnimplementedAgentSkillServiceServer
	catalog *skills.Manager
	recipes *RecipeServer      // box provisioning (reuses CreateContainer/exec/expose)
	tokens  *auth.TokenManager // mints the skill's scoped in-box token
}

// NewAgentSkillServer wires the agent-skill service to the recipe server (for
// box provisioning) and the token manager (for minting scoped in-box tokens).
func NewAgentSkillServer(recipes *RecipeServer, tokens *auth.TokenManager) *AgentSkillServer {
	return &AgentSkillServer{
		catalog: skills.GetDefault(),
		recipes: recipes,
		tokens:  tokens,
	}
}

// ListAgentSkills returns all built-in skills.
func (s *AgentSkillServer) ListAgentSkills(ctx context.Context, _ *pb.ListAgentSkillsRequest) (*pb.ListAgentSkillsResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeAgentsRead); err != nil {
		return nil, err
	}
	return &pb.ListAgentSkillsResponse{Skills: s.catalog.List()}, nil
}

// GetAgentSkill returns a single skill by ID.
func (s *AgentSkillServer) GetAgentSkill(ctx context.Context, req *pb.GetAgentSkillRequest) (*pb.GetAgentSkillResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeAgentsRead); err != nil {
		return nil, err
	}
	if req.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}
	skill, err := s.catalog.Get(req.Id)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	return &pb.GetAgentSkillResponse{Skill: skill}, nil
}

// RunAgentSkill provisions a skill's box, mints a token scoped to exactly the
// skill's allowed_scopes, seeds the prompt/token/input into the box, and
// returns the box. Gated on agents:run; the inner provisioning still enforces
// containers:write + tenant authz via CreateContainer.
//
// Phase 0 limitations (documented seams):
//   - The in-box agent loop is the agent-runtime image's job; artifact_json is
//     returned empty until it lands.
//   - The box name is derived deterministically from the skill id, so two
//     concurrent runs of the same skill collide. Per-run boxes / a warm pool
//     are a later concern (see docs/EPHEMERAL-SANDBOX-DESIGN.md).
//   - allowed_peers is inert until Phase 2 (eBPF enforcement).
func (s *AgentSkillServer) RunAgentSkill(ctx context.Context, req *pb.RunAgentSkillRequest) (*pb.RunAgentSkillResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeAgentsRun); err != nil {
		return nil, err
	}
	if req.SkillId == "" {
		return nil, status.Error(codes.InvalidArgument, "skill_id is required")
	}

	skill, err := s.catalog.Get(req.SkillId)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}

	// Phase 0 supports only the recipe_id box form (catalog skills). Inline
	// recipes are an API-only construct deferred to a later phase.
	recipeID := skill.GetRecipeId()
	if recipeID == "" {
		return nil, status.Error(codes.Unimplemented,
			"inline-recipe skills are not supported yet; use a skill that references a recipe_id")
	}

	// Deterministic box identity for the run (see limitations above).
	name := "agent-" + skill.Id
	if err := auth.AuthorizeTenant(ctx, name); err != nil {
		return nil, err
	}

	// 1. Provision the box by reusing the recipe deploy path.
	dep, err := s.recipes.deploy(ctx, &pb.DeployRecipeRequest{
		RecipeId:  recipeID,
		Name:      name,
		BackendId: req.BackendId,
		Pool:      req.Pool,
	})
	if err != nil {
		return nil, err // already a gRPC status from deploy/CreateContainer
	}

	// 2. Mint a JWT scoped to EXACTLY the skill's allowed_scopes. The catalog
	//    guarantees len(allowed_scopes) >= 1, so this is a bounded token, not
	//    the "no restriction" nil-claim case.
	token, err := s.tokens.GenerateToken(name, []string{}, agentTokenTTL, skill.AllowedScopes...)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to mint scoped agent token: %v", err)
	}

	// 3. Seed the prompt/token/input into the box for the in-box agent loop.
	containerName := name + "-container"
	if err := s.recipes.containers.manager.Exec(containerName,
		[]string{"bash", "-c", buildAgentSeedScript(skill.SystemPrompt, token, req.InputJson)}); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to seed agent box %s: %v", containerName, err)
	}

	// artifact_json intentionally empty in Phase 0 (in-box loop seam).
	return &pb.RunAgentSkillResponse{Container: dep.Container, ArtifactJson: ""}, nil
}

// buildAgentSeedScript writes the skill's system prompt, scoped token, and task
// input under agentSeedDir with restrictive permissions. Values are single-quote
// escaped (shellSingleQuote, from recipe_server.go) to prevent shell injection.
func buildAgentSeedScript(systemPrompt, token, inputJSON string) string {
	if inputJSON == "" {
		inputJSON = "{}"
	}
	var b strings.Builder
	b.WriteString("set -euo pipefail\n")
	b.WriteString("umask 077\n")
	fmt.Fprintf(&b, "mkdir -p %s\n", agentSeedDir)
	fmt.Fprintf(&b, "printf '%%s' %s > %s/system_prompt.txt\n", shellSingleQuote(systemPrompt), agentSeedDir)
	fmt.Fprintf(&b, "printf '%%s' %s > %s/token\n", shellSingleQuote(token), agentSeedDir)
	fmt.Fprintf(&b, "printf '%%s' %s > %s/input.json\n", shellSingleQuote(inputJSON), agentSeedDir)
	fmt.Fprintf(&b, "chmod 600 %s/token\n", agentSeedDir)
	return b.String()
}
