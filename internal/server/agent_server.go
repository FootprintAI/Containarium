package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/netpolicy"
	"github.com/footprintai/containarium/pkg/core/skills"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// agentBoxPrefix is the box/tenant name prefix RunAgentSkill assigns to a
// skill's box (agent-<skill-id>). The minted in-box JWT carries this as its
// subject, so a call originating from an agent box authenticates as
// agent-<skill-id> — which is how SendAgentTask recovers the real caller.
const agentBoxPrefix = "agent-"

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
	catalog   *skills.Manager
	recipes   *RecipeServer        // box provisioning (reuses CreateContainer/exec/expose)
	tokens    *auth.TokenManager   // mints the skill's scoped in-box token
	netpolicy *NetworkPolicyServer // compiles allowed_peers into a per-box egress policy (Phase 2)
	audit     *audit.Store         // records A2A hops under a trace id (Phase 2); set once the pool is ready
}

// SetAuditStore wires the audit store once the Postgres pool exists (it isn't
// available at construction). A2A hop logging no-ops until then.
func (s *AgentSkillServer) SetAuditStore(store *audit.Store) { s.audit = store }

// NewAgentSkillServer wires the agent-skill service to the recipe server (for
// box provisioning), the token manager (for minting scoped in-box tokens), and
// the network policy server (to compile allowed_peers into a per-box egress
// policy at launch). netpolicy may be nil — policy compilation then no-ops.
func NewAgentSkillServer(recipes *RecipeServer, tokens *auth.TokenManager, netpolicy *NetworkPolicyServer) *AgentSkillServer {
	return &AgentSkillServer{
		catalog:   skills.GetDefault(),
		recipes:   recipes,
		tokens:    tokens,
		netpolicy: netpolicy,
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

	// 3. Seed the prompt/token/input/card into the box. The agent card is
	//    seeded so the box's A2A server (Phase 1, agent-runtime image's job)
	//    can serve it for peer discovery.
	cardJSON := ""
	if skill.AgentCard != nil {
		if b, err := protojson.Marshal(skill.AgentCard); err == nil {
			cardJSON = string(b)
		}
	}
	containerName := name + "-container"
	if err := s.recipes.containers.manager.Exec(containerName,
		[]string{"bash", "-c", buildAgentSeedScript(skill.SystemPrompt, token, req.InputJson, cardJSON)}); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to seed agent box %s: %v", containerName, err)
	}

	// 4. Compile the skill's allowed_peers into a per-box egress network policy
	//    (Phase 2). Best-effort + LOG_ONLY: a failure here must not fail the
	//    run, and observe-only never drops traffic. Enforcement (drop) requires
	//    the env-gated eBPF enforcer AND flipping to ENFORCE — see #574.
	s.applyAllowedPeersPolicy(ctx, name, skill)

	// artifact_json intentionally empty in Phase 0 (in-box loop seam).
	return &pb.RunAgentSkillResponse{Container: dep.Container, ArtifactJson: ""}, nil
}

// applyAllowedPeersPolicy compiles a skill's allowed_peers into a per-box
// egress NetworkPolicy and stores it (LOG_ONLY). The box's tenant is its name
// (the agent-<skill-id> / <tenant>-container convention the enforcer resolves).
// Best-effort: logs and returns on any error so a policy hiccup never blocks a
// run. No-op when no policy server is wired or the skill declares no peers.
//
// Phase 2 seam: the policy is observe-only here. Dropping non-allowed egress
// in-kernel needs the env-gated eBPF enforcer (CONTAINARIUM_NETWORK_POLICY_*)
// on a Linux backend and a flip to ENFORCE. Also, before ENFORCE is safe the
// allowlist must be broadened to the platform egress the agent legitimately
// needs (daemon API, DNS) — a peer-only allowlist would otherwise strand the
// agent. Tracked in #574.
func (s *AgentSkillServer) applyAllowedPeersPolicy(ctx context.Context, tenant string, skill *pb.AgentSkill) {
	if s.netpolicy == nil || len(skill.AllowedPeers) == 0 {
		return
	}
	extraCIDRs, enforce := agentNetworkPolicyConfig()
	policy := compileAllowedPeersPolicy(tenant, skill.AllowedPeers, s.resolvePeerIP, extraCIDRs, enforce)
	if len(policy.EgressCidrs) == 0 {
		// Nothing to allow (no peers running, no platform CIDRs). Skip rather
		// than install an empty allowlist (which, under ENFORCE, denies all).
		return
	}
	// Compile (validate + normalize) before storing — same path the
	// SetNetworkPolicy RPC uses — so a bad operator-supplied egress CIDR is
	// caught here instead of silently dropped by the enforcer's reconcile.
	compiled, err := netpolicy.Compile(policy)
	if err != nil {
		log.Printf("[agent-skill] invalid network policy for %q: %v", tenant, err)
		return
	}
	if err := s.netpolicy.Store().Set(ctx, compiled.ToProto()); err != nil {
		log.Printf("[agent-skill] could not set network policy for %q: %v", tenant, err)
	}
}

// agentNetworkPolicyConfig reads the operator opt-ins for arming enforcement:
//   - CONTAINARIUM_AGENT_NETWORK_POLICY_ENFORCE=1 → compile the policy in
//     ENFORCE mode (drop), instead of the default LOG_ONLY (observe).
//   - CONTAINARIUM_AGENT_EGRESS_CIDRS=cidr,cidr → platform egress the agent
//     legitimately needs (daemon API, DNS resolver) added to every agent box's
//     allowlist, so ENFORCE doesn't strand the agent.
//
// Both default off/empty, so the out-of-the-box behaviour stays observe-only.
// ENFORCE additionally requires the daemon-wide eBPF enforcer to be armed
// (CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT + CONTAINARIUM_NETWORK_POLICY_ENFORCE).
func agentNetworkPolicyConfig() (extraCIDRs []string, enforce bool) {
	enforce = os.Getenv("CONTAINARIUM_AGENT_NETWORK_POLICY_ENFORCE") == "1"
	for _, c := range strings.Split(os.Getenv("CONTAINARIUM_AGENT_EGRESS_CIDRS"), ",") {
		if c = strings.TrimSpace(c); c != "" {
			extraCIDRs = append(extraCIDRs, c)
		}
	}
	return extraCIDRs, enforce
}

// callerSkillID recovers the skill id of the agent making an A2A call. The
// authenticated token subject wins (an agent box's JWT subject is
// agent-<skill-id>); otherwise it falls back to the caller-asserted value.
func (s *AgentSkillServer) callerSkillID(ctx context.Context, asserted string) string {
	if subj, ok := auth.UsernameFromContext(ctx); ok && strings.HasPrefix(subj, agentBoxPrefix) {
		return strings.TrimPrefix(subj, agentBoxPrefix)
	}
	return asserted
}

// peerAllowed reports whether the calling skill may send to toPeer per its
// declared allowed_peers. An unknown/empty caller (admin or operator direct
// call, not an agent box) is allowed — for box-originated traffic the eBPF
// egress policy is the hard boundary; this is the API-boundary courtesy check.
func (s *AgentSkillServer) peerAllowed(fromSkillID, toPeerID string) bool {
	if fromSkillID == "" {
		return true
	}
	skill, err := s.catalog.Get(fromSkillID)
	if err != nil {
		return true // unknown caller skill — not ours to gate here
	}
	for _, p := range skill.AllowedPeers {
		if p == toPeerID {
			return true
		}
	}
	return false
}

// resolvePeerIP returns a running peer box's IPv4 address, if any. Used to turn
// an allowed_peer skill id into an egress /32 at launch.
func (s *AgentSkillServer) resolvePeerIP(peerID string) (string, bool) {
	info, err := s.recipes.containers.manager.Get("agent-" + peerID)
	if err != nil || info == nil || info.IPAddress == "" {
		return "", false
	}
	return info.IPAddress, true
}

// compileAllowedPeersPolicy builds a per-box egress NetworkPolicy from a skill's
// allowed_peers: each currently-running peer's box IP becomes an egress /32.
// Pure (resolution is injected) so it is unit-testable without a daemon. The
// policy is LOG_ONLY — observe, never drop — until Phase 2 enforcement is armed.
func compileAllowedPeersPolicy(tenant string, allowedPeers []string, resolve func(peerID string) (string, bool), extraCIDRs []string, enforce bool) *pb.NetworkPolicy {
	var cidrs []string
	for _, peer := range allowedPeers {
		if ip, ok := resolve(peer); ok {
			cidrs = append(cidrs, ip+"/32")
		}
	}
	// Platform egress the agent legitimately needs (daemon API, DNS) so an
	// armed ENFORCE policy doesn't strand the agent.
	cidrs = append(cidrs, extraCIDRs...)

	mode := pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY
	if enforce {
		mode = pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE
	}
	return &pb.NetworkPolicy{
		Tenant:           tenant,
		AllowIntraTenant: false,
		EgressCidrs:      cidrs,
		Mode:             mode,
		AllowMetadata:    false,
		Source:           "agent-skill",
	}
}

// SendAgentTask delegates a task to a running peer agent over A2A and returns
// the peer's artifact (Phase 1 transport). Gated on agents:call.
//
// Phase 2 will enforce that to_peer_id is in the from-skill's allowed_peers and
// that network policy permits the hop (the eBPF "trust fabric"); in Phase 1 the
// send is best-effort. The peer's in-box A2A server (which receives the task)
// is the agent-runtime image's job — until it lands, a call to a real box
// reaches no listener and returns Unavailable. The transport itself is wired
// and unit-tested (see a2a_client_test.go).
func (s *AgentSkillServer) SendAgentTask(ctx context.Context, req *pb.SendAgentTaskRequest) (*pb.SendAgentTaskResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeAgentsCall); err != nil {
		return nil, err
	}
	if req.ToPeerId == "" {
		return nil, status.Error(codes.InvalidArgument, "to_peer_id is required")
	}

	// Enforce allowed_peers at the API boundary (Phase 2). The real caller is
	// the authenticated token subject when it's an agent box (agent-<skill-id>);
	// fall back to the caller-asserted from_skill_id otherwise. This is
	// defense-in-depth + fail-fast UX — the hard boundary for raw box-originated
	// traffic is the eBPF egress policy compiled from allowed_peers.
	caller := s.callerSkillID(ctx, req.FromSkillId)

	// Correlation id for the whole delegation: honor a caller-threaded id
	// (a crew, Phase 3), else generate one. Every audit record for this hop
	// shares it.
	trace := req.TraceId
	if trace == "" {
		trace = genTraceID()
	}

	if !s.peerAllowed(caller, req.ToPeerId) {
		s.auditHop(ctx, trace, caller, req.ToPeerId, "denied", "not in allowed_peers")
		return nil, status.Errorf(codes.PermissionDenied,
			"skill %q is not permitted to call peer %q (not in its allowed_peers)", caller, req.ToPeerId)
	}

	baseURL, _, err := s.resolvePeerA2A(req.ToPeerId)
	if err != nil {
		s.auditHop(ctx, trace, caller, req.ToPeerId, "unreachable", err.Error())
		return nil, err
	}

	task := &pb.AgentTask{
		Id:        "task-" + caller + "-" + req.ToPeerId,
		InputJson: req.InputJson,
	}
	art, err := sendA2ATask(ctx, baseURL, task)
	if err != nil {
		s.auditHop(ctx, trace, caller, req.ToPeerId, "failed", err.Error())
		return nil, status.Errorf(codes.Unavailable, "deliver task to peer %q: %v", req.ToPeerId, err)
	}
	s.auditHop(ctx, trace, caller, req.ToPeerId, "delivered", "")
	return &pb.SendAgentTaskResponse{Artifact: art, TraceId: trace}, nil
}

// genTraceID returns a random 128-bit hex correlation id for an A2A run.
func genTraceID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// rand failure is effectively impossible; fall back to a time nonce so
		// the trace is still non-empty rather than colliding on "".
		return fmt.Sprintf("t%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// auditHop records one A2A delegation under the shared trace id. Best-effort:
// audit must never fail the call. No-op until the audit store is wired.
func (s *AgentSkillServer) auditHop(ctx context.Context, trace, from, to, outcome, detail string) {
	if s.audit == nil {
		return
	}
	username := from
	if username == "" {
		username = "_unknown"
	}
	payload, _ := json.Marshal(map[string]string{
		"trace_id": trace,
		"from":     from,
		"to":       to,
		"outcome":  outcome,
		"detail":   detail,
	})
	if err := s.audit.Log(ctx, &audit.AuditEntry{
		Username:     username,
		Action:       "agent.a2a_call",
		ResourceType: "agent_skill",
		ResourceID:   to,
		Detail:       string(payload),
	}); err != nil {
		log.Printf("[agent-skill] audit A2A hop %s->%s: %v", from, to, err)
	}
}

// resolvePeerA2A finds a running peer's in-box A2A base URL and its agent card.
// The peer is addressed by skill id; its box is named agent-<skill-id> (the
// deterministic name RunAgentSkill assigns). Returns FailedPrecondition when
// the peer is not running.
func (s *AgentSkillServer) resolvePeerA2A(peerID string) (string, *pb.AgentCard, error) {
	skill, err := s.catalog.Get(peerID)
	if err != nil {
		return "", nil, status.Error(codes.NotFound, err.Error())
	}
	name := "agent-" + peerID
	info, err := s.recipes.containers.manager.Get(name)
	if err != nil || info == nil || info.IPAddress == "" {
		return "", nil, status.Errorf(codes.FailedPrecondition,
			"peer %q is not running (no box %q with an IP); run it first with 'containarium agent run %s'",
			peerID, name+"-container", peerID)
	}
	baseURL := fmt.Sprintf("http://%s:%d", info.IPAddress, a2aPort)
	return baseURL, skill.AgentCard, nil
}

// buildAgentSeedScript writes the skill's system prompt, scoped token, task
// input, and agent card under agentSeedDir with restrictive permissions. The
// agent card lets the box's A2A server (Phase 1) serve it for peer discovery.
// Values are single-quote escaped (shellSingleQuote, from recipe_server.go) to
// prevent shell injection.
func buildAgentSeedScript(systemPrompt, token, inputJSON, cardJSON string) string {
	if inputJSON == "" {
		inputJSON = "{}"
	}
	if cardJSON == "" {
		cardJSON = "{}"
	}
	var b strings.Builder
	b.WriteString("set -euo pipefail\n")
	b.WriteString("umask 077\n")
	fmt.Fprintf(&b, "mkdir -p %s\n", agentSeedDir)
	fmt.Fprintf(&b, "printf '%%s' %s > %s/system_prompt.txt\n", shellSingleQuote(systemPrompt), agentSeedDir)
	fmt.Fprintf(&b, "printf '%%s' %s > %s/token\n", shellSingleQuote(token), agentSeedDir)
	fmt.Fprintf(&b, "printf '%%s' %s > %s/input.json\n", shellSingleQuote(inputJSON), agentSeedDir)
	fmt.Fprintf(&b, "printf '%%s' %s > %s/agent-card.json\n", shellSingleQuote(cardJSON), agentSeedDir)
	fmt.Fprintf(&b, "chmod 600 %s/token\n", agentSeedDir)
	return b.String()
}
