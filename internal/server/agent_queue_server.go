package server

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// agentWorkerDaemonPort is the daemon's REST (grpc-gateway) port, where a
// worker box reaches the agent-tasks endpoints. The worker resolves the host
// (its default gateway) at launch and dials this port. Configurable later;
// hard-coded to the daemon's well-known HTTP port for the prototype.
const agentWorkerDaemonPort = 8080

// agent_queue_server.go — the gRPC surface of the pull-based run queue
// (prototype). Thin handlers over agentTaskQueue; the queue type holds the
// semantics and the tests. All three gate on agents:run — producing, leasing,
// and completing queued work are all "operate the agent runtime" actions.
// See docs/AGENT-MODEL-GATEWAY-DESIGN.md (pull-queue section).

// EnqueueAgentTask places a task on the queue for a skill. Validates the skill
// exists so a typo doesn't sit in the queue forever, never leasable.
func (s *AgentSkillServer) EnqueueAgentTask(ctx context.Context, req *pb.EnqueueAgentTaskRequest) (*pb.EnqueueAgentTaskResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeAgentsRun); err != nil {
		return nil, err
	}
	if req.SkillId == "" {
		return nil, status.Error(codes.InvalidArgument, "skill_id is required")
	}
	if _, err := s.catalog.Get(req.SkillId); err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	id := s.queue.enqueue(req.SkillId, req.InputJson)
	return &pb.EnqueueAgentTaskResponse{TaskId: id}, nil
}

// LeaseAgentTask hands the polling worker the next visible task (optionally
// filtered to one skill). has_task=false means "nothing right now" — a normal,
// non-error poll result the worker backs off on.
func (s *AgentSkillServer) LeaseAgentTask(ctx context.Context, req *pb.LeaseAgentTaskRequest) (*pb.LeaseAgentTaskResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeAgentsRun); err != nil {
		return nil, err
	}
	leased, ok := s.queue.lease(req.SkillId, time.Duration(req.LeaseSeconds)*time.Second)
	if !ok {
		return &pb.LeaseAgentTaskResponse{HasTask: false}, nil
	}
	return &pb.LeaseAgentTaskResponse{
		HasTask:    true,
		TaskId:     leased.ID,
		SkillId:    leased.SkillID,
		InputJson:  leased.InputJSON,
		LeaseToken: leased.LeaseToken,
	}, nil
}

// CompleteAgentTask records a leased task's outcome and removes it. A stale
// lease (the task already expired and was redelivered) returns accepted=false
// rather than an error — the worker simply drops its now-orphaned result.
func (s *AgentSkillServer) CompleteAgentTask(ctx context.Context, req *pb.CompleteAgentTaskRequest) (*pb.CompleteAgentTaskResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeAgentsRun); err != nil {
		return nil, err
	}
	if req.TaskId == "" || req.LeaseToken == "" {
		return nil, status.Error(codes.InvalidArgument, "task_id and lease_token are required")
	}
	ok := s.queue.complete(req.TaskId, req.LeaseToken, req.ArtifactJson, req.Error)
	return &pb.CompleteAgentTaskResponse{Accepted: ok}, nil
}

// StartAgentWorker provisions (or reuses) the skill's box and launches the
// in-box runtime in poll mode — the consumer side of the pull model. It mints a
// SEPARATE queue credential: a JWT scoped to agents:run (NOT the skill's
// allowed_scopes), because leasing/completing is a runtime action the skill's
// own scopes don't grant. The credential is seeded as env so the box can reach
// the daemon's agent-tasks endpoints; the worker resolves the daemon host from
// its default route at launch (see buildWorkerPollCommand).
//
// Best-effort launch, like serve mode: a box whose image doesn't ship
// agent-runtime yet still provisions + gets its credential; only the poll loop
// no-ops (logged). The token's 30m TTL means a long-lived worker needs refresh
// — deferred, the same open question as the gateway token (see the design note).
func (s *AgentSkillServer) StartAgentWorker(ctx context.Context, req *pb.StartAgentWorkerRequest) (*pb.StartAgentWorkerResponse, error) {
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

	// Provision/reuse the box (seeds the skill's persona + its own scoped token,
	// applies egress policy) — same path the push run uses, with no task input
	// since the worker pulls its inputs from the queue.
	containerName, container, err := s.provisionSkillBox(ctx, skill, req.BackendId, req.Pool, "")
	if err != nil {
		return nil, err
	}

	workerID := req.WorkerId
	if workerID == "" {
		workerID = strings.TrimSuffix(containerName, "-container")
	}

	// Mint the queue credential: agents:run only, so a compromised worker can
	// lease/complete but nothing else.
	queueToken, err := s.tokens.GenerateToken(workerID, []string{}, agentTokenTTL, auth.ScopeAgentsRun)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to mint worker queue credential: %v", err)
	}

	s.startPollMode(containerName, queueToken, workerID, skill.Id)

	return &pb.StartAgentWorkerResponse{Container: container, WorkerId: workerID}, nil
}

// startPollMode launches agent-runtime in poll mode as a background worker in
// the box. Best-effort (mirrors startServeMode): a failure (no runtime in the
// image) logs and the box is still provisioned + credentialed.
func (s *AgentSkillServer) startPollMode(containerName, queueToken, workerID, skillID string) {
	if s.recipes == nil || s.recipes.containers == nil || s.recipes.containers.manager == nil {
		return
	}
	cmd := buildWorkerPollCommand(queueToken, workerID, skillID)
	if _, stderr, err := s.recipes.containers.manager.ExecWithOutput(containerName,
		[]string{"bash", "-lc", cmd}); err != nil {
		log.Printf("[agent-worker] could not start poll mode on %s (image may not ship runtime): %v; stderr=%s",
			containerName, err, strings.TrimSpace(stderr))
	}
}

// buildWorkerPollCommand returns the bash command that launches agent-runtime
// in poll mode, detached, logging to a file. The daemon URL is resolved at
// runtime from the box's default gateway (the backend host) so the daemon never
// has to know the bridge address; the agents:run token authorizes the lease/
// complete calls. Token, worker id, and skill filter are single-quoted; the URL
// is intentionally unquoted so $GW expands.
func buildWorkerPollCommand(queueToken, workerID, skillID string) string {
	return fmt.Sprintf(
		`GW=$(ip route 2>/dev/null | awk '/default/{print $3; exit}'); `+
			`CONTAINARIUM_AGENT_MODE=poll `+
			`CONTAINARIUM_QUEUE_URL=http://${GW}:%d `+
			`CONTAINARIUM_QUEUE_TOKEN=%s `+
			`CONTAINARIUM_WORKER_ID=%s `+
			`CONTAINARIUM_QUEUE_SKILL=%s `+
			`AGENT_SEED_DIR=%s `+
			`setsid agent-runtime >/var/log/agent-runtime-poll.log 2>&1 &`,
		agentWorkerDaemonPort,
		shellSingleQuote(queueToken),
		shellSingleQuote(workerID),
		shellSingleQuote(skillID),
		agentSeedDir,
	)
}
