package server

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

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
