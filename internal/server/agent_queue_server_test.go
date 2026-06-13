package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/skills"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// runScopedCtx returns a context carrying an agents:run credential, the scope a
// worker's minted queue token grants.
func runScopedCtx() context.Context {
	return auth.ContextWithTestSubjectScopes(
		context.Background(), "agent-hello-agent", nil, []string{auth.ScopeAgentsRun})
}

func newQueueServer() *AgentSkillServer {
	return &AgentSkillServer{catalog: skills.GetDefault(), queue: newAgentTaskQueue()}
}

// TestQueueRPC_EndToEndLoop drives the full producer→worker loop through the
// real RPC handlers with a real agents:run credential context — the same path
// a poll-mode worker exercises, minus the HTTP transport. This is the
// end-to-end proof that the minted credential authorizes the lease/complete
// cycle and the queue threads a task from enqueue to completion.
func TestQueueRPC_EndToEndLoop(t *testing.T) {
	s := newQueueServer()
	ctx := runScopedCtx()

	// Producer enqueues.
	enq, err := s.EnqueueAgentTask(ctx, &pb.EnqueueAgentTaskRequest{
		SkillId:   "hello-agent",
		InputJson: `{"q":"hi"}`,
	})
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if enq.TaskId == "" {
		t.Fatal("enqueue returned empty task id")
	}

	// Worker leases.
	lease, err := s.LeaseAgentTask(ctx, &pb.LeaseAgentTaskRequest{
		WorkerId: "worker-1", SkillId: "hello-agent", LeaseSeconds: 60,
	})
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	if !lease.HasTask || lease.TaskId != enq.TaskId || lease.InputJson != `{"q":"hi"}` || lease.LeaseToken == "" {
		t.Fatalf("lease returned wrong task: %+v", lease)
	}

	// Worker completes.
	done, err := s.CompleteAgentTask(ctx, &pb.CompleteAgentTaskRequest{
		TaskId: lease.TaskId, LeaseToken: lease.LeaseToken, ArtifactJson: `{"ok":true}`,
	})
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if !done.Accepted {
		t.Fatal("complete should be accepted with the current lease token")
	}

	// Queue is now empty.
	empty, err := s.LeaseAgentTask(ctx, &pb.LeaseAgentTaskRequest{WorkerId: "worker-1"})
	if err != nil {
		t.Fatalf("lease (empty): %v", err)
	}
	if empty.HasTask {
		t.Fatal("queue should be empty after completion")
	}
}

// TestQueueRPC_StaleCompleteRejected proves the cross-RPC stale-lease guard: a
// worker whose lease expired and was redelivered cannot clobber the retry.
func TestQueueRPC_StaleCompleteRejected(t *testing.T) {
	s := newQueueServer()
	ctx := runScopedCtx()
	base := time.Unix(1_700_000_000, 0).UTC()
	clock := base
	s.queue.now = func() time.Time { return clock }

	_, _ = s.EnqueueAgentTask(ctx, &pb.EnqueueAgentTaskRequest{SkillId: "hello-agent"})
	first, _ := s.LeaseAgentTask(ctx, &pb.LeaseAgentTaskRequest{LeaseSeconds: 1})

	// Force redelivery by expiring the lease, then re-lease (new token).
	clock = base.Add(2 * time.Second)
	second, _ := s.LeaseAgentTask(ctx, &pb.LeaseAgentTaskRequest{LeaseSeconds: 60})
	if second.LeaseToken == first.LeaseToken {
		t.Fatal("redelivery should mint a new token")
	}

	stale, _ := s.CompleteAgentTask(ctx, &pb.CompleteAgentTaskRequest{
		TaskId: first.TaskId, LeaseToken: first.LeaseToken, ArtifactJson: "late",
	})
	if stale.Accepted {
		t.Error("stale-token completion must be rejected at the RPC layer")
	}
}

// TestQueueRPC_RequireRunScope confirms every queue op (and the worker launcher)
// gates on agents:run — a token without it is denied.
func TestQueueRPC_RequireRunScope(t *testing.T) {
	s := newQueueServer()
	noScope := auth.ContextWithTestSubjectScopes(
		context.Background(), "nobody", nil, []string{auth.ScopeAgentsRead})

	if _, err := s.EnqueueAgentTask(noScope, &pb.EnqueueAgentTaskRequest{SkillId: "hello-agent"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("enqueue without agents:run: got %v, want PermissionDenied", err)
	}
	if _, err := s.LeaseAgentTask(noScope, &pb.LeaseAgentTaskRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("lease without agents:run: got %v, want PermissionDenied", err)
	}
	if _, err := s.CompleteAgentTask(noScope, &pb.CompleteAgentTaskRequest{TaskId: "t", LeaseToken: "x"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("complete without agents:run: got %v, want PermissionDenied", err)
	}
	if _, err := s.StartAgentWorker(noScope, &pb.StartAgentWorkerRequest{SkillId: "hello-agent"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("start-worker without agents:run: got %v, want PermissionDenied", err)
	}
}

func TestBuildWorkerPollCommand(t *testing.T) {
	cmd := buildWorkerPollCommand("tok.tok.tok", "worker-7", "hello-agent")

	for _, want := range []string{
		"CONTAINARIUM_AGENT_MODE=poll",
		"ip route", // resolves the daemon host from the default gateway
		"CONTAINARIUM_QUEUE_URL=http://${GW}:8080",
		"CONTAINARIUM_QUEUE_TOKEN='tok.tok.tok'",
		"CONTAINARIUM_WORKER_ID='worker-7'",
		"CONTAINARIUM_QUEUE_SKILL='hello-agent'",
		"AGENT_SEED_DIR=" + agentSeedDir,
		"setsid agent-runtime",
		"&", // detached
	} {
		if !strings.Contains(cmd, want) {
			t.Errorf("poll command missing %q\n---\n%s", want, cmd)
		}
	}

	// The URL must stay UNQUOTED so $GW expands; the token must be quoted.
	if strings.Contains(cmd, `'http://${GW}`) {
		t.Error("queue URL must not be single-quoted (breaks $GW expansion)")
	}
}
