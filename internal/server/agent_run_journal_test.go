package server

import (
	"context"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/skills"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// #2095: the in-box runtime journals every run under
// /var/log/agent-runtime/runs/<run_id>/<skill_id>.jsonl. These tests pin how
// the daemon hands it those two ids: the exec prefix for run mode, the A2A
// task for serve mode.

func TestRunModeCommand_ExportsRunAndSkillID(t *testing.T) {
	gemini := &AgentSkillServer{gateway: &gatewayProvisioning{provider: "gemini"}}
	direct := &AgentSkillServer{}
	cases := []struct {
		name      string
		s         *AgentSkillServer
		seedDir   string
		runID     string
		skillID   string
		want      []string
		wantOrder []string
	}{
		{
			name: "direct mode", s: direct, seedDir: "/seed/run-1", runID: "run-1", skillID: "hello-agent",
			want: []string{
				"CONTAINARIUM_RUN_ID='run-1' ",
				"CONTAINARIUM_SKILL_ID='hello-agent' ",
				"AGENT_SEED_DIR=/seed/run-1 agent-runtime",
				sourceGatewayEnvPrefix("/seed/run-1"),
			},
		},
		{
			name: "gateway mode keeps the engine pin", s: gemini, seedDir: "/seed/r2", runID: "r2", skillID: "relay-agent",
			want: []string{
				"CONTAINARIUM_AGENT_ENGINE=gemini ",
				"CONTAINARIUM_RUN_ID='r2' ",
				"CONTAINARIUM_SKILL_ID='relay-agent' ",
			},
			// The gateway env is sourced first, so a gateway.env can never
			// shadow the run id the daemon exports for this exec.
			wantOrder: []string{"gateway.env", "CONTAINARIUM_RUN_ID=", "agent-runtime"},
		},
		{
			name: "ids are shell-quoted", s: direct, seedDir: "/seed/x", runID: "a.b_c-1", skillID: "it's",
			want: []string{"CONTAINARIUM_RUN_ID='a.b_c-1' ", `CONTAINARIUM_SKILL_ID='it'\''s' `},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.s.runModeCommand(tc.seedDir, tc.runID, tc.skillID)
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("runModeCommand = %q, want it to contain %q", got, w)
				}
			}
			if strings.Contains(got, "CONTAINARIUM_AGENT_MODE=serve") {
				t.Errorf("runModeCommand = %q, must not select serve mode", got)
			}
			last := -1
			for _, w := range tc.wantOrder {
				i := strings.Index(got, w)
				if i <= last {
					t.Errorf("runModeCommand = %q, want %q after the previous element", got, w)
				}
				last = i
			}
		})
	}
}

func TestServeModeCommand_ExportsSkillIDKeepsProcessLog(t *testing.T) {
	s := &AgentSkillServer{gateway: &gatewayProvisioning{provider: "anthropic"}}
	got := s.serveModeCommand("/seed/run-9", "hello-agent")
	for _, w := range []string{
		sourceGatewayEnvPrefix("/seed/run-9"),
		"CONTAINARIUM_AGENT_ENGINE=claude ",
		"CONTAINARIUM_SKILL_ID='hello-agent' ",
		"CONTAINARIUM_AGENT_MODE=serve AGENT_SEED_DIR=/seed/run-9",
		// The process log is unchanged (#2095): the journal is separate.
		" setsid agent-runtime >/var/log/agent-runtime.log 2>&1 &",
	} {
		if !strings.Contains(got, w) {
			t.Errorf("serveModeCommand = %q, want it to contain %q", got, w)
		}
	}
	// Serve mode takes the run id from each A2A task, never from the launch:
	// one serve process outlives no run, but the id belongs to the task.
	if strings.Contains(got, "CONTAINARIUM_RUN_ID") {
		t.Errorf("serveModeCommand = %q, must not export CONTAINARIUM_RUN_ID", got)
	}
}

func TestAgentTaskFor_ForwardsRunID(t *testing.T) {
	for _, runID := range []string{"", "run-crew-1"} {
		task := agentTaskFor("relay-agent", "hello-agent", &pb.SendAgentTaskRequest{InputJson: `{"q":1}`, RunId: runID})
		if task.GetRunId() != runID {
			t.Errorf("run_id = %q, want %q", task.GetRunId(), runID)
		}
		if task.GetId() != "task-relay-agent-hello-agent" || task.GetInputJson() != `{"q":1}` {
			t.Errorf("task = %+v, want id/input unchanged", task)
		}
	}
}

// TestRunCrew_EveryHopCarriesTheCrewRunID: the crew run's id reaches every
// member as SendAgentTaskRequest.run_id, so each member's journal lands under
// the same run.
func TestRunCrew_EveryHopCarriesTheCrewRunID(t *testing.T) {
	h := newCrewLeaseHarness(t, "relay-agent", "hello-agent")
	const runID = "run-crew-journal"

	var got []string
	_, err := h.run(t, runID, func(_ context.Context, req *pb.SendAgentTaskRequest) (*pb.SendAgentTaskResponse, error) {
		got = append(got, req.GetRunId())
		return completed("out-of-" + req.ToPeerId), nil
	})
	if err != nil {
		t.Fatalf("runCrew: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("hops = %d, want 2", len(got))
	}
	for i, id := range got {
		if id != runID {
			t.Errorf("hop %d run_id = %q, want %q", i, id, runID)
		}
	}
}

// TestSendAgentTask_ValidatesRunID: run_id becomes a path segment of the
// peer's journal, so a malformed one is rejected before any peer lookup, with
// the same shape rule RunAgentSkill/RunCrew apply. Empty stays allowed (the
// task is simply not journaled).
func TestSendAgentTask_ValidatesRunID(t *testing.T) {
	s := &AgentSkillServer{catalog: skills.GetDefault()}
	ctx := auth.ContextWithTestSubjectScopes(
		context.Background(), "agent-hello-agent", nil, []string{auth.ScopeAgentsCall})
	for _, bad := range []string{"..", ".", "../etc", "a/b", "has space", strings.Repeat("x", 129)} {
		_, err := s.SendAgentTask(ctx, &pb.SendAgentTaskRequest{ToPeerId: "other-peer", RunId: bad})
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("run_id %q: got %v, want InvalidArgument", bad, err)
		}
	}
	// A well-formed or empty run_id passes validation and reaches the
	// allowed_peers check (hello-agent is a leaf, so PermissionDenied).
	for _, ok := range []string{"", "run-crew-1"} {
		_, err := s.SendAgentTask(ctx, &pb.SendAgentTaskRequest{ToPeerId: "other-peer", RunId: ok})
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("run_id %q: got %v, want PermissionDenied (validation passed)", ok, err)
		}
	}
}
