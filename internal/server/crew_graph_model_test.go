package server

import (
	"context"
	"testing"

	"github.com/footprintai/containarium/pkg/core/crews"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func skillNode(id, skill string) *pb.TaskNode {
	return &pb.TaskNode{Id: id, Goal: "g", Assignee: &pb.TaskNode_SkillId{SkillId: skill}}
}

// A graph run's override scope is the skills its nodes use: skill nodes and the
// members of crew nodes, each once, unknown crews left to graph validation.
func TestGraphModelMembers(t *testing.T) {
	g := &pb.TaskGraph{Nodes: []*pb.TaskNode{
		skillNode("a", "hello-agent-claude"),
		skillNode("b", "hello-agent-claude"),
		{Id: "c", Goal: "g", Assignee: &pb.TaskNode_CrewId{CrewId: "two-engine-crew"}},
		{Id: "d", Goal: "g", Assignee: &pb.TaskNode_CrewId{CrewId: "no-such-crew"}},
	}}
	got := graphModelMembers(g, crews.GetDefault())
	seen := map[string]int{}
	for _, id := range got {
		seen[id]++
	}
	if seen["hello-agent-claude"] != 1 || seen["hello-agent-codex"] != 1 {
		t.Errorf("members = %v, want each skill of the graph listed once", got)
	}
}

func TestValidateModelOverrides_Graph(t *testing.T) {
	_, get := modelTestSkills()
	members := []string{"named-bare", "no-engine"}
	for _, tc := range []struct {
		name string
		req  *pb.RunCrewRequest
		want codes.Code
	}{
		{"a node skill with a valid id", &pb.RunCrewRequest{ModelOverrides: map[string]string{"named-bare": "m-1"}}, codes.OK},
		{"an invalid id", &pb.RunCrewRequest{ModelOverrides: map[string]string{"named-bare": "bad id"}}, codes.InvalidArgument},
		{"a skill no node uses", &pb.RunCrewRequest{ModelOverrides: map[string]string{"named-pinned": "m-1"}}, codes.InvalidArgument},
		{"a node with no named engine", &pb.RunCrewRequest{ModelOverrides: map[string]string{"no-engine": "m-1"}}, codes.FailedPrecondition},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateModelOverrides(members, tc.req, get); status.Code(err) != tc.want {
				t.Fatalf("code = %v (%v), want %v", status.Code(err), err, tc.want)
			}
		})
	}
}

// The single-skill node request carries the same optional model.
func TestSkillRunModel(t *testing.T) {
	_, get := modelTestSkills()
	named, _ := get("named-pinned")
	bare, _ := get("no-engine")
	none := pb.AgentEngine_AGENT_ENGINE_UNSPECIFIED

	if err := validateSkillRunModel(named, none, "m-1"); err != nil {
		t.Errorf("named engine: %v", err)
	}
	if err := validateSkillRunModel(bare, none, ""); err != nil {
		t.Errorf("absent model must pass: %v", err)
	}
	if code := status.Code(validateSkillRunModel(named, none, "x; y")); code != codes.InvalidArgument {
		t.Errorf("invalid id code = %v, want InvalidArgument", code)
	}
	if code := status.Code(validateSkillRunModel(bare, none, "m-1")); code != codes.FailedPrecondition {
		t.Errorf("no named engine code = %v, want FailedPrecondition", code)
	}
	if err := validateSkillRunModel(bare, pb.AgentEngine_AGENT_ENGINE_CODEX, "m-1"); err != nil {
		t.Errorf("engine named on the request must satisfy the rule: %v", err)
	}

	if got := withSkillModel(named, "m-1"); got.GetModel() != "m-1" || named.GetModel() != "pinned-model" {
		t.Errorf("override = %q, catalog skill = %q: want the copy overridden and the shared skill untouched", got.GetModel(), named.GetModel())
	}
	if withSkillModel(named, "") != named {
		t.Error("no model must return the skill itself")
	}
}

func modelGraph(skillIDs ...string) *pb.TaskGraph {
	g := &pb.TaskGraph{Goal: "g"}
	for i, id := range skillIDs {
		g.Nodes = append(g.Nodes, skillNode(string(rune('a'+i)), id))
	}
	return g
}

// A graph run with an override reports that model for the node and the default
// for the other, and hands the node's request the overrides.
func TestRunCrewGraph_ModelOverrides(t *testing.T) {
	newReq := func(ov map[string]string) *pb.RunCrewRequest {
		return &pb.RunCrewRequest{CrewId: "freeform-crew", Graph: modelGraph("hello-agent-claude", "hello-agent-codex"), ModelOverrides: ov}
	}

	t.Run("override reaches the node and is reported", func(t *testing.T) {
		var got map[string]string
		resp, err := NewCrewServer(nil).runCrewGraph(ctxAs("admin", true),
			newReq(map[string]string{"hello-agent-claude": "m-override"}), graphCrew(), "graph-model-ok",
			func(_ context.Context, node *pb.TaskNode, _, _ string, child *pb.RunCrewRequest) (string, error) {
				if node.GetSkillId() == "hello-agent-claude" {
					got = child.GetModelOverrides()
				}
				return "{}", nil
			})
		if err != nil {
			t.Fatal(err)
		}
		if got["hello-agent-claude"] != "m-override" {
			t.Errorf("node request overrides = %v", got)
		}
		if m := resp.Run.GetMemberModels()["hello-agent-claude"]; m != "m-override" {
			t.Errorf("member_models = %v, want the override for the node", resp.Run.GetMemberModels())
		}
		if m, ok := resp.Run.GetMemberModels()["hello-agent-codex"]; ok {
			t.Errorf("the node without an override or pin reported model %q", m)
		}
	})

	t.Run("absent override is unchanged", func(t *testing.T) {
		resp, err := NewCrewServer(nil).runCrewGraph(ctxAs("admin", true), newReq(nil), graphCrew(), "graph-model-none",
			func(context.Context, *pb.TaskNode, string, string, *pb.RunCrewRequest) (string, error) {
				return "{}", nil
			})
		if err != nil {
			t.Fatal(err)
		}
		if len(resp.Run.GetMemberModels()) != 0 {
			t.Errorf("member_models = %v, want none", resp.Run.GetMemberModels())
		}
	})
}

// RunCrew refuses a bad override before any node starts (no agent runtime is
// wired here, so a request that got past validation could not return the code).
func TestRunCrew_GraphModelOverrideRefusedUpFront(t *testing.T) {
	for _, tc := range []struct {
		name  string
		graph *pb.TaskGraph
		ov    map[string]string
		want  codes.Code
	}{
		{"invalid id", modelGraph("hello-agent-claude"), map[string]string{"hello-agent-claude": "bad id"}, codes.InvalidArgument},
		{"skill no node uses", modelGraph("hello-agent-claude"), map[string]string{"hello-agent-codex": "m-1"}, codes.InvalidArgument},
		{"node with no named engine", modelGraph("code-review"), map[string]string{"code-review": "m-1"}, codes.FailedPrecondition},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewCrewServer(nil).RunCrew(ctxAs("admin", true),
				&pb.RunCrewRequest{CrewId: "freeform-crew", Graph: tc.graph, ModelOverrides: tc.ov})
			if status.Code(err) != tc.want {
				t.Fatalf("code = %v (%v), want %v", status.Code(err), err, tc.want)
			}
		})
	}
}
