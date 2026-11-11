package server

import (
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/pkg/core/skills"
)

// The request a graph skill node is started with carries that skill's model
// override, its engine override, and the parent's placement and git fields.
func TestGraphSkillNodeRequest_CarriesModelAndEngine(t *testing.T) {
	parent := &pb.RunCrewRequest{
		BackendId: "b", Pool: "p", GitSource: "src", GitRef: "ref", GitCredential: "cred",
		EngineOverrides: map[string]pb.AgentEngine{"s1": pb.AgentEngine_AGENT_ENGINE_CODEX},
		ModelOverrides:  map[string]string{"s1": "m-1", "other": "m-2"},
	}
	got := graphSkillNodeRequest(parent, "s1", "run-1", `{"x":1}`)
	if got.GetModel() != "m-1" {
		t.Errorf("model = %q, want the node skill's override", got.GetModel())
	}
	if got.GetEngine() != pb.AgentEngine_AGENT_ENGINE_CODEX {
		t.Errorf("engine = %v, want the skill's engine override", got.GetEngine())
	}
	if got.GetSkillId() != "s1" || got.GetRunId() != "run-1" || got.GetInputJson() != `{"x":1}` ||
		got.GetBackendId() != "b" || got.GetPool() != "p" || got.GetGitSource() != "src" ||
		got.GetGitRef() != "ref" || got.GetGitCredential() != "cred" {
		t.Errorf("request = %v", got)
	}
	if none := graphSkillNodeRequest(parent, "unlisted", "r", ""); none.GetModel() != "" {
		t.Errorf("a skill with no override got model %q", none.GetModel())
	}
}

// A crew node's child request keeps the overrides (runCrew applies them to the
// members) and drops the graph fields, and the parent request is not mutated.
func TestGraphCrewNodeRequest_KeepsOverridesDropsGraph(t *testing.T) {
	parent := &pb.RunCrewRequest{
		CrewId: "outer", Graph: &pb.TaskGraph{Goal: "g"}, Concurrency: 3,
		ModelOverrides: map[string]string{"s1": "m-1"},
	}
	got := graphCrewNodeRequest(parent, &pb.Crew{Id: "inner"}, "run-2", "in")
	if got.GetModelOverrides()["s1"] != "m-1" {
		t.Errorf("model_overrides = %v, want the parent's carried to the crew node", got.GetModelOverrides())
	}
	if got.GetGraph() != nil || got.GetConcurrency() != 0 {
		t.Errorf("graph fields survived: %v", got)
	}
	if got.GetCrewId() != "inner" || got.GetRunId() != "run-2" || got.GetInputJson() != "in" {
		t.Errorf("request = %v", got)
	}
	if parent.GetGraph() == nil || parent.GetCrewId() != "outer" {
		t.Error("the parent request was mutated")
	}
}

// applyRunModel is what beginSkillRunWith provisions: the overridden copy, with
// the shared catalog skill untouched.
func TestApplyRunModel_ProvisionsTheOverriddenSkill(t *testing.T) {
	catalog := skills.GetDefault()
	shared, err := catalog.Get("hello-agent-claude")
	if err != nil {
		t.Fatal(err)
	}
	before := shared.GetModel()
	got, err := applyRunModel(shared, &pb.RunAgentSkillRequest{SkillId: shared.GetId(), Model: "m-run"})
	if err != nil {
		t.Fatal(err)
	}
	if got.GetModel() != "m-run" {
		t.Errorf("provisioned model = %q, want the request's", got.GetModel())
	}
	if shared.GetModel() != before {
		t.Errorf("catalog skill mutated: %q -> %q", before, shared.GetModel())
	}
}

// The public single-skill request refuses a bad model up front, through
// RunAgentSkill itself; no runtime is wired, so only validation can return these.
func TestRunAgentSkill_ModelRefusedUpFront(t *testing.T) {
	s := &AgentSkillServer{catalog: skills.GetDefault()}
	for _, tc := range []struct {
		name  string
		skill string
		model string
		want  codes.Code
	}{
		{"malformed id", "hello-agent-claude", "bad id", codes.InvalidArgument},
		{"no named engine", "code-review", "m-1", codes.FailedPrecondition},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.RunAgentSkill(ctxAs("admin", true), &pb.RunAgentSkillRequest{SkillId: tc.skill, Model: tc.model})
			if status.Code(err) != tc.want {
				t.Fatalf("code = %v (%v), want %v", status.Code(err), err, tc.want)
			}
		})
	}
}
