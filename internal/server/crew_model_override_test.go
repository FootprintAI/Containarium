package server

import (
	"strings"
	"testing"

	"github.com/footprintai/containarium/pkg/core/crews"
	"github.com/footprintai/containarium/pkg/core/skills"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func modelTestSkills() (*pb.Crew, func(string) (*pb.AgentSkill, bool)) {
	byID := map[string]*pb.AgentSkill{
		"named-pinned": {Id: "named-pinned", Engine: pb.AgentEngine_AGENT_ENGINE_CLAUDE, Model: "pinned-model"},
		"named-bare":   {Id: "named-bare", Engine: pb.AgentEngine_AGENT_ENGINE_CLAUDE},
		"no-engine":    {Id: "no-engine"},
	}
	crew := &pb.Crew{Id: "c", SkillIds: []string{"named-pinned", "named-bare", "no-engine"}}
	return crew, func(id string) (*pb.AgentSkill, bool) { s, ok := byID[id]; return s, ok }
}

func TestValidateCrewModelOverrides(t *testing.T) {
	crew, get := modelTestSkills()
	for _, tc := range []struct {
		name string
		req  *pb.RunCrewRequest
		want codes.Code
	}{
		{"none is fine", &pb.RunCrewRequest{}, codes.OK},
		{"a named-engine member", &pb.RunCrewRequest{ModelOverrides: map[string]string{"named-bare": "m-1"}}, codes.OK},
		{"a member the crew does not have", &pb.RunCrewRequest{ModelOverrides: map[string]string{"stranger": "m-1"}}, codes.InvalidArgument},
		{"a malformed id", &pb.RunCrewRequest{ModelOverrides: map[string]string{"named-bare": "x; rm -rf /"}}, codes.InvalidArgument},
		{"an empty id", &pb.RunCrewRequest{ModelOverrides: map[string]string{"named-bare": ""}}, codes.InvalidArgument},
		// A model is only carried to the box together with a named engine; on a
		// default-engine member it would be dropped silently, so it is refused.
		{"a member with no engine named", &pb.RunCrewRequest{ModelOverrides: map[string]string{"no-engine": "m-1"}}, codes.FailedPrecondition},
		{"no engine in the manifest but one in engine_overrides", &pb.RunCrewRequest{
			ModelOverrides:  map[string]string{"no-engine": "m-1"},
			EngineOverrides: map[string]pb.AgentEngine{"no-engine": pb.AgentEngine_AGENT_ENGINE_CODEX}}, codes.OK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateModelOverrides(crew.GetSkillIds(), tc.req, get)
			if status.Code(err) != tc.want {
				t.Fatalf("code = %v (%v), want %v", status.Code(err), err, tc.want)
			}
		})
	}
}

func TestWithModelOverride_ClonesAndNamesTheModel(t *testing.T) {
	_, get := modelTestSkills()
	sk, _ := get("named-pinned")
	req := &pb.RunCrewRequest{ModelOverrides: map[string]string{"named-pinned": "override-model"}}

	got := withModelOverride(sk, req)
	if got.GetModel() != "override-model" {
		t.Errorf("model = %q, want the per-run override to win over the skill's pinned one", got.GetModel())
	}
	if sk.GetModel() != "pinned-model" {
		t.Errorf("the shared catalog skill was mutated: model = %q", sk.GetModel())
	}
	if untouched := withModelOverride(sk, &pb.RunCrewRequest{}); untouched != sk {
		t.Error("no override must return the skill itself, unchanged")
	}
}

// Precedence: per-run override, then the skill's own model; a member that
// exports no model is not listed (the engine default ran).
func TestCrewMemberModels_ReportsTheEffectiveModel(t *testing.T) {
	crew, get := modelTestSkills()
	req := &pb.RunCrewRequest{ModelOverrides: map[string]string{"named-bare": "override-model"}}
	got := crewMemberModels(crew.GetSkillIds(), req, get)
	want := map[string]string{"named-pinned": "pinned-model", "named-bare": "override-model"}
	if len(got) != len(want) {
		t.Fatalf("member models = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("member_models[%s] = %q, want %q", k, got[k], v)
		}
	}
}

// RunCrew refuses before provisioning anything.
func TestRunCrew_ModelOverrideRefusedUpFront(t *testing.T) {
	s := &CrewServer{catalog: crews.GetDefault(), skills: skills.GetDefault(), runs: NewMemCrewRunStore()}
	_, err := s.RunCrew(ctxAs("admin", true), &pb.RunCrewRequest{
		CrewId:         "two-engine-crew",
		RunId:          "run-bad-model",
		ModelOverrides: map[string]string{"hello-agent-claude": "bad id"},
	})
	if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "model_overrides") {
		t.Errorf("err = %v, want InvalidArgument naming model_overrides", err)
	}
}
