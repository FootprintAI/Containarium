package server

import (
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/agentengine"
	"github.com/footprintai/containarium/pkg/core/crews"
	"github.com/footprintai/containarium/pkg/core/skills"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestRunCrew_EngineOverrides_AppliedPerMember reuses #2225's own embedded
// fixture (two-engine-crew: hello-agent-claude then hello-agent-codex) to
// prove #2228's per-member override reaches provisionMemberBox. The
// harness's gateway marks only openai as a ready global provider, so without
// an override hello-agent-claude's own manifest engine (claude/anthropic)
// is refused; with an override to codex it is not.
func TestRunCrew_EngineOverrides_AppliedPerMember(t *testing.T) {
	store := newFakeRevocationStore()
	agents, _ := newSkillBoxHarnessForSkills(t, store, "hello-agent-claude", "hello-agent-codex")
	agents.gateway = &gatewayProvisioning{
		engines: agentengine.Gateway{
			DefaultProvider: "anthropic",
			GlobalProviders: map[string]bool{"openai": true}, // codex ready; claude/anthropic not
		},
		httpPort: 8080,
		secret:   []byte("test-shared-secret"),
	}
	s := &CrewServer{
		catalog: crews.GetDefault(),
		skills:  skills.GetDefault(),
		agents:  agents,
		runs:    NewMemCrewRunStore(),
	}
	ctx := ctxAs("admin", true)

	t.Run("no override: the manifest's own not-ready engine is refused", func(t *testing.T) {
		_, err := s.RunCrew(ctx, &pb.RunCrewRequest{
			CrewId: "two-engine-crew",
			RunId:  "run-no-override",
		})
		if err == nil {
			t.Fatal("expected an error — hello-agent-claude's manifest engine (claude/anthropic) has no key in this harness")
		}
		if status.Code(err) != codes.Internal {
			t.Errorf("code = %v, want Internal (RunCrew wraps every provisioning failure, including an engine refusal)", status.Code(err))
		}
		if got := err.Error(); !strings.Contains(got, "hello-agent-claude") || !strings.Contains(got, "anthropic") {
			t.Errorf("error = %q, want it to name hello-agent-claude's unready engine/provider", got)
		}
	})

	t.Run("override rescues a member whose manifest engine has no key", func(t *testing.T) {
		_, err := s.RunCrew(ctx, &pb.RunCrewRequest{
			CrewId: "two-engine-crew",
			RunId:  "run-override-rescue",
			EngineOverrides: map[string]pb.AgentEngine{
				"hello-agent-claude": pb.AgentEngine_AGENT_ENGINE_CODEX,
			},
		})
		// hello-agent-claude is overridden to codex (ready); hello-agent-codex
		// keeps its own manifest engine (also codex, also ready). Both members
		// now pass engine resolution, so the run fails LATER, at the fake
		// backend's seed-exec step — proving the override reached
		// provisionMemberBox instead of being dropped.
		if err == nil {
			t.Fatal("expected an error — the harness's fake backend always fails the seed exec")
		}
		if status.Code(err) != codes.Internal {
			t.Errorf("code = %v, want Internal (a provisioning failure, not an engine refusal)", status.Code(err))
		}
		if got := err.Error(); !strings.Contains(got, "failed to seed agent box") {
			t.Errorf("error = %q, want it to name the seed step — an engine refusal here would mean the override did not rescue hello-agent-claude", got)
		}
	})
}
