package server

import (
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/agentengine"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestRunAgentSkill_EngineOverride_RefusedWhenNotReady proves #2228's
// request-level override actually reaches agentengine.Resolve: hello-agent's
// own manifest names no engine, so with no override it would resolve via the
// gateway's default-provider path and never hit a readiness check at all
// (agentengine.Resolve's own UNSPECIFIED branch). A FailedPrecondition here
// can only be explained by the override being honored.
func TestRunAgentSkill_EngineOverride_RefusedWhenNotReady(t *testing.T) {
	store := newFakeRevocationStore()
	s, skill := newSkillBoxHarness(t, store) // skill = hello-agent, engine unspecified
	// Default gateway from the harness has no GlobalProviders/Keys at all, so
	// a NAMED engine (unlike UNSPECIFIED) is never ready here.
	ctx := ctxAs("admin", true)

	_, err := s.RunAgentSkill(ctx, &pb.RunAgentSkillRequest{
		SkillId: skill.Id, RunId: "run-override-not-ready", Engine: pb.AgentEngine_AGENT_ENGINE_CODEX,
	})
	if err == nil {
		t.Fatal("expected an error — the requested engine (codex/openai) has no key in this harness")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition (an engine refusal, not a provisioning failure)", status.Code(err))
	}
	if got := err.Error(); !strings.Contains(got, "codex") || !strings.Contains(got, "openai") {
		t.Errorf("error = %q, want it to name the requested engine (codex) and provider (openai)", got)
	}
}

// TestRunAgentSkill_EngineOverride_WinsOverManifest proves the override wins
// over a CONCRETE (not just unspecified) manifest value: hello-agent-claude
// names engine: claude, which has no key in this harness and would be
// refused on its own — but the request overrides to codex, which IS ready.
// The run must get PAST engine resolution (observable only indirectly: it
// then fails later, at the fake backend's seed-exec step, like every
// provisioning test in this file's siblings) rather than being refused for
// claude's missing key.
func TestRunAgentSkill_EngineOverride_WinsOverManifest(t *testing.T) {
	store := newFakeRevocationStore()
	s, skills := newSkillBoxHarnessForSkills(t, store, "hello-agent-claude")
	skill := skills[0]
	s.gateway = &gatewayProvisioning{
		engines: agentengine.Gateway{
			DefaultProvider: "anthropic",
			GlobalProviders: map[string]bool{"openai": true}, // codex is ready; claude/anthropic is not
		},
		httpPort: 8080,
		secret:   []byte("test-shared-secret"),
	}
	ctx := ctxAs("admin", true)

	_, err := s.RunAgentSkill(ctx, &pb.RunAgentSkillRequest{
		SkillId: skill.Id, RunId: "run-override-wins", Engine: pb.AgentEngine_AGENT_ENGINE_CODEX,
	})
	if err == nil {
		t.Fatal("expected an error — the harness's fake backend always fails the seed exec")
	}
	if status.Code(err) == codes.FailedPrecondition {
		// FailedPrecondition here would mean the override was ignored and
		// the manifest's own not-ready claude engine was used instead.
		t.Fatalf("code = FailedPrecondition (%v) — the override must have been dropped, the manifest's unready claude engine was used", err)
	}
	if status.Code(err) != codes.Internal {
		t.Fatalf("code = %v (%v), want Internal (a provisioning failure PAST engine resolution)", status.Code(err), err)
	}
	if got := err.Error(); !strings.Contains(got, "failed to seed agent box") {
		t.Errorf("error = %q, want it to name the seed step — proves the override (codex) was used instead of the manifest's own unready claude", got)
	}
}
