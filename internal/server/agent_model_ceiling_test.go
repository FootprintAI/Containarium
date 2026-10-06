package server

import (
	"context"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/agentengine"
	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/modelgateway"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/skills"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// modelCeilingSkillYAML is a minimal named-engine, named-model skill — the
// embedded catalog's own skills (hello-agent-claude/-codex, #2225) deliberately
// pin no model, so #2229's check needs a fixture that does.
const modelCeilingSkillYAML = `
skills:
  - id: model-ceiling-test
    name: Model Ceiling Test
    recipe_id: agent-runtime
    system_prompt: test skill for #2229's model-ceiling check.
    allowed_scopes:
      - containers:read
    engine: codex
    model: gpt-5-codex
`

// fakeModelLister is a modelLister test double with a call recorder (the
// issue's own AC: "the model list lookup is a fake with a call recorder").
type fakeModelLister struct {
	models []string
	err    error
	calls  []struct{ keyOwner, provider string }
}

func (f *fakeModelLister) ListModels(_ context.Context, keyOwner, provider string) ([]string, error) {
	f.calls = append(f.calls, struct{ keyOwner, provider string }{keyOwner, provider})
	if f.err != nil {
		return nil, f.err
	}
	return f.models, nil
}

// newModelCeilingHarness is newSkillBoxHarness, generalized to a caller-
// supplied catalog and modelLister — #2229's model-ceiling check needs a
// skill with a pinned engine+model, which no embedded skill has.
func newModelCeilingHarness(t *testing.T, catalogYAML string, models modelLister) (*AgentSkillServer, *pb.AgentSkill) {
	t.Helper()
	tm, err := auth.NewTokenManager("test-secret-must-be-at-least-32-bytes-long-ok", "test")
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	catalog := skills.New()
	if err := catalog.LoadFromBytes([]byte(catalogYAML)); err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}
	skill, err := catalog.Get("model-ceiling-test")
	if err != nil {
		t.Fatalf("catalog model-ceiling-test: %v", err)
	}
	backend := newFakeSandboxBackend()
	if err := backend.CreateContainer(incus.ContainerConfig{Name: "agent-" + skill.Id + "-container"}); err != nil {
		t.Fatalf("seed fake backend: %v", err)
	}
	cs := &ContainerServer{manager: container.NewWithBackend(backend)}
	s := &AgentSkillServer{
		catalog: catalog,
		recipes: NewRecipeServer(cs, nil),
		tokens:  tm,
		gateway: &gatewayProvisioning{
			engines: agentengine.Gateway{
				DefaultProvider: "anthropic",
				GlobalProviders: map[string]bool{"anthropic": true, "openai": true},
			},
			httpPort: 8080,
			secret:   []byte("test-shared-secret"),
			models:   models,
		},
	}
	s.SetRevocationStore(newFakeRevocationStore())
	return s, skill
}

// TestRunAgentSkill_ModelCeiling_ConfirmedMismatchRefuses pins the AC's core
// claim: a model the resolved provider does NOT list is refused at
// RunAgentSkill with FailedPrecondition naming the model, the provider, and
// the models it does list — before any box work past engine resolution.
func TestRunAgentSkill_ModelCeiling_ConfirmedMismatchRefuses(t *testing.T) {
	fake := &fakeModelLister{models: []string{"gpt-5", "gpt-5-mini"}} // does NOT list gpt-5-codex
	s, skill := newModelCeilingHarness(t, modelCeilingSkillYAML, fake)
	ctx := ctxAs("admin", true)

	_, err := s.RunAgentSkill(ctx, &pb.RunAgentSkillRequest{SkillId: skill.Id, RunId: "run-mismatch"})
	if err == nil {
		t.Fatal("expected a refusal — the fake model list does not include gpt-5-codex")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition", status.Code(err))
	}
	for _, want := range []string{"model-ceiling-test", "gpt-5-codex", "openai", "gpt-5", "gpt-5-mini"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to contain %q (AC: name the model, the provider, and the models it does list)", err, want)
		}
	}
	if len(fake.calls) != 1 || fake.calls[0].provider != "openai" {
		t.Errorf("ListModels calls = %+v, want exactly one call for provider openai", fake.calls)
	}
}

// TestRunAgentSkill_ModelCeiling_ConfirmedMatchProceeds proves a model the
// provider DOES list is not refused — the run gets past engine+model
// resolution and fails later, at the fake backend's own seed-exec step, the
// same "proceeded past this check" signal #2228's tests use.
func TestRunAgentSkill_ModelCeiling_ConfirmedMatchProceeds(t *testing.T) {
	fake := &fakeModelLister{models: []string{"gpt-5-codex", "gpt-5"}}
	s, skill := newModelCeilingHarness(t, modelCeilingSkillYAML, fake)
	ctx := ctxAs("admin", true)

	_, err := s.RunAgentSkill(ctx, &pb.RunAgentSkillRequest{SkillId: skill.Id, RunId: "run-match"})
	if err == nil {
		t.Fatal("expected an error — the harness's fake backend always fails the seed exec")
	}
	if status.Code(err) == codes.FailedPrecondition {
		t.Fatalf("code = FailedPrecondition (%v) — the model-ceiling check must have refused a model the provider DOES list", err)
	}
	if got := err.Error(); !strings.Contains(got, "failed to seed agent box") {
		t.Errorf("error = %q, want it to name the seed step (proceeded past the model check)", got)
	}
	if len(fake.calls) != 1 {
		t.Errorf("ListModels calls = %+v, want exactly one", fake.calls)
	}
}

// TestRunAgentSkill_ModelCeiling_CantCheckProceeds covers both "can't check"
// cases the AC's best-effort posture names: an unsupported provider shape and
// no key to list with. Neither is a refusal — proceeding without a check we
// have no way to perform is strictly no worse than today's unchecked pass-
// through, and matches this function's own best-effort posture for the mint
// a few lines below the check.
func TestRunAgentSkill_ModelCeiling_CantCheckProceeds(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"provider has no model-list support", modelgateway.ErrModelListUnsupported},
		{"no key to list with", modelgateway.ErrNoKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeModelLister{err: tc.err}
			s, skill := newModelCeilingHarness(t, modelCeilingSkillYAML, fake)
			ctx := ctxAs("admin", true)

			_, err := s.RunAgentSkill(ctx, &pb.RunAgentSkillRequest{SkillId: skill.Id, RunId: "run-cant-check"})
			if err == nil {
				t.Fatal("expected an error — the harness's fake backend always fails the seed exec")
			}
			if status.Code(err) == codes.FailedPrecondition {
				t.Fatalf("code = FailedPrecondition (%v) — a lookup we cannot perform must not refuse the run", err)
			}
			if got := err.Error(); !strings.Contains(got, "failed to seed agent box") {
				t.Errorf("error = %q, want it to name the seed step (proceeded past the unchecked model)", got)
			}
		})
	}
}

// TestRunAgentSkill_ModelCeiling_SkippedWhenEngineUnspecified proves the
// check never runs for a skill naming no engine: #2222 already ignores its
// pinned model entirely (never exported), so checking it would refuse a run
// over a value nothing uses.
func TestRunAgentSkill_ModelCeiling_SkippedWhenEngineUnspecified(t *testing.T) {
	fake := &fakeModelLister{err: errNeverCalled{}}
	const yaml = `
skills:
  - id: model-ceiling-test
    name: Model Ceiling Test
    recipe_id: agent-runtime
    system_prompt: test skill for #2229's model-ceiling check.
    allowed_scopes:
      - containers:read
    model: gpt-5-codex
`
	s, skill := newModelCeilingHarness(t, yaml, fake)
	ctx := ctxAs("admin", true)

	_, err := s.RunAgentSkill(ctx, &pb.RunAgentSkillRequest{SkillId: skill.Id, RunId: "run-unspecified"})
	if err == nil {
		t.Fatal("expected an error — the harness's fake backend always fails the seed exec")
	}
	if len(fake.calls) != 0 {
		t.Errorf("ListModels was called %d time(s), want 0 — an unspecified-engine skill's model is never checked", len(fake.calls))
	}
}

// errNeverCalled fails the test loudly if ListModels is ever actually invoked
// (it should short-circuit on engineRes.Default before reaching the lookup).
type errNeverCalled struct{}

func (errNeverCalled) Error() string {
	return "ListModels must not be called for an unspecified-engine skill"
}
