package server

import (
	"context"
	"testing"

	"github.com/footprintai/containarium/internal/alert"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/skills"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// The daemon side of the credential-expiry watch (#2371): AgentSkillServer
// is the watcher's CredentialProber.
var _ alert.CredentialProber = (*AgentSkillServer)(nil)

// TestGetSkillBoxCredentialStatus_ReportsExpired: the probe's new "expired"
// answer surfaces as the new wire enum value, not UNSPECIFIED or an error.
func TestGetSkillBoxCredentialStatus_ReportsExpired(t *testing.T) {
	s, skill, backend := newSkillBoxHarnessInspectable(t, newFakeRevocationStore())
	backend.execStdout = "expired\n"

	resp, err := s.GetSkillBoxCredentialStatus(ctxAs("admin", true), &pb.GetSkillBoxCredentialStatusRequest{SkillId: skill.Id})
	if err != nil {
		t.Fatalf("GetSkillBoxCredentialStatus: %v", err)
	}
	if resp.GetCredentialSource() != pb.CodeCredentialSource_CODE_CREDENTIAL_SOURCE_EXPIRED {
		t.Errorf("CredentialSource = %v, want EXPIRED", resp.GetCredentialSource())
	}
}

// TestCredentialWatchTargets_OnlyRunningProbeableSkillBoxes: the watcher
// sweeps a skill's box only once it is running (a stopped box cannot be
// probed) and only for an engine that has a probe — a codex-pinned skill
// is left out rather than probed with the wrong script.
func TestCredentialWatchTargets_OnlyRunningProbeableSkillBoxes(t *testing.T) {
	s, skills, backend := newCredentialWatchHarness(t, "hello-agent", "hello-agent-codex")
	ctx := context.Background()

	got, err := s.CredentialWatchTargets(ctx)
	if err != nil {
		t.Fatalf("CredentialWatchTargets: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("targets with every box stopped = %+v, want none", got)
	}

	for _, sk := range skills {
		if err := backend.StartContainer("agent-" + sk.Id + "-container"); err != nil {
			t.Fatalf("start %s: %v", sk.Id, err)
		}
	}
	got, err = s.CredentialWatchTargets(ctx)
	if err != nil {
		t.Fatalf("CredentialWatchTargets: %v", err)
	}
	want := alert.CredentialWatchTarget{SkillID: "hello-agent", Box: "agent-hello-agent-container", Engine: pb.AgentEngine_AGENT_ENGINE_CLAUDE}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("targets = %+v, want exactly [%+v]", got, want)
	}
}

// TestProbeCredential_RunsTheSameProbeAsTheRPC: the watcher's probe and
// GetSkillBoxCredentialStatus share one code path, so the alert can never
// disagree with what an operator sees when they check by hand.
func TestProbeCredential_RunsTheSameProbeAsTheRPC(t *testing.T) {
	s, skill, backend := newSkillBoxHarnessInspectable(t, newFakeRevocationStore())
	backend.execStdout = "expired\n"

	src, err := s.ProbeCredential(context.Background(), alert.CredentialWatchTarget{
		SkillID: skill.Id, Box: "agent-" + skill.Id + "-container", Engine: pb.AgentEngine_AGENT_ENGINE_CLAUDE,
	})
	if err != nil {
		t.Fatalf("ProbeCredential: %v", err)
	}
	if src != pb.CodeCredentialSource_CODE_CREDENTIAL_SOURCE_EXPIRED {
		t.Errorf("source = %v, want EXPIRED", src)
	}
	if len(backend.execCalls) != 1 || backend.execCalls[0].ContainerName != "agent-"+skill.Id+"-container" {
		t.Errorf("exec calls = %+v, want exactly one probe in the skill's box", backend.execCalls)
	}

	backend.execStdout = "something-else\n"
	if _, err := s.ProbeCredential(context.Background(), alert.CredentialWatchTarget{
		SkillID: skill.Id, Box: "agent-" + skill.Id + "-container", Engine: pb.AgentEngine_AGENT_ENGINE_CLAUDE,
	}); err == nil {
		t.Error("an unrecognized probe answer must be an error, not a guessed source")
	}
}

// newCredentialWatchHarness seeds one (stopped) box per skill id on a fake
// backend and returns the backend too, so a test can start boxes.
func newCredentialWatchHarness(t *testing.T, skillIDs ...string) (*AgentSkillServer, []*pb.AgentSkill, *fakeSandboxBackend) {
	t.Helper()
	backend := newFakeSandboxBackend()
	catalog := skills.GetDefault()
	var out []*pb.AgentSkill
	for _, id := range skillIDs {
		skill, err := catalog.Get(id)
		if err != nil {
			t.Fatalf("catalog %s: %v", id, err)
		}
		if err := backend.CreateContainer(incus.ContainerConfig{Name: "agent-" + skill.Id + "-container"}); err != nil {
			t.Fatalf("seed fake backend for %s: %v", id, err)
		}
		out = append(out, skill)
	}
	cs := &ContainerServer{manager: container.NewWithBackend(backend)}
	return &AgentSkillServer{catalog: catalog, recipes: NewRecipeServer(cs, nil)}, out, backend
}
