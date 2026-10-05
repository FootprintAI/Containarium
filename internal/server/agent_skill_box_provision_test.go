package server

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/skills"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// TestProvisionSkillBox_ReusesExistingBoxWithoutMintingOrSeeding is #2272's
// core acceptance criterion: a skill's box can be provisioned ahead of any
// real run, and that provisioning never mints a token, never seeds a
// prompt/task, and never execs anything in the box — RunAgentSkill's seed
// exec is the only thing a model call could ever ride in on, and this path
// must not go near it.
//
// newSkillBoxHarness pre-creates the box in "Stopped" state (the fake
// backend's CreateContainer default), which exercises the REUSE branch:
// ProvisionSkillBox must start it (so a human can SSH in) without deploying
// a new one or touching exec.
func TestProvisionSkillBox_ReusesExistingBoxWithoutMintingOrSeeding(t *testing.T) {
	store := newFakeRevocationStore()
	s, skill, backend := newSkillBoxHarnessInspectable(t, store)

	resp, err := s.ProvisionSkillBox(ctxAs("admin", true), &pb.ProvisionSkillBoxRequest{SkillId: skill.Id})
	if err != nil {
		t.Fatalf("ProvisionSkillBox: %v", err)
	}
	if resp.GetFreshlyProvisioned() {
		t.Error("FreshlyProvisioned = true, want false — the harness pre-creates the box, this must be the reuse path")
	}
	if resp.GetContainer() == nil {
		t.Fatal("Container is nil")
	}
	if resp.GetContainer().GetState() != pb.ContainerState_CONTAINER_STATE_RUNNING {
		t.Errorf("Container.State = %v, want RUNNING (a stopped box must be started so a human can SSH in)", resp.GetContainer().GetState())
	}
	if len(backend.execCalls) != 0 {
		t.Errorf("ProvisionSkillBox must never exec in the box (no seed, no run); got exec calls: %+v", backend.execCalls)
	}
}

// TestProvisionSkillBox_RequiresSkillID pins the InvalidArgument guard.
func TestProvisionSkillBox_RequiresSkillID(t *testing.T) {
	s := &AgentSkillServer{catalog: skills.GetDefault()}
	_, err := s.ProvisionSkillBox(ctxAs("admin", true), &pb.ProvisionSkillBoxRequest{})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", status.Code(err))
	}
}

// TestProvisionSkillBox_UnknownSkillIsNotFound pins that an unregistered
// skill id fails NotFound before any box work is attempted.
func TestProvisionSkillBox_UnknownSkillIsNotFound(t *testing.T) {
	store := newFakeRevocationStore()
	s, _ := newSkillBoxHarness(t, store)

	_, err := s.ProvisionSkillBox(ctxAs("admin", true), &pb.ProvisionSkillBoxRequest{SkillId: "no-such-skill"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("code = %v, want NotFound", status.Code(err))
	}
}

// TestGetSkillBoxCredentialStatus_RequiresProvisionedBox: the credential
// check is only meaningful once ProvisionSkillBox (or a run) has created the
// box. An unprovisioned skill must fail NotFound, naming the fix.
func TestGetSkillBoxCredentialStatus_RequiresProvisionedBox(t *testing.T) {
	tm, err := auth.NewTokenManager("test-secret-must-be-at-least-32-bytes-long-ok", "test")
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	backend := newFakeSandboxBackend()
	cs := &ContainerServer{manager: container.NewWithBackend(backend)}
	s := &AgentSkillServer{catalog: skills.GetDefault(), recipes: NewRecipeServer(cs, nil), tokens: tm}

	_, err = s.GetSkillBoxCredentialStatus(ctxAs("admin", true), &pb.GetSkillBoxCredentialStatusRequest{SkillId: "hello-agent"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("code = %v, want NotFound (box never provisioned)", status.Code(err))
	}
}

// TestGetSkillBoxCredentialStatus_ReportsProbeSourceNameOnly proves the
// RPC surfaces exactly the probe's source NAME and nothing else: it stuffs
// an arbitrary (non-credential-shaped) string as the fake exec's stdout and
// asserts the typed enum round-trips it — there is no value field anywhere
// on the response for a real credential to leak through even if the box's
// probe somehow printed one.
func TestGetSkillBoxCredentialStatus_ReportsProbeSourceNameOnly(t *testing.T) {
	store := newFakeRevocationStore()
	s, skill, backend := newSkillBoxHarnessInspectable(t, store)
	backend.execStdout = "interactive\n"
	backend.execExitCode = 0

	before := time.Now()
	resp, err := s.GetSkillBoxCredentialStatus(ctxAs("admin", true), &pb.GetSkillBoxCredentialStatusRequest{SkillId: skill.Id})
	if err != nil {
		t.Fatalf("GetSkillBoxCredentialStatus: %v", err)
	}
	if resp.GetCredentialSource() != pb.CodeCredentialSource_CODE_CREDENTIAL_SOURCE_INTERACTIVE {
		t.Errorf("CredentialSource = %v, want INTERACTIVE", resp.GetCredentialSource())
	}
	if resp.GetEngine() != pb.AgentEngine_AGENT_ENGINE_CLAUDE {
		t.Errorf("Engine = %v, want CLAUDE (hello-agent names none, which resolves to Claude)", resp.GetEngine())
	}
	if resp.GetCheckedAt() == nil || resp.GetCheckedAt().AsTime().Before(before) {
		t.Errorf("CheckedAt = %v, want set to roughly now", resp.GetCheckedAt())
	}
	if len(backend.execCalls) != 1 {
		t.Fatalf("exec calls = %d, want exactly 1 (the probe)", len(backend.execCalls))
	}
	// The probe must be a read-only presence check — never anything that
	// could itself leak a value (e.g. `cat` on a credential file).
	for _, part := range backend.execCalls[0].Command {
		if strings.Contains(part, "cat ") {
			t.Errorf("probe command must never cat a file: %v", backend.execCalls[0].Command)
		}
	}
}

// TestGetSkillBoxCredentialStatus_NoneIsNotAnError: a freshly provisioned
// box with nothing signed in yet must report NONE successfully, not an
// error — "none" is the expected, normal state #2272 exists to let a human
// move past.
func TestGetSkillBoxCredentialStatus_NoneIsNotAnError(t *testing.T) {
	store := newFakeRevocationStore()
	s, skill, backend := newSkillBoxHarnessInspectable(t, store)
	backend.execStdout = "none\n"
	backend.execExitCode = 0

	resp, err := s.GetSkillBoxCredentialStatus(ctxAs("admin", true), &pb.GetSkillBoxCredentialStatusRequest{SkillId: skill.Id})
	if err != nil {
		t.Fatalf("GetSkillBoxCredentialStatus: %v", err)
	}
	if resp.GetCredentialSource() != pb.CodeCredentialSource_CODE_CREDENTIAL_SOURCE_NONE {
		t.Errorf("CredentialSource = %v, want NONE", resp.GetCredentialSource())
	}
}

// TestGetSkillBoxCredentialStatus_UnsupportedEngineIsUnimplemented: a skill
// pinned to an engine with no probe yet (Codex, #2273) must refuse clearly
// rather than silently reporting a wrong/default status. hello-agent-codex
// is the repo's own reference fixture for a codex-pinned skill.
func TestGetSkillBoxCredentialStatus_UnsupportedEngineIsUnimplemented(t *testing.T) {
	store := newFakeRevocationStore()
	s, skills := newSkillBoxHarnessForSkills(t, store, "hello-agent-codex")
	skill := skills[0]
	if skill.GetEngine() != pb.AgentEngine_AGENT_ENGINE_CODEX {
		t.Fatalf("fixture hello-agent-codex engine = %v, want CODEX", skill.GetEngine())
	}

	_, err := s.GetSkillBoxCredentialStatus(ctxAs("admin", true), &pb.GetSkillBoxCredentialStatusRequest{SkillId: skill.Id})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("code = %v, want Unimplemented (no credential-status probe for codex yet)", status.Code(err))
	}
}

// TestGetSkillBoxCredentialStatus_RejectsGarbageProbeOutput: if the box's
// probe ever printed something other than the three valid source names
// (a bug in a future engine's script, or a tampered box), the RPC must fail
// loudly rather than silently reporting a value that happens to parse. This
// is the one path that would otherwise risk echoing something
// credential-shaped back to a caller.
func TestGetSkillBoxCredentialStatus_RejectsGarbageProbeOutput(t *testing.T) {
	store := newFakeRevocationStore()
	s, skill, backend := newSkillBoxHarnessInspectable(t, store)
	backend.execStdout = "sk-ant-not-a-real-value-but-the-shape-of-one\n"
	backend.execExitCode = 0

	_, err := s.GetSkillBoxCredentialStatus(ctxAs("admin", true), &pb.GetSkillBoxCredentialStatusRequest{SkillId: skill.Id})
	if status.Code(err) != codes.Internal {
		t.Fatalf("code = %v, want Internal (unrecognized probe output must fail, never be reported as a status)", status.Code(err))
	}
}

// TestGetSkillBoxCredentialStatus_ScopeEnforced: a caller holding only
// agents:run (enough to provision/run a box) must not pass agents:read's
// gate; a caller holding agents:read must.
func TestGetSkillBoxCredentialStatus_ScopeEnforced(t *testing.T) {
	store := newFakeRevocationStore()
	s, skill, backend := newSkillBoxHarnessInspectable(t, store)
	backend.execStdout = "none\n"

	runOnly := auth.ContextWithTestSubjectScopes(ctxAs("alice", false), "alice", nil, []string{auth.ScopeAgentsRun})
	if _, err := s.GetSkillBoxCredentialStatus(runOnly, &pb.GetSkillBoxCredentialStatusRequest{SkillId: skill.Id}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("agents:run-only caller: code = %v, want PermissionDenied (scope check must run before any box lookup)", status.Code(err))
	}
}
