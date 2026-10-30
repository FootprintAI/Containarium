package server

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/proofpack"
	"github.com/footprintai/containarium/internal/runlease"
	"github.com/footprintai/containarium/pkg/core/crews"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #2799: the engineer-crew's Proof Pack comes from a box other than the
// coder's. These tests drive runCrew with the real embedded engineer-crew and
// fakes for the collaborators a unit test cannot reach (box provisioning, A2A,
// in-box exec).

const (
	packImplArtifact  = `{"files":[{"path":"widget.go","content":"package widget\n"}],"summary":"add widget","pr_title":"Add widget","pr_body":"b","tests_run":true}`
	packFinalArtifact = `{"files":[{"path":"widget.go","content":"package widget\n\n// reviewed\n"}],"drafter_summary":"add widget","review_notes":"comment","pr_title":"Add widget","pr_body":"b","tests_run":true}`
)

// packCall is one producePack invocation.
type packCall struct{ box, dir, artifact string }

type packHarness struct {
	*crewLeaseHarness
	producerProvisioned []string
	producerBox         string // box the fake provisionProducer hands back
	packs               []packCall
	pack                *pb.ProofPack
	packErr             error
}

func newPackHarness(t *testing.T) *packHarness {
	t.Helper()
	h := newCrewLeaseHarness(t, "relay-agent", "hello-agent")
	h.crew.catalog = crews.GetDefault()
	return &packHarness{crewLeaseHarness: h, producerBox: "agent-test-runner-container"}
}

func (h *packHarness) provisionProducer(_ context.Context, skill *pb.AgentSkill, _ *pb.RunCrewRequest, runID string) (runlease.Lease, string, error) {
	h.producerProvisioned = append(h.producerProvisioned, skill.Id)
	return runlease.Lease{RunID: runID, Box: h.producerBox, SeedDir: seedDirFor(runID), Workspace: workspaceDirFor(runID)}, "commit-base", nil
}

func (h *packHarness) producePack(_ context.Context, box, dir, artifact string) (*pb.ProofPack, error) {
	h.packs = append(h.packs, packCall{box, dir, artifact})
	if h.packErr != nil {
		return nil, h.packErr
	}
	p := h.pack
	if p == nil {
		p = &pb.ProofPack{SchemaVersion: 1, Producer: box, GitCommit: "commit-base", Status: pb.ProofPackStatus_PROOF_PACK_STATUS_PASSED}
	}
	return p, nil
}

func (h *packHarness) runEngineerCrew(t *testing.T, runID string, send taskSender) *pb.CrewRun {
	t.Helper()
	crew, err := h.crew.catalog.Get("engineer-crew")
	if err != nil {
		t.Fatalf("engineer-crew: %v", err)
	}
	if err := validateCrewTopology(crew, h.crew.skillByID); err != nil {
		t.Fatalf("engineer-crew fails RunCrew's topology gate: %v", err)
	}
	resp, err := h.crew.runCrew(ctxAs("admin", true), &pb.RunCrewRequest{
		CrewId: "engineer-crew", RunId: runID, GitSource: "https://example.com/org/repo", GitRef: "main",
	}, crew, runID, crewRunDeps{
		provision:         h.provisioner.provision,
		provisionProducer: h.provisionProducer,
		producePack:       h.producePack,
		send:              send,
		wiper:             h.wiper,
	})
	if err != nil {
		t.Fatalf("runCrew: %v", err)
	}
	return resp.GetRun()
}

func engineerSend(_ context.Context, req *pb.SendAgentTaskRequest) (*pb.SendAgentTaskResponse, error) {
	if req.ToPeerId == "diff-reviewer" {
		return completed(packFinalArtifact), nil
	}
	return completed(packImplArtifact), nil
}

// TestRunCrew_EngineerCrewPackFromProducerBox is acceptance criterion 1: the
// pack is produced in the test-runner's box, not the coder's, from the
// reviewer's final files, and its status is on the run result.
func TestRunCrew_EngineerCrewPackFromProducerBox(t *testing.T) {
	h := newPackHarness(t)
	const runID = "run-pack-ok"
	run := h.runEngineerCrew(t, runID, engineerSend)

	if run.GetState() != pb.CrewRunState_CREW_RUN_STATE_COMPLETED {
		t.Fatalf("state = %v (%s), want COMPLETED", run.GetState(), run.GetError())
	}
	// The A2A members are provisioned as agents; the producer is not.
	if got := strings.Join(h.provisioner.provided, ","); got != "issue-implementer,diff-reviewer" {
		t.Errorf("agent members provisioned = %s, want issue-implementer,diff-reviewer", got)
	}
	if got := strings.Join(h.producerProvisioned, ","); got != "test-runner" {
		t.Errorf("producer provisioned = %s, want test-runner", got)
	}
	if len(h.packs) != 1 {
		t.Fatalf("producePack calls = %d, want 1", len(h.packs))
	}
	call := h.packs[0]
	if call.box != "agent-test-runner-container" || call.dir != workspaceDirFor(runID) {
		t.Errorf("pack produced in %s:%s, want agent-test-runner-container:%s", call.box, call.dir, workspaceDirFor(runID))
	}
	if call.artifact != packFinalArtifact {
		t.Errorf("producer got %q, want the reviewer's final artifact", call.artifact)
	}

	pp := run.GetProofPack()
	if pp.GetStatus() != pb.ProofPackStatus_PROOF_PACK_STATUS_PASSED || pp.GetError() != "" {
		t.Errorf("proof_pack = %+v, want PASSED with no error", pp)
	}
	if pp.GetProducerBox() != "agent-test-runner-container" || pp.GetCoderBox() != "agent-issue-implementer-container" {
		t.Errorf("producer_box = %q coder_box = %q", pp.GetProducerBox(), pp.GetCoderBox())
	}
	want, _ := proofpack.PackDigest(&pb.ProofPack{SchemaVersion: 1, Producer: "agent-test-runner-container", GitCommit: "commit-base", Status: pb.ProofPackStatus_PROOF_PACK_STATUS_PASSED})
	if pp.GetPackSha256() != want || pp.GetGitCommit() != "commit-base" {
		t.Errorf("pack_sha256 = %q git_commit = %q, want %q commit-base", pp.GetPackSha256(), pp.GetGitCommit(), want)
	}
	if got := strings.Join(pp.GetAppliedFiles(), ","); got != "widget.go" {
		t.Errorf("applied_files = %s, want widget.go", got)
	}
	// The stored run carries it too.
	stored, _, _ := h.crew.runs.Get(context.Background(), runID)
	if stored.GetProofPack().GetStatus() != pb.ProofPackStatus_PROOF_PACK_STATUS_PASSED {
		t.Errorf("stored run proof_pack = %+v", stored.GetProofPack())
	}
	// The producer's checkout is removed with the run, like every member's.
	var removed bool
	for i, cmd := range h.wiper.cmds {
		if h.wiper.boxes[i] == "agent-test-runner-container" && strings.Join(cmd, " ") == "rm -rf "+seedDirFor(runID)+" "+workspaceDirFor(runID) {
			removed = true
		}
	}
	if !removed {
		t.Error("the producer's workspace was not removed when the run ended")
	}
}

// TestRunCrew_PackOutcomeIsReportedNotEnforced: a failing or unproducible
// pack is reported on the run; the run itself still COMPLETES. Gating on it
// is the caller's job (the PR opener), which reads proof_pack.
func TestRunCrew_PackOutcomeIsReportedNotEnforced(t *testing.T) {
	t.Run("failed pack", func(t *testing.T) {
		h := newPackHarness(t)
		h.pack = &pb.ProofPack{Producer: "agent-test-runner-container", Status: pb.ProofPackStatus_PROOF_PACK_STATUS_FAILED}
		run := h.runEngineerCrew(t, "run-pack-failed", engineerSend)
		if run.GetState() != pb.CrewRunState_CREW_RUN_STATE_COMPLETED || run.GetProofPack().GetStatus() != pb.ProofPackStatus_PROOF_PACK_STATUS_FAILED {
			t.Errorf("state = %v proof_pack = %+v, want COMPLETED with a FAILED pack", run.GetState(), run.GetProofPack())
		}
	})
	t.Run("pack could not be produced", func(t *testing.T) {
		h := newPackHarness(t)
		h.packErr = errors.New("box has no timeout")
		run := h.runEngineerCrew(t, "run-pack-err", engineerSend)
		pp := run.GetProofPack()
		if run.GetState() != pb.CrewRunState_CREW_RUN_STATE_COMPLETED || pp.GetStatus() != pb.ProofPackStatus_PROOF_PACK_STATUS_UNSPECIFIED || !strings.Contains(pp.GetError(), "box has no timeout") {
			t.Errorf("state = %v proof_pack = %+v, want COMPLETED, no status, the error", run.GetState(), pp)
		}
	})
	t.Run("crew failed before the final files", func(t *testing.T) {
		h := newPackHarness(t)
		run := h.runEngineerCrew(t, "run-pack-drive-failed", func(_ context.Context, _ *pb.SendAgentTaskRequest) (*pb.SendAgentTaskResponse, error) {
			return nil, errors.New("peer down")
		})
		if run.GetState() != pb.CrewRunState_CREW_RUN_STATE_FAILED || run.GetProofPack() != nil || len(h.packs) != 0 {
			t.Errorf("state = %v proof_pack = %+v packs = %d, want FAILED and no pack", run.GetState(), run.GetProofPack(), len(h.packs))
		}
	})
}

// TestRunCrew_RefusesPackFromCoderBox is the runtime half of criterion 2: if
// provisioning ever hands the producer the coder's box, no pack is produced.
func TestRunCrew_RefusesPackFromCoderBox(t *testing.T) {
	h := newPackHarness(t)
	h.producerBox = "agent-issue-implementer-container"
	run := h.runEngineerCrew(t, "run-pack-same-box", engineerSend)
	if len(h.packs) != 0 {
		t.Fatalf("a pack was produced in the coder's box")
	}
	if pp := run.GetProofPack(); pp.GetStatus() != pb.ProofPackStatus_PROOF_PACK_STATUS_UNSPECIFIED || !strings.Contains(pp.GetError(), "coder's box") {
		t.Errorf("proof_pack = %+v, want an error naming the coder's box", pp)
	}
}

// fakePackBox records writes into a box and answers proofpack's probe as a
// checkout with no declaration and no Makefile.
type fakePackBox struct {
	writes map[string]string
	execs  [][]string
}

func (f *fakePackBox) Exec(_ string, cmd []string) error { f.execs = append(f.execs, cmd); return nil }
func (f *fakePackBox) WriteFile(_, path string, content []byte, _ string) error {
	if f.writes == nil {
		f.writes = map[string]string{}
	}
	f.writes[path] = string(content)
	return nil
}
func (f *fakePackBox) ExecWithExitCode(_ string, cmd []string) (string, string, int, error) {
	if cmd[0] == "git" {
		return "base123\n", "", 0, nil
	}
	return "", "", 10, nil
}

// TestProduceProofPack writes the final files into the producer's checkout
// and generates the pack there with proofpack.Generate (not by shelling out
// to `containariumd proof-pack generate`).
func TestProduceProofPack(t *testing.T) {
	box := &fakePackBox{}
	pack, err := produceProofPack(context.Background(), box, "agent-test-runner-container", "/workspace/runs/r1",
		`{"files":[{"path":"pkg/a.go","content":"package a\n"},{"path":"b.txt","content":"b"}]}`)
	if err != nil {
		t.Fatalf("produceProofPack: %v", err)
	}
	if box.writes["/workspace/runs/r1/pkg/a.go"] != "package a\n" || box.writes["/workspace/runs/r1/b.txt"] != "b" || len(box.writes) != 2 {
		t.Errorf("writes = %v", box.writes)
	}
	if pack.GetProducer() != "agent-test-runner-container" || pack.GetRepoDir() != "/workspace/runs/r1" ||
		pack.GetGitCommit() != "base123" || pack.GetStatus() != pb.ProofPackStatus_PROOF_PACK_STATUS_NO_COMMANDS {
		t.Errorf("pack = producer %q dir %q commit %q status %v", pack.GetProducer(), pack.GetRepoDir(), pack.GetGitCommit(), pack.GetStatus())
	}

	for _, bad := range []string{"../escape.go", "/etc/passwd", "", "a/../../b", `{"files":`} {
		t.Run("rejects "+bad, func(t *testing.T) {
			box := &fakePackBox{}
			artifact := `{"files":[{"path":"ok.go","content":"x"},{"path":"` + bad + `","content":"x"}]}`
			if strings.HasPrefix(bad, "{") {
				artifact = bad
			}
			if _, err := produceProofPack(context.Background(), box, "b", "/workspace/runs/r1", artifact); err == nil {
				t.Fatal("want an error")
			}
			if len(box.writes) != 0 {
				t.Errorf("wrote %v before rejecting the artifact", box.writes)
			}
		})
	}
}
