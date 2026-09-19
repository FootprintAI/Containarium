package server

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// TestRunAgentSkill_GitFieldsRoundTrip pins the git_source/git_ref/
// git_credential request fields and the git_commit/workspace_path response
// fields against the GENERATED pb types (#1859), so a stale regen fails to
// compile rather than passing quietly — the same pattern
// TestRunAgentSkill_ResponseCarriesRunID uses for run_id.
func TestRunAgentSkill_GitFieldsRoundTrip(t *testing.T) {
	req := &pb.RunAgentSkillRequest{
		SkillId:       "code-review",
		GitSource:     "https://github.com/org/repo",
		GitRef:        "abc123",
		GitCredential: "ghs_secret",
	}
	if req.GetGitSource() != "https://github.com/org/repo" {
		t.Errorf("GetGitSource() = %q, want the set value", req.GetGitSource())
	}
	if req.GetGitRef() != "abc123" {
		t.Errorf("GetGitRef() = %q, want the set value", req.GetGitRef())
	}
	if req.GetGitCredential() != "ghs_secret" {
		t.Errorf("GetGitCredential() = %q, want the set value", req.GetGitCredential())
	}

	// Empty request: every git field reads as its zero value, so a caller
	// that never sets them (today's every existing caller) is unaffected.
	empty := &pb.RunAgentSkillRequest{SkillId: "code-review"}
	if empty.GetGitSource() != "" || empty.GetGitRef() != "" || empty.GetGitCredential() != "" {
		t.Errorf("unset git fields must read as empty, got source=%q ref=%q credential=%q",
			empty.GetGitSource(), empty.GetGitRef(), empty.GetGitCredential())
	}

	resp := &pb.RunAgentSkillResponse{
		RunId:         "run-1",
		ArtifactJson:  "{}",
		GitCommit:     "deadbeefcafe",
		WorkspacePath: "/workspace/runs/run-1",
	}
	if resp.GetGitCommit() != "deadbeefcafe" {
		t.Errorf("GetGitCommit() = %q, want the set value", resp.GetGitCommit())
	}
	if resp.GetWorkspacePath() != "/workspace/runs/run-1" {
		t.Errorf("GetWorkspacePath() = %q, want the set value", resp.GetWorkspacePath())
	}

	emptyResp := &pb.RunAgentSkillResponse{RunId: "run-1"}
	if emptyResp.GetGitCommit() != "" || emptyResp.GetWorkspacePath() != "" {
		t.Errorf("a run with no git_source must report empty git_commit/workspace_path, got commit=%q path=%q",
			emptyResp.GetGitCommit(), emptyResp.GetWorkspacePath())
	}
}

// TestProvisionSkillBox_GitSourceSet_SeedFailsBeforeFetch proves the design's
// ordering ("fetch after seed, before policy apply") from the side that is
// actually reachable in a unit test. Every fake backend fails the seed exec
// deterministically (see newSkillBoxHarness: (*container.Manager).Exec
// type-asserts to the concrete *incus.Client), so a provisionSkillBox call
// that carries a git_source and still fails with the SAME "failed to seed"
// error — not a git-fetch error — proves the fetch is gated behind a
// successful seed rather than racing ahead of it. The happy-path ordering
// (seed succeeds, THEN fetch runs, THEN policy applies) needs a real box and
// is covered by the e2e (#1861), the same limitation
// TestRunAgentSkill_ResponseCarriesRunID documents for the run itself.
func TestProvisionSkillBox_GitSourceSet_SeedFailsBeforeFetch(t *testing.T) {
	store := newFakeRevocationStore()
	s, skill := newSkillBoxHarness(t, store)

	_, _, lease, _, _, err := s.provisionSkillBox(ctxAs("admin", true), skill, "", "", "{}", "run-git",
		"https://github.com/org/repo", "main", "", "")
	if err == nil {
		t.Fatal("provisionSkillBox must fail when the seed exec fails, git_source or not")
	}
	if status.Code(err) != codes.Internal {
		t.Errorf("seed failure code = %v, want Internal (the seed step, not a git-fetch step)", status.Code(err))
	}
	if got := err.Error(); !strings.Contains(got, "failed to seed agent box") {
		t.Errorf("error = %q, want it to name the seed step (fetch must not run before a successful seed)", got)
	}
	if lease.RunID != "" || len(lease.Credentials) != 0 {
		t.Errorf("a failed provision must return no live lease, got %+v", lease)
	}
}

// TestProvisionSkillBox_NoGitSource_Unchanged is the same seed-failure
// regression with no git fields set, pinned beside the git-source case so a
// future reader can see both call shapes fail identically at the seed step.
func TestProvisionSkillBox_NoGitSource_Unchanged(t *testing.T) {
	store := newFakeRevocationStore()
	s, skill := newSkillBoxHarness(t, store)

	_, _, _, _, _, err := s.provisionSkillBox(ctxAs("admin", true), skill, "", "", "{}", "run-no-git", "", "", "", "")
	if status.Code(err) != codes.Internal {
		t.Errorf("seed failure code = %v, want Internal", status.Code(err))
	}
	if got := err.Error(); !strings.Contains(got, "failed to seed agent box") {
		t.Errorf("error = %q, want it to name the seed step", got)
	}
}
