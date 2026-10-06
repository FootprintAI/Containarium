package server

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/runlease"
	containerpkg "github.com/footprintai/containarium/pkg/core/container"
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
// ordering ("fetch after seed, before policy apply") from the failure side.
// Every fake backend fails the seed exec deterministically (see
// newSkillBoxHarness: (*container.Manager).Exec type-asserts to the concrete
// *incus.Client), so a provisionSkillBox call that carries a git_source and
// still fails with the SAME "failed to seed" error — not a git-fetch error —
// proves the fetch is gated behind a successful seed rather than racing ahead
// of it. The fetch's own three outcomes, with the seed succeeding, are
// covered through the boxOps seam by TestProvisionSkillBox_GitFetch (#2161).
func TestProvisionSkillBox_GitSourceSet_SeedFailsBeforeFetch(t *testing.T) {
	store := newFakeRevocationStore()
	s, skill := newSkillBoxHarness(t, store)

	_, _, lease, _, _, _, err := s.provisionSkillBox(ctxAs("admin", true), skill, "", "", "{}", "run-git",
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

	_, _, _, _, _, _, err := s.provisionSkillBox(ctxAs("admin", true), skill, "", "", "{}", "run-no-git", "", "", "", "")
	if status.Code(err) != codes.Internal {
		t.Errorf("seed failure code = %v, want Internal", status.Code(err))
	}
	if got := err.Error(); !strings.Contains(got, "failed to seed agent box") {
		t.Errorf("error = %q, want it to name the seed step", got)
	}
}

// fakeAgentBox stands in for the container manager behind the boxOps seam:
// every Exec succeeds and is recorded, and FetchGitSource returns what the
// test configured.
type fakeAgentBox struct {
	mu       sync.Mutex
	execs    [][]string
	fetches  []containerpkg.GitSourceSpec
	commit   string
	fetchErr error
}

func (f *fakeAgentBox) Exec(_ string, cmd []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.execs = append(f.execs, cmd)
	return nil
}

func (f *fakeAgentBox) FetchGitSource(_ string, spec containerpkg.GitSourceSpec) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fetches = append(f.fetches, spec)
	return f.commit, f.fetchErr
}

// ranScriptContaining reports whether any `bash -c` script the box ran
// contains sub.
func (f *fakeAgentBox) ranScriptContaining(sub string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.execs {
		if len(c) == 3 && c[0] == "bash" && strings.Contains(c[2], sub) {
			return true
		}
	}
	return false
}

// removed reports whether the box ran an `rm -rf` naming path.
func (f *fakeAgentBox) removed(path string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.execs {
		if len(c) > 2 && c[0] == "rm" && c[1] == "-rf" && slices.Contains(c[2:], path) {
			return true
		}
	}
	return false
}

// TestProvisionSkillBox_GitFetch covers the three outcomes of the run's git
// fetch in provisionSkillBoxWith (#2161): success, a failure tolerated by a
// best-effort run (tracker dispatch), and a failure that ends the run. The
// seed has to succeed to get there, which no fake incus backend allows, so
// the box is replaced through the boxOps seam.
func TestProvisionSkillBox_GitFetch(t *testing.T) {
	const (
		runID  = "run-fetch"
		source = "https://github.com/org/repo"
		ref    = "main"
		cred   = "ghs_secret"
		commit = "deadbeefcafe"
	)
	workspace := workspaceDirFor(runID)

	type outcome struct {
		lease     runlease.Lease
		commit    string
		workspace string
		revoked   []string // revocation reasons, one per credential revoked
		err       error
	}
	provision := func(t *testing.T, box *fakeAgentBox, opts provisionOptions) outcome {
		t.Helper()
		store := newFakeRevocationStore()
		s, skill := newSkillBoxHarness(t, store)
		s.boxOps = box
		var o outcome
		_, _, o.lease, o.commit, o.workspace, _, o.err = s.provisionSkillBoxWith(ctxAs("admin", true), skill, "", "", "{}", runID,
			source, ref, cred, "", opts)
		revoked, err := store.List(context.Background(), auth.ListRevocationsParams{})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		for _, r := range revoked {
			o.revoked = append(o.revoked, r.Reason)
		}
		return o
	}

	t.Run("success records the commit and keeps the workspace", func(t *testing.T) {
		box := &fakeAgentBox{commit: commit}
		o := provision(t, box, provisionOptions{})
		if o.err != nil {
			t.Fatalf("provisionSkillBoxWith: %v", o.err)
		}
		if o.commit != commit {
			t.Errorf("gitCommit = %q, want %q", o.commit, commit)
		}
		if o.workspace != workspace || o.lease.Workspace != workspace {
			t.Errorf("workspacePath = %q, lease.Workspace = %q; want both %q", o.workspace, o.lease.Workspace, workspace)
		}
		want := containerpkg.GitSourceSpec{Source: source, Ref: ref, Credential: cred, WorkspacePath: workspace}
		if len(box.fetches) != 1 || box.fetches[0] != want {
			t.Errorf("fetches = %+v, want exactly %+v", box.fetches, want)
		}
		if !box.ranScriptContaining("/workspace.json") {
			t.Error("no workspace.json written after a successful fetch")
		}
		if len(o.lease.Credentials) == 0 {
			t.Error("the returned lease carries no credentials; the run's lease must stay live")
		}
		if len(o.revoked) != 0 {
			t.Errorf("revoked %v on a successful provision, want none", o.revoked)
		}
	})

	t.Run("best-effort failure continues without a workspace", func(t *testing.T) {
		box := &fakeAgentBox{fetchErr: errors.New("git fetch in box failed: exit status 128: repository not found")}
		o := provision(t, box, provisionOptions{gitSourceBestEffort: true})
		if o.err != nil {
			t.Fatalf("a best-effort run must survive a fetch failure, got %v", o.err)
		}
		if o.workspace != "" || o.commit != "" {
			t.Errorf("workspacePath = %q, gitCommit = %q; want both empty for a run with no checkout", o.workspace, o.commit)
		}
		if o.lease.Workspace != workspace {
			t.Errorf("lease.Workspace = %q, want %q: the fetch's empty dir must stay on the lease so ending it removes the dir", o.lease.Workspace, workspace)
		}
		if box.ranScriptContaining("/workspace.json") {
			t.Error("workspace.json written for a fetch that failed")
		}
		if len(o.lease.Credentials) == 0 {
			t.Error("the returned lease carries no credentials; the run's lease must stay live")
		}
		if len(o.revoked) != 0 {
			t.Errorf("revoked %v on a tolerated fetch failure, want none", o.revoked)
		}
		if box.removed(workspace) {
			t.Error("workspace removed while the run is still live")
		}
	})

	t.Run("failure ends the run lease and returns FailedPrecondition", func(t *testing.T) {
		box := &fakeAgentBox{fetchErr: errors.New("git fetch in box failed: exit status 128: repository not found")}
		o := provision(t, box, provisionOptions{})
		if status.Code(o.err) != codes.FailedPrecondition {
			t.Fatalf("err = %v, want FailedPrecondition", o.err)
		}
		if !strings.Contains(o.err.Error(), "git fetch into agent box") {
			t.Errorf("error = %q, want it to name the git fetch step", o.err)
		}
		if o.lease.RunID != "" || len(o.lease.Credentials) != 0 {
			t.Errorf("a failed provision must return no live lease, got %+v", o.lease)
		}
		// endRunLease runs synchronously, so what it did is already done.
		reasons := o.revoked
		if len(reasons) != 2 {
			t.Fatalf("revoked %d credential(s), want both the platform JWT and the gateway token", len(reasons))
		}
		for _, r := range reasons {
			if r != provisionFailedReason {
				t.Errorf("revocation reason %q, want %q", r, provisionFailedReason)
			}
		}
		if !box.removed(workspace) {
			t.Errorf("ending the lease did not remove %s; the fetch's empty dir would be left behind", workspace)
		}
		if box.ranScriptContaining("/workspace.json") {
			t.Error("workspace.json written for a fetch that failed")
		}
	})
}
