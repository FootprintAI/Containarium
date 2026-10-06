package server

import (
	"errors"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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

// fakeSkillBoxOps stands in for *container.Manager behind the skillBoxOps
// seam, so provisionSkillBox gets past the seed exec (which always fails on a
// fake incus backend) and reaches the git-fetch branch (#1859/#1860). Every
// Exec succeeds and is recorded — that covers the seed, the workspace.json
// seed, and runlease.End's wipe/rm-rf, since boxWiper returns the same seam.
type fakeSkillBoxOps struct {
	commit   string
	fetchErr error

	mu      sync.Mutex
	execs   [][]string
	fetches []containerpkg.GitSourceSpec
}

func (f *fakeSkillBoxOps) Exec(_ string, cmd []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.execs = append(f.execs, cmd)
	return nil
}

func (f *fakeSkillBoxOps) FetchGitSource(_ string, spec containerpkg.GitSourceSpec) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fetches = append(f.fetches, spec)
	return f.commit, f.fetchErr
}

// removed reports whether an `rm -rf` exec targeted dir — the step
// runlease.End uses to remove a lease's seed dir and workspace.
func (f *fakeSkillBoxOps) removed(dir string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, cmd := range f.execs {
		if len(cmd) < 2 || cmd[0] != "rm" {
			continue
		}
		for _, arg := range cmd[2:] {
			if arg == dir {
				return true
			}
		}
	}
	return false
}

func (f *fakeSkillBoxOps) execCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.execs)
}

func newGitFetchHarness(t *testing.T, ops *fakeSkillBoxOps) (*AgentSkillServer, *pb.AgentSkill, *fakeRevocationStore, *fakeAuditLogger) {
	t.Helper()
	store := newFakeRevocationStore()
	s, skill := newSkillBoxHarness(t, store)
	audits := &fakeAuditLogger{}
	s.audit = audits
	s.boxOps = ops
	return s, skill, store, audits
}

// TestProvisionSkillBox_GitFetch_Success: path 1 of the git-fetch branch. The
// fetch returns a commit, so the run carries it and keeps its workspace, the
// fetch is pointed at this run's own workspace dir, the workspace.json seed is
// written, and nothing is revoked or removed.
func TestProvisionSkillBox_GitFetch_Success(t *testing.T) {
	ops := &fakeSkillBoxOps{commit: "deadbeefcafe"}
	s, skill, store, _ := newGitFetchHarness(t, ops)
	const runID = "run-git-ok"

	_, _, lease, commit, workspace, err := s.provisionSkillBox(ctxAs("admin", true), skill, "", "", "{}", runID,
		"https://github.com/org/repo", "main", "ghs_secret", "")
	if err != nil {
		t.Fatalf("provisionSkillBox: %v", err)
	}
	if commit != "deadbeefcafe" {
		t.Errorf("gitCommit = %q, want the fetched commit", commit)
	}
	if want := workspaceDirFor(runID); workspace != want || lease.Workspace != want {
		t.Errorf("workspacePath = %q, lease.Workspace = %q, want both %q", workspace, lease.Workspace, want)
	}
	if len(ops.fetches) != 1 {
		t.Fatalf("FetchGitSource called %d time(s), want 1", len(ops.fetches))
	}
	want := containerpkg.GitSourceSpec{
		Source: "https://github.com/org/repo", Ref: "main", Credential: "ghs_secret", WorkspacePath: workspaceDirFor(runID),
	}
	if ops.fetches[0] != want {
		t.Errorf("fetch spec = %+v, want %+v", ops.fetches[0], want)
	}
	if n := ops.execCount(); n != 2 {
		t.Errorf("exec count = %d, want 2 (the seed, then the workspace.json seed)", n)
	}
	if ops.removed(workspaceDirFor(runID)) {
		t.Error("a successful provision must not remove the run's workspace")
	}
	if got := listRevocations(t, store); len(got) != 0 {
		t.Errorf("a successful provision must revoke nothing, got %+v", got)
	}
}

// TestProvisionSkillBox_GitFetch_FailureBestEffort: path 2. A best-effort run
// (a tracker-dispatched run, #2023) logs the fetch failure and continues with
// no workspace and no commit — but the (empty) workspace dir the failed fetch
// left on disk stays on the lease (#1871), so ending the lease removes it.
func TestProvisionSkillBox_GitFetch_FailureBestEffort(t *testing.T) {
	ops := &fakeSkillBoxOps{fetchErr: errors.New("git fetch in box failed: exit status 128: repository not found")}
	s, skill, store, _ := newGitFetchHarness(t, ops)
	const runID = "run-git-best-effort"

	_, _, lease, commit, workspace, err := s.provisionSkillBoxWith(ctxAs("admin", true), skill, "", "", "{}", runID,
		"https://github.com/org/private", "main", "", "", provisionOptions{gitSourceBestEffort: true})
	if err != nil {
		t.Fatalf("a best-effort fetch failure must not fail the provision, got %v", err)
	}
	if commit != "" || workspace != "" {
		t.Errorf("gitCommit = %q, workspacePath = %q, want both empty (the run proceeds without a workspace)", commit, workspace)
	}
	if lease.RunID != runID || len(lease.Credentials) == 0 {
		t.Errorf("the run must proceed with a live lease, got %+v", lease)
	}
	if lease.Workspace != workspaceDirFor(runID) {
		t.Errorf("lease.Workspace = %q, want %q (the failed fetch's dir stays on the lease for cleanup)", lease.Workspace, workspaceDirFor(runID))
	}
	if n := ops.execCount(); n != 1 {
		t.Errorf("exec count = %d, want 1 (the seed only — no workspace.json for a failed fetch)", n)
	}
	if got := listRevocations(t, store); len(got) != 0 {
		t.Errorf("a best-effort failure must not end the lease, but revoked %+v", got)
	}

	// Ending the lease — RunAgentSkill's defer, in production — removes the
	// workspace dir the failed fetch left behind.
	s.endRunLease(ctxAs("admin", true), lease, s.boxWiper(), runExitReason)
	if !ops.removed(workspaceDirFor(runID)) {
		t.Errorf("ending the lease must rm -rf %s, execs: %+v", workspaceDirFor(runID), ops.execs)
	}
}

// TestProvisionSkillBox_GitFetch_FailureNotBestEffort: path 3. Without
// best-effort, a fetch failure ends the partial lease — revoking the minted
// credentials and removing the workspace dir — and returns FailedPrecondition.
func TestProvisionSkillBox_GitFetch_FailureNotBestEffort(t *testing.T) {
	ops := &fakeSkillBoxOps{fetchErr: errors.New("git fetch in box failed: exit status 128: repository not found")}
	s, skill, store, audits := newGitFetchHarness(t, ops)
	const runID = "run-git-fail"

	_, _, lease, commit, workspace, err := s.provisionSkillBox(ctxAs("admin", true), skill, "", "", "{}", runID,
		"https://github.com/org/private", "main", "", "")
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v, want FailedPrecondition", err)
	}
	if !strings.Contains(err.Error(), "git fetch into agent box") {
		t.Errorf("error = %q, want it to name the git-fetch step", err.Error())
	}
	if lease.RunID != "" || len(lease.Credentials) != 0 || commit != "" || workspace != "" {
		t.Errorf("a failed provision must return no lease/commit/workspace, got lease=%+v commit=%q workspace=%q", lease, commit, workspace)
	}

	// endRunLease ran before the return: both credentials revoked, the
	// workspace removed, and the end row audited.
	revoked := listRevocations(t, store)
	if len(revoked) != 2 {
		t.Fatalf("revoked %d credential(s), want both the platform JWT and the gateway token: %+v", len(revoked), revoked)
	}
	for _, r := range revoked {
		if r.Reason != provisionFailedReason {
			t.Errorf("jti %s revoked with reason %q, want %q", r.JTI, r.Reason, provisionFailedReason)
		}
	}
	if !ops.removed(workspaceDirFor(runID)) {
		t.Errorf("ending the lease must rm -rf %s, execs: %+v", workspaceDirFor(runID), ops.execs)
	}
	if ends := audits.byAction("agent.run_lease_end"); len(ends) != 1 {
		t.Errorf("agent.run_lease_end rows = %d, want 1", len(ends))
	}
	if issues := audits.byAction("agent.run_lease_issue"); len(issues) != 0 {
		t.Errorf("a failed provision must not audit a lease issue, got %d row(s)", len(issues))
	}
}
