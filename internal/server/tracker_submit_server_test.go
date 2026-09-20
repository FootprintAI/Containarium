package server

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/runlease"
	"github.com/footprintai/containarium/internal/tracker"
	"github.com/footprintai/containarium/internal/tracker/submit"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeSubmitBox is a submit.BoxRunner test double standing in for a
// real box: ExecWithOutput answers ExtractBundle's two scripted calls
// (bundle create + rev-parse, then stat/wc) without running anything,
// and ReadFile returns pre-built bundle bytes.
type fakeSubmitBox struct {
	bundleBytes []byte
	headSHA     string
	execErr     error
}

func (f *fakeSubmitBox) ExecWithOutput(_ string, cmd []string) (string, string, error) {
	if f.execErr != nil {
		return "", "boom", f.execErr
	}
	script := strings.Join(cmd, " ")
	if strings.Contains(script, "stat -c") || strings.Contains(script, "wc -c") {
		return strconv.Itoa(len(f.bundleBytes)), "", nil
	}
	return f.headSHA + "\n", "", nil
}

func (f *fakeSubmitBox) ReadFile(_ string, _ string) ([]byte, error) {
	return f.bundleBytes, nil
}

// fakeSubmitPusher is a submit.GitPusher test double recording the
// PushSpec it was called with and returning a canned result.
type fakeSubmitPusher struct {
	gotSpec submit.PushSpec
	result  submit.PushResult
	err     error
}

func (f *fakeSubmitPusher) PushBundle(_ context.Context, spec submit.PushSpec) (submit.PushResult, error) {
	f.gotSpec = spec
	return f.result, f.err
}

// realBundleBytes builds an actual git bundle (base commit + one commit
// on top, bundled as base..HEAD) so tests exercising the happy path
// pass through ExtractBundle's real `git bundle list-heads` validation
// rather than a hand-rolled fixture that might not match git's format.
func realBundleBytes(t *testing.T) (bundle []byte, headSHA string) {
	t.Helper()
	dir := t.TempDir()
	runGitFixture(t, dir, "init", "-q", "-b", "main")
	runGitFixture(t, dir, "config", "user.email", "t@example.com")
	runGitFixture(t, dir, "config", "user.name", "t")
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("base"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGitFixture(t, dir, "add", "f.txt")
	runGitFixture(t, dir, "commit", "-q", "-m", "base")
	base := strings.TrimSpace(runGitFixtureOutput(t, dir, "rev-parse", "HEAD"))
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("head"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGitFixture(t, dir, "add", "f.txt")
	runGitFixture(t, dir, "commit", "-q", "-m", "head")
	headSHA = strings.TrimSpace(runGitFixtureOutput(t, dir, "rev-parse", "HEAD"))
	bundlePath := filepath.Join(dir, "out.bundle")
	runGitFixture(t, dir, "bundle", "create", bundlePath, base+"..HEAD")
	b, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	return b, headSHA
}

func runGitFixture(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...) //nolint:gosec // test-only, fixed argv
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func runGitFixtureOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...) //nolint:gosec // test-only, fixed argv
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %s: %v", strings.Join(args, " "), err)
	}
	return string(out)
}

func TestSubmitTrackerChange_NoAuthContext(t *testing.T) {
	s := &ContainerServer{}
	_, err := s.SubmitTrackerChange(context.Background(), &pb.SubmitTrackerChangeRequest{
		Username: "alice", Connection: "default", Issue: 1, Title: "t",
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want Unauthenticated", status.Code(err))
	}
}

func TestSubmitTrackerChange_TrackerReadScopeInsufficient(t *testing.T) {
	s := &ContainerServer{}
	ctx := kmsKeyTestCtx("alice", "member", "tracker:read")
	_, err := s.SubmitTrackerChange(ctx, &pb.SubmitTrackerChangeRequest{
		Username: "alice", Connection: "default", Issue: 1, Title: "t",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied (tracker:read must not grant a write verb)", status.Code(err))
	}
}

func TestSubmitTrackerChange_NoTrackerStoreConfigured(t *testing.T) {
	s := &ContainerServer{}
	ctx := kmsKeyTestCtx("alice", "member", "tracker:write")
	_, err := s.SubmitTrackerChange(ctx, &pb.SubmitTrackerChangeRequest{
		Username: "alice", Connection: "default", Issue: 1, Title: "t",
	})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", status.Code(err))
	}
}

func TestSubmitTrackerChange_RejectsMissingIssue(t *testing.T) {
	s := &ContainerServer{trackerStore: mustTestTrackerStore(t)}
	ctx := kmsKeyTestCtx("alice", "member", "tracker:write")
	_, err := s.SubmitTrackerChange(ctx, &pb.SubmitTrackerChangeRequest{
		Username: "alice", Connection: "default", Title: "t",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument (missing issue)", status.Code(err))
	}
}

func TestSubmitTrackerChange_RejectsMissingTitle(t *testing.T) {
	s := &ContainerServer{trackerStore: mustTestTrackerStore(t)}
	ctx := kmsKeyTestCtx("alice", "member", "tracker:write")
	_, err := s.SubmitTrackerChange(ctx, &pb.SubmitTrackerChangeRequest{
		Username: "alice", Connection: "default", Issue: 1,
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument (missing title)", status.Code(err))
	}
}

func TestSubmitTrackerChange_CrossTenantDenied(t *testing.T) {
	s := &ContainerServer{trackerStore: mustTestTrackerStore(t)}
	ctx := kmsKeyTestCtx("mallory", "member", "tracker:write")
	_, err := s.SubmitTrackerChange(ctx, &pb.SubmitTrackerChangeRequest{
		Username: "alice", Connection: "default", Issue: 1, Title: "t",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied (cross-tenant)", status.Code(err))
	}
}

// validRunInfo is the runlease.Info a well-formed run-scoped submit
// resolves against — same run id setUpWriterConnection's context
// already carries ("run-abc123"), matching a run WITH a git_source.
func validRunInfo() runlease.Info {
	return runlease.Info{
		SkillID:   "code-review",
		Box:       "agent-box-1",
		GitCommit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Workspace: "/workspace/runs/run-abc123",
		GitRef:    "main",
	}
}

// setUpSubmitConnection layers #1923's box/pusher wiring and a
// registered run onto setUpWriterConnection's tracker connection setup.
// info nil means "don't register the run at all" (RunNotFound case).
func setUpSubmitConnection(t *testing.T, user string, provider *fakeWriterProvider, box *fakeSubmitBox, pusher *fakeSubmitPusher, info *runlease.Info) (*ContainerServer, context.Context) {
	t.Helper()
	s, ctx := setUpWriterConnection(t, user, provider)
	reg := runlease.NewRegistry()
	if info != nil {
		reg.Register("run-abc123", *info)
	}
	s.runRegistry = reg
	// A nil *fakeSubmitBox/*fakeSubmitPusher assigned into these
	// interface-typed fields would be a NON-nil interface wrapping a
	// nil pointer (the same typed-nil pitfall boxRunnerForSubmit's own
	// doc comment warns about in production) — panicking the first
	// time a method is called on it instead of falling through to the
	// "not configured" checks these fields exist to test. Guard here so
	// passing nil really means "leave it unset".
	if box != nil {
		s.submitBoxRunner = box
	}
	if pusher != nil {
		s.submitPusher = pusher
	}
	return s, ctx
}

func TestSubmitTrackerChange_RequiresRunScopedToken(t *testing.T) {
	const user = "tracker-rpc-submit-no-run"
	provider := &fakeWriterProvider{}
	s, _ := setUpWriterConnection(t, user, provider)
	// An operator context — same scopes, no run_id claim.
	ctx := kmsKeyTestCtx(user, "member", "tracker:write")

	_, err := s.SubmitTrackerChange(ctx, &pb.SubmitTrackerChangeRequest{
		Username: user, Connection: "default", Issue: 1, Title: "t",
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition (no run_id claim)", status.Code(err))
	}
}

func TestSubmitTrackerChange_NoRunRegistryConfigured(t *testing.T) {
	const user = "tracker-rpc-submit-no-registry"
	provider := &fakeWriterProvider{}
	s, ctx := setUpWriterConnection(t, user, provider) // s.runRegistry left nil

	_, err := s.SubmitTrackerChange(ctx, &pb.SubmitTrackerChangeRequest{
		Username: user, Connection: "default", Issue: 1, Title: "t",
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition (no run registry configured)", status.Code(err))
	}
}

func TestSubmitTrackerChange_RunNotFound(t *testing.T) {
	const user = "tracker-rpc-submit-run-not-found"
	provider := &fakeWriterProvider{}
	s, ctx := setUpSubmitConnection(t, user, provider, nil, nil, nil) // no run registered

	_, err := s.SubmitTrackerChange(ctx, &pb.SubmitTrackerChangeRequest{
		Username: user, Connection: "default", Issue: 1, Title: "t",
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition (run not found)", status.Code(err))
	}
}

func TestSubmitTrackerChange_RunHasNoGitSource(t *testing.T) {
	const user = "tracker-rpc-submit-no-git-source"
	provider := &fakeWriterProvider{}
	noGitSource := runlease.Info{SkillID: "code-review", Box: "agent-box-1"} // GitCommit/Workspace empty
	s, ctx := setUpSubmitConnection(t, user, provider, nil, nil, &noGitSource)

	_, err := s.SubmitTrackerChange(ctx, &pb.SubmitTrackerChangeRequest{
		Username: user, Connection: "default", Issue: 1, Title: "t",
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition (run has no git_source)", status.Code(err))
	}
}

func TestSubmitTrackerChange_NoContainerManagerConfigured(t *testing.T) {
	const user = "tracker-rpc-submit-no-manager"
	provider := &fakeWriterProvider{}
	info := validRunInfo()
	// box is nil AND s.manager is nil (setUpWriterConnection never sets
	// it) — boxRunnerForSubmit must return nil, not a typed-nil panic.
	s, ctx := setUpSubmitConnection(t, user, provider, nil, nil, &info)

	_, err := s.SubmitTrackerChange(ctx, &pb.SubmitTrackerChangeRequest{
		Username: user, Connection: "default", Issue: 1, Title: "t",
	})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable (no container manager configured)", status.Code(err))
	}
}

func TestSubmitTrackerChange_HostGitMissingOrTooOld(t *testing.T) {
	const user = "tracker-rpc-submit-no-git"
	provider := &fakeWriterProvider{}
	info := validRunInfo()
	box := &fakeSubmitBox{}
	s, ctx := setUpSubmitConnection(t, user, provider, box, &fakeSubmitPusher{}, &info)

	// An empty-but-existing PATH directory: exec.LookPath("git") fails
	// deterministically without depending on what's actually installed
	// on the machine running this test.
	t.Setenv("PATH", t.TempDir())

	_, err := s.SubmitTrackerChange(ctx, &pb.SubmitTrackerChangeRequest{
		Username: user, Connection: "default", Issue: 1, Title: "t",
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition (git missing)", status.Code(err))
	}
}

func TestSubmitTrackerChange_BundleTooLarge(t *testing.T) {
	const user = "tracker-rpc-submit-bundle-too-large"
	provider := &fakeWriterProvider{}
	info := validRunInfo()
	bundleBytes, headSHA := realBundleBytes(t)
	box := &fakeSubmitBox{bundleBytes: bundleBytes, headSHA: headSHA}
	// Force ExtractBundle's in-box size check to report far more than
	// the real (tiny) fixture bundle actually is, without needing an
	// actual 50MB+ payload in a test.
	box.bundleBytes = make([]byte, submitTestOverCap)
	s, ctx := setUpSubmitConnection(t, user, provider, box, &fakeSubmitPusher{}, &info)

	_, err := s.SubmitTrackerChange(ctx, &pb.SubmitTrackerChangeRequest{
		Username: user, Connection: "default", Issue: 1, Title: "t",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument (bundle over size cap)", status.Code(err))
	}
}

// submitTestOverCap is deliberately larger than submit.DefaultMaxBundleBytes
// without actually allocating 50MB+ of real bundle content elsewhere in
// this file — fakeSubmitBox's stat step reports len(bundleBytes)
// directly, so an all-zero slice of this size is enough to exercise the
// cap check.
const submitTestOverCap = 51 * 1024 * 1024

func TestSubmitTrackerChange_PushFails(t *testing.T) {
	const user = "tracker-rpc-submit-push-fails"
	provider := &fakeWriterProvider{}
	info := validRunInfo()
	bundleBytes, headSHA := realBundleBytes(t)
	box := &fakeSubmitBox{bundleBytes: bundleBytes, headSHA: headSHA}
	pusher := &fakeSubmitPusher{err: errors.New("push failed: connection refused")}
	s, ctx := setUpSubmitConnection(t, user, provider, box, pusher, &info)

	_, err := s.SubmitTrackerChange(ctx, &pb.SubmitTrackerChangeRequest{
		Username: user, Connection: "default", Issue: 1, Title: "t",
	})
	if status.Code(err) != codes.Internal {
		t.Fatalf("code = %v, want Internal (push failure)", status.Code(err))
	}
}

func TestSubmitTrackerChange_OpenChangeFails(t *testing.T) {
	const user = "tracker-rpc-submit-openchange-fails"
	provider := &fakeWriterProvider{openChangeErr: tracker.ErrCredentialInvalid}
	info := validRunInfo()
	bundleBytes, headSHA := realBundleBytes(t)
	box := &fakeSubmitBox{bundleBytes: bundleBytes, headSHA: headSHA}
	pusher := &fakeSubmitPusher{result: submit.PushResult{Branch: "agent/run-abc123de/1-t", SHA: headSHA}}
	s, ctx := setUpSubmitConnection(t, user, provider, box, pusher, &info)

	_, err := s.SubmitTrackerChange(ctx, &pb.SubmitTrackerChangeRequest{
		Username: user, Connection: "default", Issue: 1, Title: "t",
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition (credential rejected)", status.Code(err))
	}
}

// TestSubmitTrackerChange_HappyPath exercises the whole pipeline end to
// end with fakes standing in for the box and the git push: extract a
// real bundle, "push" it (recording the PushSpec for inspection),
// "open" the change (fakeWriterProvider records the OpenChangeRequest),
// and check the response and what each fake was actually called with.
func TestSubmitTrackerChange_HappyPath(t *testing.T) {
	const user = "tracker-rpc-submit-happy"
	bundleBytes, headSHA := realBundleBytes(t)
	wantBranch := "agent/run-abc123de/1-conformance-change"
	provider := &fakeWriterProvider{
		openChangeOut: tracker.Change{Number: 6, URL: "https://github.com/acme/widgets/pull/6"},
	}
	info := validRunInfo()
	box := &fakeSubmitBox{bundleBytes: bundleBytes, headSHA: headSHA}
	pusher := &fakeSubmitPusher{result: submit.PushResult{Branch: wantBranch, SHA: headSHA}}
	s, ctx := setUpSubmitConnection(t, user, provider, box, pusher, &info)

	resp, err := s.SubmitTrackerChange(ctx, &pb.SubmitTrackerChangeRequest{
		Username: user, Connection: "default", Issue: 1, Title: "My change", Description: "does the thing",
	})
	if err != nil {
		t.Fatalf("SubmitTrackerChange: %v", err)
	}
	if resp.GetChange().GetNumber() != 6 {
		t.Errorf("response change number = %d, want 6", resp.GetChange().GetNumber())
	}
	if resp.GetChange().GetUrl() != "https://github.com/acme/widgets/pull/6" {
		t.Errorf("response change url = %q, want the provider's URL echoed", resp.GetChange().GetUrl())
	}

	// PushBundle must have been called with the run's actual recorded
	// base commit and the bundle's actual resolved head — never guessed
	// or left zero.
	if pusher.gotSpec.BaseSHA != info.GitCommit {
		t.Errorf("PushSpec.BaseSHA = %q, want %q", pusher.gotSpec.BaseSHA, info.GitCommit)
	}
	if pusher.gotSpec.HeadSHA != headSHA {
		t.Errorf("PushSpec.HeadSHA = %q, want %q", pusher.gotSpec.HeadSHA, headSHA)
	}
	if pusher.gotSpec.RunID != "run-abc123" {
		t.Errorf("PushSpec.RunID = %q, want run-abc123", pusher.gotSpec.RunID)
	}
	if pusher.gotSpec.Credential == "" {
		t.Error("PushSpec.Credential is empty — the resolved broker credential must reach GitPusher")
	}

	// OpenChange must be called with the PUSHED branch (from GitPusher's
	// result), the daemon-resolved base branch, and a description
	// carrying the closing reference and the platform stamp — never the
	// raw, unstamped request description.
	if provider.openChangeReq.HeadBranch != wantBranch {
		t.Errorf("OpenChangeRequest.HeadBranch = %q, want %q (the pushed branch, not re-derived)", provider.openChangeReq.HeadBranch, wantBranch)
	}
	if provider.openChangeReq.BaseBranch != "main" {
		t.Errorf("OpenChangeRequest.BaseBranch = %q, want %q (the run's recorded GitRef)", provider.openChangeReq.BaseBranch, "main")
	}
	if !strings.Contains(provider.openChangeReq.Description, "Closes #1") {
		t.Errorf("OpenChangeRequest.Description = %q, want it to contain the closing reference", provider.openChangeReq.Description)
	}
	if !strings.Contains(provider.openChangeReq.Description, "does the thing") {
		t.Errorf("OpenChangeRequest.Description = %q, want the caller's own description", provider.openChangeReq.Description)
	}
	if !strings.Contains(provider.openChangeReq.Description, "via Containarium") {
		t.Errorf("OpenChangeRequest.Description = %q, want the platform stamp", provider.openChangeReq.Description)
	}
}
