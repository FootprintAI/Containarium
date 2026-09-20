package submit

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// testGit runs a real git command for test-fixture setup only — not the
// package under test's own hardened path, just plain git so the fixture
// looks like an ordinary repository a developer or agent would produce.
func testGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...) // #nosec G204 -- test-only, fixed argv, test tmp dirs.
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s (dir=%s): %v\n%s", strings.Join(args, " "), dir, err, out)
	}
	return strings.TrimSpace(string(out))
}

// TestGitPusher_RealGit_PushesToLocalBareRemote is an integration test
// (real git, no network — the "remote" is a local bare repository) that
// PushBundle's actual git plumbing, not just its argv/env shape, produces
// a correct result: given a bundle of one new commit on top of a base
// already present on the remote, the remote ends up with a new branch at
// exactly that commit, non-destructively (nothing else on the remote is
// touched).
func TestGitPusher_RealGit_PushesToLocalBareRemote(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	root := t.TempDir()
	originDir := filepath.Join(root, "origin.git")
	workDir := filepath.Join(root, "work")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatal(err)
	}

	testGit(t, root, "init", "--bare", "-q", originDir)
	testGit(t, workDir, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(workDir, "README.md"), []byte("base\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	testGit(t, workDir, "add", "README.md")
	testGit(t, workDir, "commit", "-q", "-m", "base commit")
	baseSHA := testGit(t, workDir, "rev-parse", "HEAD")
	testGit(t, workDir, "remote", "add", "origin", originDir)
	testGit(t, workDir, "push", "-q", "origin", "main")

	// The "agent's work": one new commit on top of base, never pushed to
	// origin directly — that's the whole point of the bundle path.
	if err := os.WriteFile(filepath.Join(workDir, "feature.txt"), []byte("new work\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	testGit(t, workDir, "add", "feature.txt")
	testGit(t, workDir, "commit", "-q", "-m", "agent's change")
	headSHA := testGit(t, workDir, "rev-parse", "HEAD")

	// The upper bound must be a ref ("HEAD"), not the resolved sha — git
	// bundle create needs a ref to advertise as the bundle's head, and
	// refuses "Refusing to create empty bundle" for a bare sha..sha
	// range even though the underlying commit range is non-empty.
	// Matches docs/architecture/agent-tracker-broker.md's own submit-path
	// pseudocode, which uses `<base>..HEAD` literally.
	bundlePath := filepath.Join(root, "out.bundle")
	testGit(t, workDir, "bundle", "create", bundlePath, baseSHA+"..HEAD")

	pusher := NewGitPusher()
	result, err := pusher.PushBundle(context.Background(), PushSpec{
		BundlePath:  bundlePath,
		BaseSHA:     baseSHA,
		HeadSHA:     headSHA,
		RemoteURL:   originDir,
		Credential:  "unused-for-local-file-remote",
		RunID:       "run-integration-test-0001",
		IssueNumber: 7,
		Title:       "Integration test change",
	})
	if err != nil {
		t.Fatalf("PushBundle: %v", err)
	}
	if result.SHA != headSHA {
		t.Errorf("result.SHA = %q, want %q", result.SHA, headSHA)
	}

	// Confirm the branch actually landed on the remote at the right sha,
	// and that main (the branch the agent never touched) is untouched.
	gotHead := testGit(t, root, "ls-remote", originDir, "refs/heads/"+result.Branch)
	if !strings.HasPrefix(gotHead, headSHA) {
		t.Errorf("remote ref for %s = %q, want it to start with %s", result.Branch, gotHead, headSHA)
	}
	gotMain := testGit(t, root, "ls-remote", originDir, "refs/heads/main")
	if !strings.HasPrefix(gotMain, baseSHA) {
		t.Errorf("remote main moved: %q, want it to still start with %s", gotMain, baseSHA)
	}
}
