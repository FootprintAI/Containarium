package submit

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// localBox implements BoxRunner by running the script for real, locally
// — standing in for "exec inside the box" without needing incus. Good
// enough for this test's purpose: proving ExtractBundle's script, run
// against a REAL (hostile) git repository, behaves the same way it
// would inside a box. Every path ExtractBundle's script touches is
// already absolute (the workspace dir, the fixed remote bundle path),
// so this type needs no root of its own.
type localBox struct{}

func (b *localBox) ExecWithOutput(_ string, command []string) (string, string, error) {
	// command is ["/bin/sh", "-c", script] — run it for real.
	// #nosec G204 -- test-only, command built by this package's own code
	// under test, not from untrusted input reaching this test binary.
	cmd := exec.Command(command[0], command[1:]...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

func (b *localBox) ReadFile(_ string, path string) ([]byte, error) {
	return os.ReadFile(path)
}

// TestSubmit_HostileRepo is the integration test named in the design
// note's test strategy: a workspace whose .git/config and hooks try to
// capture the push credential or redirect the push elsewhere. It
// exercises ExtractBundle and GitPusher.PushBundle TOGETHER, real git,
// no network (the tracker's "remote" is a local bare repository).
//
// The hooks/config below are deliberately the ones the design doc calls
// out by name: pre-push, credential.helper, url.<x>.insteadOf,
// http.proxy. None of them should ever fire, for two independent
// reasons this test checks separately:
//   - git bundle create (what ExtractBundle runs INSIDE the hostile
//     workspace) does no network I/O and does not invoke push hooks —
//     hostile config there has nothing to attach to.
//   - GitPusher.PushBundle never runs a single git command inside the
//     hostile workspace's .git directory at all — it builds its own
//     fresh bare repository elsewhere with GIT_CONFIG_NOSYSTEM=1,
//     GIT_CONFIG_GLOBAL=/dev/null, and its own HOME, so the hostile
//     workspace's config is never even on a path git would consult.
func TestSubmit_HostileRepo(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hook scripts below assume a POSIX shell")
	}

	root := t.TempDir()
	originDir := filepath.Join(root, "origin.git")
	decoyDir := filepath.Join(root, "decoy.git")
	workDir := filepath.Join(root, "work")
	sinkPath := filepath.Join(root, "sink.txt")

	testGit(t, root, "init", "--bare", "-q", originDir)
	testGit(t, root, "init", "--bare", "-q", decoyDir)

	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatal(err)
	}
	testGit(t, workDir, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(workDir, "README.md"), []byte("base\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	testGit(t, workDir, "add", "README.md")
	testGit(t, workDir, "commit", "-q", "-m", "base commit")
	baseSHA := testGit(t, workDir, "rev-parse", "HEAD")
	testGit(t, workDir, "remote", "add", "origin", originDir)
	testGit(t, workDir, "push", "-q", "origin", "main")

	if err := os.WriteFile(filepath.Join(workDir, "feature.txt"), []byte("agent work\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	testGit(t, workDir, "add", "feature.txt")
	testGit(t, workDir, "commit", "-q", "-m", "agent's change")

	// --- Plant the hostile config and hooks. ---
	credential := "top-secret-broker-credential"

	// pre-push hook: if it ever ran, it would capture argv/stdin.
	hooksDir := filepath.Join(workDir, ".git", "hooks")
	prePush := "#!/bin/sh\n" +
		"{ echo \"pre-push ran: $@\"; cat; } >> " + shellSingleQuote(sinkPath) + "\n" +
		"exit 0\n"
	writeExecutable(t, filepath.Join(hooksDir, "pre-push"), prePush)

	// credential.helper: if ever invoked, captures whatever git asks it
	// to fill in, plus checks the environment for the real credential.
	helperScript := filepath.Join(workDir, "capture-credential-helper.sh")
	writeExecutable(t, helperScript, "#!/bin/sh\n"+
		"echo \"credential helper ran\" >> "+shellSingleQuote(sinkPath)+"\n"+
		"env | grep -i "+shellSingleQuote("GIT_CONFIG_VALUE")+" >> "+shellSingleQuote(sinkPath)+" || true\n"+
		"exit 0\n")
	testGit(t, workDir, "config", "credential.helper", helperScript)

	// url.<decoy>.insteadOf origin: try to redirect any push at origin to
	// the decoy repo instead.
	testGit(t, workDir, "config", "url."+decoyDir+".insteadOf", originDir)

	// http.proxy: point at a bogus, unreachable address. If GitPusher's
	// push ever honored this (it shouldn't — file:// transport ignores
	// HTTP proxy config, and GitPusher's own repo doesn't read this
	// config file at all), the push would simply fail to connect.
	testGit(t, workDir, "config", "http.proxy", "http://127.0.0.1:1/should-never-be-reached")

	headSHA := testGit(t, workDir, "rev-parse", "HEAD")

	box := &localBox{}
	extracted, err := ExtractBundle(box, "unused-container-name", workDir, baseSHA, DefaultMaxBundleBytes)
	if err != nil {
		t.Fatalf("ExtractBundle: %v", err)
	}
	defer func() { _ = os.Remove(extracted.BundlePath) }()
	if extracted.HeadSHA != headSHA {
		t.Fatalf("ExtractBundle HeadSHA = %q, want %q", extracted.HeadSHA, headSHA)
	}

	pusher := NewGitPusher()
	result, err := pusher.PushBundle(context.Background(), PushSpec{
		BundlePath:  extracted.BundlePath,
		BaseSHA:     baseSHA,
		HeadSHA:     extracted.HeadSHA,
		RemoteURL:   originDir,
		Credential:  credential,
		RunID:       "run-hostile-repo-test-0001",
		IssueNumber: 13,
		Title:       "Hostile repo test",
	})
	if err != nil {
		t.Fatalf("PushBundle: %v", err)
	}

	// The branch must land on the REAL origin, at the right sha.
	gotHead := testGit(t, root, "ls-remote", originDir, "refs/heads/"+result.Branch)
	if !strings.HasPrefix(gotHead, headSHA) {
		t.Errorf("origin ref for %s = %q, want it to start with %s", result.Branch, gotHead, headSHA)
	}

	// The decoy must never have been touched.
	decoyRefs := testGit(t, root, "ls-remote", decoyDir)
	if decoyRefs != "" {
		t.Errorf("decoy repo has refs %q; push must never have been redirected to it", decoyRefs)
	}

	// The capture sink must be empty or nonexistent: no hook and no
	// credential helper ever ran.
	if sink, err := os.ReadFile(sinkPath); err == nil && len(sink) > 0 {
		t.Errorf("capture sink is non-empty, a hostile hook or credential helper ran:\n%s", sink)
	}
}

func writeExecutable(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o700); err != nil {
		t.Fatal(err)
	}
}
