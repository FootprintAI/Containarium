//go:build linux

package proofpack

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// localExecer runs Generate's argv on this machine instead of in a box, so
// the probe and step shell wrappers are exercised for real (sh, timeout,
// mktemp, wc, tail). The container name is ignored.
type localExecer struct{}

func (localExecer) ExecWithExitCode(_ string, argv []string) (string, string, int, error) {
	cmd := exec.Command(argv[0], argv[1:]...) // #nosec G204 -- test runs Generate's own fixed wrappers
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return stdout.String(), stderr.String(), exitErr.ExitCode(), nil
	}
	if err != nil {
		return "", "", 0, err
	}
	return stdout.String(), stderr.String(), 0, nil
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestGenerate_RealShell(t *testing.T) {
	for _, tool := range []string{"sh", "timeout", "mktemp", "wc", "tail", "head"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available: %v", tool, err)
		}
	}
	repo := t.TempDir()
	// A step whose output is longer than the bound, a failing step that
	// writes to stderr, a passing step, and one that outlives its timeout.
	writeFile(t, filepath.Join(repo, DeclarationPath), `test:
  - name: big
    kind: unit
    run: "yes line | head -c 300000; echo; echo END-OF-OUTPUT"
  - name: fails
    kind: integration
    run: "echo to-stdout; echo to-stderr >&2; exit 3"
  - name: passes
    kind: static_analysis
    run: "true"
  - name: hangs
    kind: e2e
    run: "echo started; sleep 30"
`)

	start := time.Now()
	pack, err := Generate(context.Background(), localExecer{}, "local", Options{RepoDir: repo, StepTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 20*time.Second {
		t.Errorf("Generate took %v; the 1s step timeout did not bound the hanging step", took)
	}
	if pack.GetStatus() != pb.ProofPackStatus_PROOF_PACK_STATUS_FAILED {
		t.Errorf("status = %v", pack.GetStatus())
	}
	steps := map[string]*pb.ProofStep{}
	for _, s := range pack.GetSteps() {
		steps[s.GetName()] = s
	}

	big := steps["big"]
	if big.GetExitCode() != 0 || !big.GetLogTruncated() || len(big.GetLog()) != LogLimitBytes {
		t.Errorf("big: exit=%d truncated=%v len=%d", big.GetExitCode(), big.GetLogTruncated(), len(big.GetLog()))
	}
	if big.GetLogOriginalBytes() != int64(300000+1+len("END-OF-OUTPUT\n")) {
		t.Errorf("big: original bytes = %d", big.GetLogOriginalBytes())
	}
	if !bytes.HasSuffix(big.GetLog(), []byte("END-OF-OUTPUT\n")) {
		t.Errorf("big: the tail was not kept")
	}

	fails := steps["fails"]
	if fails.GetExitCode() != 3 || fails.GetTimedOut() {
		t.Errorf("fails: exit=%d timed_out=%v", fails.GetExitCode(), fails.GetTimedOut())
	}
	if !strings.Contains(string(fails.GetLog()), "to-stdout") || !strings.Contains(string(fails.GetLog()), "to-stderr") {
		t.Errorf("fails: log %q lacks stdout or stderr", fails.GetLog())
	}

	if p := steps["passes"]; p.GetExitCode() != 0 || len(p.GetLog()) != 0 || p.GetLogOriginalBytes() != 0 {
		t.Errorf("passes: exit=%d log=%q", p.GetExitCode(), p.GetLog())
	}

	hangs := steps["hangs"]
	if !hangs.GetTimedOut() || hangs.GetExitCode() != 124 {
		t.Errorf("hangs: exit=%d timed_out=%v", hangs.GetExitCode(), hangs.GetTimedOut())
	}
	if string(hangs.GetLog()) != "started\n" {
		t.Errorf("hangs: log = %q", hangs.GetLog())
	}

	if err := CheckPartDigests(pack); err != nil {
		t.Error(err)
	}
	// The repo dir is not a git checkout.
	if pack.GetGitCommit() != "" {
		t.Errorf("git_commit = %q in a non-git dir", pack.GetGitCommit())
	}
}

func TestGenerate_RealShell_FallbackAndMissingDir(t *testing.T) {
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("make not available")
	}
	repo := t.TempDir()
	writeFile(t, filepath.Join(repo, "Makefile"), "test:\n\t@echo running-make-test; exit 1\n")
	pack, err := Generate(context.Background(), localExecer{}, "local", Options{RepoDir: repo, StepTimeout: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if pack.GetCommandSource() != pb.ProofCommandSource_PROOF_COMMAND_SOURCE_FALLBACK_MAKE_TEST {
		t.Errorf("source = %v", pack.GetCommandSource())
	}
	if s := pack.GetSteps()[0]; s.GetExitCode() == 0 || !strings.Contains(string(s.GetLog()), "running-make-test") {
		t.Errorf("make-test: exit=%d log=%q", s.GetExitCode(), s.GetLog())
	}

	_, err = Generate(context.Background(), localExecer{}, "local", Options{RepoDir: filepath.Join(repo, "nope")})
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("missing dir: err = %v", err)
	}
}

// A declaration that exists but cannot be read is an error. It must not
// fall back to `make test`: the repository declared something else.
func TestGenerate_RealShell_UnreadableDeclarationIsError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read a mode-000 file")
	}
	repo := t.TempDir()
	writeFile(t, filepath.Join(repo, "Makefile"), "test:\n\t@echo fallback-ran\n")
	decl := filepath.Join(repo, DeclarationPath)
	writeFile(t, decl, "test: exit 1\n")
	if err := os.Chmod(decl, 0); err != nil {
		t.Fatal(err)
	}
	pack, err := Generate(context.Background(), localExecer{}, "local", Options{RepoDir: repo, StepTimeout: 30 * time.Second})
	if err == nil {
		t.Fatalf("unreadable declaration produced a pack (source %v, steps %d)", pack.GetCommandSource(), len(pack.GetSteps()))
	}
	if !strings.Contains(err.Error(), "cannot read") {
		t.Errorf("err = %v", err)
	}
}
