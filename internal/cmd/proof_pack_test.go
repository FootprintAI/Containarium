//go:build !containarium_client

package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/footprintai/containarium/internal/proofpack"
	"github.com/footprintai/containarium/pkg/core/incus/incustest"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// proofPackBox is a mock box whose repo declares one unit step that exits
// with stepExit.
func proofPackBox(t *testing.T, stepExit int) *incustest.MockBackend {
	t.Helper()
	m := incustest.NewMockBackend()
	m.ExecWithExitCodeFunc = func(container string, argv []string) (string, string, int, error) {
		if container != "tenant-container" {
			t.Errorf("exec in %q, want tenant-container", container)
		}
		switch {
		case len(argv) > 3 && argv[3] == "proofpack-probe":
			if argv[4] != "/srv/repo" {
				t.Errorf("repo dir = %q, want --dir", argv[4])
			}
			return "test:\n  - {name: unit, kind: unit, run: go test ./...}\n", "", 11, nil
		case argv[0] == "git":
			return "", "", 128, nil
		case len(argv) > 5 && argv[3] == "proofpack-step":
			if argv[5] != "7" {
				t.Errorf("step timeout arg = %q, want 7", argv[5])
			}
			return "test output\n", "12\n", stepExit, nil
		}
		t.Errorf("unexpected exec %q", argv)
		return "", "", 1, nil
	}
	return m
}

func runProofPack(t *testing.T, m *incustest.MockBackend, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	prev := proofPackExecer
	proofPackExecer = func() (proofpack.Execer, error) { return m, nil }
	t.Cleanup(func() { proofPackExecer = prev })
	proofPackDir, proofPackOut, proofPackStepTimeout = proofpack.DefaultRepoDir, "", proofpack.DefaultStepTimeout

	var out, errb bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&errb)
	rootCmd.SetArgs(append([]string{"proof-pack", "generate"}, args...))
	defer rootCmd.SetArgs(nil)
	err = rootCmd.Execute()
	return out.String(), errb.String(), err
}

func TestProofPackGenerate_FailedStepWritesPackAndExitsNonZero(t *testing.T) {
	out := filepath.Join(t.TempDir(), "pack.json")
	_, stderr, err := runProofPack(t, proofPackBox(t, 1),
		"tenant-container", "--dir", "/srv/repo", "--step-timeout", "6500ms", "--out", out)
	if err == nil || !strings.Contains(err.Error(), "FAILED") {
		t.Fatalf("err = %v, want a FAILED status error", err)
	}
	b, rerr := os.ReadFile(out)
	if rerr != nil {
		t.Fatalf("pack not written on FAILED: %v", rerr)
	}
	var pack pb.ProofPack
	if err := protojson.Unmarshal(b, &pack); err != nil {
		t.Fatal(err)
	}
	if pack.GetStatus() != pb.ProofPackStatus_PROOF_PACK_STATUS_FAILED || pack.GetSteps()[0].GetExitCode() != 1 {
		t.Errorf("pack status=%v exit=%d", pack.GetStatus(), pack.GetSteps()[0].GetExitCode())
	}
	if pack.GetStepTimeoutSeconds() != 7 {
		t.Errorf("step_timeout_seconds = %d, want 6.5s rounded up", pack.GetStepTimeoutSeconds())
	}
	if strings.Contains(string(b), "go test") {
		t.Errorf("pack JSON contains the command line")
	}
	digest, _ := proofpack.PackDigest(&pack)
	if !strings.Contains(stderr, digest) {
		t.Errorf("stderr %q does not report the pack digest %s", stderr, digest)
	}
	if fi, _ := os.Stat(out); fi.Mode().Perm() != 0o600 {
		t.Errorf("pack file mode = %v", fi.Mode().Perm())
	}
}

func TestProofPackGenerate_PassedToStdout(t *testing.T) {
	stdout, _, err := runProofPack(t, proofPackBox(t, 0),
		"tenant-container", "--dir", "/srv/repo", "--step-timeout", "7s")
	if err != nil {
		t.Fatal(err)
	}
	var pack pb.ProofPack
	if err := protojson.Unmarshal([]byte(stdout), &pack); err != nil {
		t.Fatalf("stdout is not a pack: %v\n%s", err, stdout)
	}
	if pack.GetStatus() != pb.ProofPackStatus_PROOF_PACK_STATUS_PASSED {
		t.Errorf("status = %v", pack.GetStatus())
	}
	if pack.GetStartedAt().AsTime().After(time.Now()) {
		t.Errorf("started_at in the future")
	}
}
