package integration

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestQuickstartLocalIncus is the daemon-level integration test for
// `containarium quickstart`. Unlike the hermetic orchestration test in
// internal/cmd (which fakes the daemon), this runs the REAL binary end to end
// against a running instance and asserts that a box is actually created and
// that the real SSH + agent-MCP config gets written.
//
// It self-skips unless you point it at a binary and (optionally) a server:
//
//	CONTAINARIUM_BIN=$(pwd)/bin/containarium \
//	CONTAINARIUM_SERVER=localhost:50051 \
//	  go test -v -run TestQuickstartLocalIncus ./test/integration/
//
// Auth/TLS flags your daemon needs (e.g. --insecure, --token) can be supplied
// via CONTAINARIUM_TEST_FLAGS (space-separated), appended to every CLI call.
// HOME is redirected to a temp dir so the test never touches your real
// ~/.ssh/config or ~/.claude.json.
func TestQuickstartLocalIncus(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	if os.Getenv("CONTAINARIUM_BIN") == "" {
		t.Skip("set CONTAINARIUM_BIN to the containarium binary to run this test")
	}

	server := getServerAddr(t)
	home := t.TempDir()
	const box = "qs-it-box"

	// Best-effort pre-clean (a prior run may have left the box) + teardown.
	_, _ = runQuickstartCLI(t, home, "delete", box, "--server", server, "--force")
	t.Cleanup(func() {
		_, _ = runQuickstartCLI(t, home, "delete", box, "--server", server, "--force")
	})

	// 1. quickstart wires everything. No --ssh-key → auto-provision a managed
	//    key; no --prompt → no expose/launch (those need a sentinel + a real
	//    agent, out of scope for a daemon-only integration test).
	out, err := runQuickstartCLI(t, home, "quickstart", box, "--server", server)
	require.NoError(t, err, "quickstart failed:\n%s", out)

	// 2. the box actually exists on the daemon.
	list, err := runQuickstartCLI(t, home, "list", "--server", server)
	require.NoError(t, err, "list failed:\n%s", list)
	require.Contains(t, list, box, "box not listed after quickstart")

	// 3. real config was written under the temp HOME.
	sshConfig := filepath.Join(home, ".containarium", "ssh_config")
	require.FileExists(t, sshConfig)
	require.Contains(t, readFileString(t, sshConfig), box, "ssh_config has no host for the box")

	claudeCfg := filepath.Join(home, ".claude.json")
	require.FileExists(t, claudeCfg)
	require.Contains(t, readFileString(t, claudeCfg), "containarium-box", "agent MCP config not wired")

	userSSHConfig := filepath.Join(home, ".ssh", "config")
	require.FileExists(t, userSSHConfig)
	require.Contains(t, readFileString(t, userSSHConfig), "Include", "Include line not added to ~/.ssh/config")

	// 4. a managed keypair was generated (since no --ssh-key was passed).
	require.FileExists(t, filepath.Join(home, ".ssh", "containarium_ed25519"))

	// 5. idempotent — a second run succeeds and reuses the box.
	out2, err := runQuickstartCLI(t, home, "quickstart", box, "--server", server)
	require.NoError(t, err, "second quickstart (idempotency) failed:\n%s", out2)
}

// runQuickstartCLI runs the containarium binary with HOME redirected to the
// test's temp dir. Any daemon auth/TLS flags come from CONTAINARIUM_TEST_FLAGS.
func runQuickstartCLI(t *testing.T, home string, args ...string) (string, error) {
	t.Helper()
	bin := os.Getenv("CONTAINARIUM_BIN")

	if extra := strings.Fields(os.Getenv("CONTAINARIUM_TEST_FLAGS")); len(extra) > 0 {
		args = append(args, extra...)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, args...)
	// Redirect HOME so config writes are isolated; keep the rest of the env
	// (PATH, CONTAINARIUM_TOKEN, etc.) so auth passes through.
	cmd.Env = append(os.Environ(), "HOME="+home)

	out, err := cmd.CombinedOutput()
	return string(out), err
}

func readFileString(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err, "read %s", path)
	return string(b)
}
