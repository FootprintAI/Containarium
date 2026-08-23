package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

// These pin the fail-fast validation that runs BEFORE newSandboxGRPCClient
// dials anything, so they need no server and no --server flag.

func TestRunSandboxExec_RequiresCommand(t *testing.T) {
	if err := runSandboxExec(sandboxExecCmd, []string{"sandbox-abc123"}); err == nil {
		t.Fatal("exec with no command should fail before dialing a server")
	}
}

func TestRunSandboxWriteFile_RequiresFrom(t *testing.T) {
	old := sandboxWriteFrom
	sandboxWriteFrom = ""
	defer func() { sandboxWriteFrom = old }()

	if err := runSandboxWriteFile(sandboxWriteFileCmd, []string{"sandbox-abc123", "/workspace/out.txt"}); err == nil {
		t.Fatal("write-file with no --from should fail before dialing a server")
	}
}

func TestRunSandboxWriteFile_MissingLocalFile(t *testing.T) {
	old := sandboxWriteFrom
	sandboxWriteFrom = filepath.Join(t.TempDir(), "does-not-exist")
	defer func() { sandboxWriteFrom = old }()

	err := runSandboxWriteFile(sandboxWriteFileCmd, []string{"sandbox-abc123", "/workspace/out.txt"})
	if err == nil {
		t.Fatal("write-file with a nonexistent --from path should fail before dialing a server")
	}
}

// TestRunSandboxWriteFile_ReadsLocalFileBeforeDialing pins that the local
// file IS actually read (not just existence-checked) before any network
// call — a --server flag is deliberately left unset here, so if this
// reached newSandboxGRPCClient it would fail on "--server is required"
// instead, which os.ReadFile's own error would not resemble.
func TestRunSandboxWriteFile_ReadsLocalFileBeforeDialing(t *testing.T) {
	oldFrom, oldServer := sandboxWriteFrom, serverAddr
	dir := t.TempDir()
	path := filepath.Join(dir, "local.txt")
	if err := os.WriteFile(path, []byte("hello"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	sandboxWriteFrom = path
	serverAddr = ""
	defer func() { sandboxWriteFrom, serverAddr = oldFrom, oldServer }()

	err := runSandboxWriteFile(sandboxWriteFileCmd, []string{"sandbox-abc123", "/workspace/out.txt"})
	if err == nil || err.Error() != "--server is required" {
		t.Fatalf("err = %v, want the newSandboxGRPCClient --server error (local file read must have succeeded to reach it)", err)
	}
}
