package container

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// makeHomeDir creates homeRoot/username[/.ssh/authorized_keys] for test
// fixtures. withKey=false leaves out the .ssh/authorized_keys file
// entirely, matching a directory the reaper should never consider.
func makeHomeDir(t *testing.T, homeRoot, username string, withKey bool) {
	t.Helper()
	dir := filepath.Join(homeRoot, username)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll(%s): %v", dir, err)
	}
	if !withKey {
		return
	}
	sshDir := filepath.Join(dir, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(%s): %v", sshDir, err)
	}
	akPath := filepath.Join(sshDir, "authorized_keys")
	if err := os.WriteFile(akPath, []byte("ssh-ed25519 AAAA fake\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(%s): %v", akPath, err)
	}
}

// TestReapOnce_OnlyReapsContainariumManagedShell is the regression test for
// the real incident: an operator's own admin account (real login shell, no
// matching container) must never be reaped just because it lives under
// homeRoot with an authorized_keys file. Only accounts whose shell is
// exactly containerShellPath are eligible.
func TestReapOnce_OnlyReapsContainariumManagedShell(t *testing.T) {
	homeRoot := t.TempDir()

	makeHomeDir(t, homeRoot, "orphaned-tenant", true) // containarium-shell, no container -> reap
	makeHomeDir(t, homeRoot, "admin-user", true)      // /bin/bash, no container -> must NOT reap
	makeHomeDir(t, homeRoot, "live-tenant", true)     // containarium-shell, HAS container -> must NOT reap
	makeHomeDir(t, homeRoot, "no-key-dir", false)     // no authorized_keys -> never considered

	shells := map[string]string{
		"orphaned-tenant": containerShellPath,
		"admin-user":      "/bin/bash",
		"live-tenant":     containerShellPath,
	}
	userShellFn := func(username string) (string, error) {
		shell, ok := shells[username]
		if !ok {
			return "", fmt.Errorf("user %q not found", username)
		}
		return shell, nil
	}

	containerExistsFn := func(username string) bool {
		return username == "live-tenant"
	}

	var deleted []string
	deleteFn := func(username string, verbose bool) error {
		deleted = append(deleted, username)
		return nil
	}

	reapOnce(homeRoot, containerExistsFn, userShellFn, deleteFn)

	if len(deleted) != 1 || deleted[0] != "orphaned-tenant" {
		t.Fatalf("deleted = %v, want exactly [orphaned-tenant]", deleted)
	}
}

// TestReapOnce_UnknownShellIsNotReaped covers the fail-safe path: if the
// passwd lookup errors (e.g. the directory has no matching passwd entry at
// all — a stale artifact, not a live account), the reaper must not delete
// anything rather than guessing.
func TestReapOnce_UnknownShellIsNotReaped(t *testing.T) {
	homeRoot := t.TempDir()
	makeHomeDir(t, homeRoot, "stale-dir", true)

	userShellFn := func(username string) (string, error) {
		return "", fmt.Errorf("user %q not found", username)
	}
	containerExistsFn := func(username string) bool { return false }

	var deleted []string
	deleteFn := func(username string, verbose bool) error {
		deleted = append(deleted, username)
		return nil
	}

	reapOnce(homeRoot, containerExistsFn, userShellFn, deleteFn)

	if len(deleted) != 0 {
		t.Fatalf("deleted = %v, want none", deleted)
	}
}

// TestReapOnce_NoAuthorizedKeysNeverConsidered ensures a plain directory
// under homeRoot with no .ssh/authorized_keys never reaches the shell
// lookup or delete path at all.
func TestReapOnce_NoAuthorizedKeysNeverConsidered(t *testing.T) {
	homeRoot := t.TempDir()
	makeHomeDir(t, homeRoot, "plain-dir", false)

	userShellFn := func(username string) (string, error) {
		t.Fatalf("userShellFn should not be called for %q", username)
		return "", nil
	}
	containerExistsFn := func(username string) bool { return false }
	deleteFn := func(username string, verbose bool) error {
		t.Fatalf("deleteFn should not be called for %q", username)
		return nil
	}

	reapOnce(homeRoot, containerExistsFn, userShellFn, deleteFn)
}

// TestReapOnce_InvalidUsernameShapeNeverConsidered ensures a directory
// whose name isn't a valid containarium username (e.g. contains shell
// metacharacters) never reaches the getent/exec.Command call at all —
// gosec G204 defense-in-depth, not just a shell-invocation non-issue.
func TestReapOnce_InvalidUsernameShapeNeverConsidered(t *testing.T) {
	homeRoot := t.TempDir()
	// ';' isn't a valid path separator, so this is one directory named
	// literally "weird;name" — invalid per isValidUsername, but a legal
	// (if unusual) single filesystem entry.
	makeHomeDir(t, homeRoot, "weird;name", true)

	userShellFn := func(username string) (string, error) {
		t.Fatalf("userShellFn should not be called for %q", username)
		return "", nil
	}
	containerExistsFn := func(username string) bool { return false }
	deleteFn := func(username string, verbose bool) error {
		t.Fatalf("deleteFn should not be called for %q", username)
		return nil
	}

	reapOnce(homeRoot, containerExistsFn, userShellFn, deleteFn)
}

func TestUserShell_ParsesGetentOutput(t *testing.T) {
	if _, err := exec.LookPath("getent"); err != nil {
		t.Skip("getent not available on this platform (Linux-only tool; CI runs Linux)")
	}
	// root always exists on Linux CI runners and never runs
	// containerShellPath, so this exercises the real getent path
	// without requiring a fixture user.
	shell, err := userShell("root")
	if err != nil {
		t.Fatalf("userShell(root): %v", err)
	}
	if shell == "" {
		t.Fatal("userShell(root) returned empty shell")
	}
	if shell == containerShellPath {
		t.Fatalf("root should never have shell %q", containerShellPath)
	}
}

func TestUserShell_UnknownUser(t *testing.T) {
	if _, err := userShell("nonexistent_user_12345"); err == nil {
		t.Fatal("userShell(nonexistent_user_12345) should error")
	}
}
