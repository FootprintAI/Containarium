package container

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// withTestHomeRoot overrides the package's home root + user-exists check
// for a single test. Restores the originals via t.Cleanup so tests run
// in any order without bleeding state.
func withTestHomeRoot(t *testing.T, homeRoot string, userExistsFn func(string) bool) {
	t.Helper()
	origHome := authorizedKeysHomeRoot
	origExists := authorizedKeysUserExists
	authorizedKeysHomeRoot = homeRoot
	authorizedKeysUserExists = userExistsFn
	t.Cleanup(func() {
		authorizedKeysHomeRoot = origHome
		authorizedKeysUserExists = origExists
	})
}

const validTestKey1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBZkMdKTk8EXlTr5tlsIfAvlCi2iCl0YB/YDua3uMyDX test1"
const validTestKey2 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDtmr5hyCwDmlxelT+dTGxmh8SpOObOWJIhoRa61oY2Q test2"
// TestJumpServerAuthorizesAllRequestKeys_470 is the #470 regression.
//
// The manager seeds the HOST jump-server authorized_keys with SSHKeys[0]
// only (CreateJumpServerAccount → setupUserSSHKey OVERWRITES the host file
// with a single key), then must AddAuthorizedKey the rest. Without that
// loop, any key after the first lands only in the CONTAINER-internal
// authorized_keys, never the host file the sentinel syncs from — so a
// client using e.g. an automation key that sorts after a registered key is
// rejected at the sentinel (publickey) though the box itself would accept it.
//
// This test exercises the host-side invariant the fix relies on: after the
// seed-then-authorize-the-rest sequence, EVERY supplied key is present in
// the host authorized_keys.
func TestJumpServerAuthorizesAllRequestKeys_470(t *testing.T) {
	tmp := t.TempDir()
	withTestHomeRoot(t, tmp, func(string) bool { return true })

	const user = "boxuser"
	keys := []string{validTestKey1, validTestKey2}

	// Simulate CreateJumpServerAccount seeding the host file with keys[0]
	// (setupUserSSHKey writes exactly one key, overwriting).
	akPath := filepath.Join(tmp, user, ".ssh", "authorized_keys")
	if err := os.MkdirAll(filepath.Dir(akPath), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(akPath, []byte(keys[0]+"\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// The fix: authorize the remaining keys host-side.
	for _, k := range keys[1:] {
		if err := AddAuthorizedKey(user, k); err != nil {
			t.Fatalf("AddAuthorizedKey(%q): %v", k, err)
		}
	}

	content, err := os.ReadFile(akPath)
	if err != nil {
		t.Fatalf("readback: %v", err)
	}
	for i, k := range keys {
		if !strings.Contains(string(content), k) {
			t.Errorf("host authorized_keys missing key[%d] — the sentinel would reject a client using it; #470 regression:\nkey:  %s\nfile:\n%s", i, k, content)
		}
	}
}

func TestAddAuthorizedKey_CreatesDirAndFile(t *testing.T) {
	tmp := t.TempDir()
	withTestHomeRoot(t, tmp, func(string) bool { return true })

	if err := AddAuthorizedKey("alice", validTestKey1); err != nil {
		t.Fatalf("AddAuthorizedKey: %v", err)
	}

	akPath := filepath.Join(tmp, "alice", ".ssh", "authorized_keys")
	content, err := os.ReadFile(akPath)
	if err != nil {
		t.Fatalf("readback: %v", err)
	}
	if !strings.Contains(string(content), validTestKey1) {
		t.Errorf("file missing the key:\n%s", content)
	}
	if !strings.HasSuffix(string(content), "\n") {
		t.Errorf("file doesn't end in newline (sshd may reject)")
	}

	if runtime.GOOS != "windows" {
		st, _ := os.Stat(akPath)
		if mode := st.Mode().Perm(); mode != 0o600 {
			t.Errorf("authorized_keys mode = %o, want 0600", mode)
		}
		stDir, _ := os.Stat(filepath.Dir(akPath))
		if mode := stDir.Mode().Perm(); mode != 0o700 {
			t.Errorf(".ssh dir mode = %o, want 0700", mode)
		}
	}
}

func TestAddAuthorizedKey_AppendsToExisting(t *testing.T) {
	tmp := t.TempDir()
	withTestHomeRoot(t, tmp, func(string) bool { return true })

	if err := AddAuthorizedKey("bob", validTestKey1); err != nil {
		t.Fatalf("add 1: %v", err)
	}
	if err := AddAuthorizedKey("bob", validTestKey2); err != nil {
		t.Fatalf("add 2: %v", err)
	}

	content, _ := os.ReadFile(filepath.Join(tmp, "bob", ".ssh", "authorized_keys"))
	if !strings.Contains(string(content), validTestKey1) {
		t.Errorf("first key missing after second add")
	}
	if !strings.Contains(string(content), validTestKey2) {
		t.Errorf("second key missing")
	}
	// Two lines + trailing newline.
	nonEmpty := 0
	for _, line := range strings.Split(string(content), "\n") {
		if strings.TrimSpace(line) != "" {
			nonEmpty++
		}
	}
	if nonEmpty != 2 {
		t.Errorf("expected 2 lines after two adds, got %d:\n%s", nonEmpty, content)
	}
}

func TestAddAuthorizedKey_Idempotent(t *testing.T) {
	tmp := t.TempDir()
	withTestHomeRoot(t, tmp, func(string) bool { return true })

	if err := AddAuthorizedKey("carol", validTestKey1); err != nil {
		t.Fatalf("first: %v", err)
	}
	// Same key again — no error, no duplicate.
	if err := AddAuthorizedKey("carol", validTestKey1); err != nil {
		t.Fatalf("second (idempotent): %v", err)
	}

	content, _ := os.ReadFile(filepath.Join(tmp, "carol", ".ssh", "authorized_keys"))
	count := strings.Count(string(content), validTestKey1)
	if count != 1 {
		t.Errorf("expected key once after double-add, got %d times", count)
	}
}

func TestAddAuthorizedKey_RejectsBadKey(t *testing.T) {
	tmp := t.TempDir()
	withTestHomeRoot(t, tmp, func(string) bool { return true })

	if err := AddAuthorizedKey("dave", "not a real ssh key"); err == nil {
		t.Errorf("expected error for invalid key, got nil")
	}
}

func TestAddAuthorizedKey_RejectsUnknownUser(t *testing.T) {
	tmp := t.TempDir()
	withTestHomeRoot(t, tmp, func(string) bool { return false }) // user doesn't exist

	err := AddAuthorizedKey("eve", validTestKey1)
	if err == nil {
		t.Fatal("expected error for nonexistent user, got nil")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("error %q should mention nonexistence", err)
	}
}

func TestRemoveAuthorizedKey_StripsAndPreservesOthers(t *testing.T) {
	tmp := t.TempDir()
	withTestHomeRoot(t, tmp, func(string) bool { return true })

	if err := AddAuthorizedKey("frank", validTestKey1); err != nil {
		t.Fatalf("add 1: %v", err)
	}
	if err := AddAuthorizedKey("frank", validTestKey2); err != nil {
		t.Fatalf("add 2: %v", err)
	}

	if err := RemoveAuthorizedKey("frank", validTestKey1); err != nil {
		t.Fatalf("remove: %v", err)
	}

	content, _ := os.ReadFile(filepath.Join(tmp, "frank", ".ssh", "authorized_keys"))
	if strings.Contains(string(content), validTestKey1) {
		t.Errorf("removed key still present:\n%s", content)
	}
	if !strings.Contains(string(content), validTestKey2) {
		t.Errorf("other key got removed too:\n%s", content)
	}
}

func TestRemoveAuthorizedKey_NoOpWhenAbsent(t *testing.T) {
	tmp := t.TempDir()
	withTestHomeRoot(t, tmp, func(string) bool { return true })

	if err := AddAuthorizedKey("greta", validTestKey1); err != nil {
		t.Fatalf("setup: %v", err)
	}
	// Remove a key that was never added — should succeed silently.
	if err := RemoveAuthorizedKey("greta", validTestKey2); err != nil {
		t.Errorf("removing non-present key should not error, got: %v", err)
	}
	// And the existing key must remain.
	content, _ := os.ReadFile(filepath.Join(tmp, "greta", ".ssh", "authorized_keys"))
	if !strings.Contains(string(content), validTestKey1) {
		t.Errorf("existing key disappeared after no-op remove")
	}
}

func TestCountAuthorizedKeys(t *testing.T) {
	tmp := t.TempDir()
	withTestHomeRoot(t, tmp, func(string) bool { return true })

	// No file yet.
	if n, err := CountAuthorizedKeys("henry"); err != nil || n != 0 {
		t.Errorf("expected 0/nil for missing file, got %d / %v", n, err)
	}

	_ = AddAuthorizedKey("henry", validTestKey1)
	if n, _ := CountAuthorizedKeys("henry"); n != 1 {
		t.Errorf("expected 1 after add, got %d", n)
	}

	_ = AddAuthorizedKey("henry", validTestKey2)
	if n, _ := CountAuthorizedKeys("henry"); n != 2 {
		t.Errorf("expected 2 after second add, got %d", n)
	}

	_ = RemoveAuthorizedKey("henry", validTestKey1)
	if n, _ := CountAuthorizedKeys("henry"); n != 1 {
		t.Errorf("expected 1 after remove, got %d", n)
	}
}
