//go:build unix

package container

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A planted symlink at authorized_keys must not be followed by either the
// setup or the update path (#3651, F2). The target stays as it was.
func TestUpdateUserSSHKeyRefusesSymlinkedAuthorizedKeys(t *testing.T) {
	root := fakeHome(t, "alice")
	withTestHomeRoot(t, root, func(string) bool { return true })

	sshDir := filepath.Join(root, "alice", ".ssh")
	if err := os.Mkdir(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(sshDir, "authorized_keys")); err != nil {
		t.Fatal(err)
	}

	if err := updateUserSSHKey("alice", validTestKey1, false); err == nil {
		t.Fatal("updateUserSSHKey followed a symlinked authorized_keys; want refusal")
	}
	got, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "keep\n" {
		t.Errorf("symlink target was modified: %q", string(got))
	}
}

func TestSetupUserSSHKeyRefusesSymlinkedAuthorizedKeys(t *testing.T) {
	root := fakeHome(t, "alice")
	withTestHomeRoot(t, root, func(string) bool { return true })

	sshDir := filepath.Join(root, "alice", ".ssh")
	if err := os.Mkdir(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(sshDir, "authorized_keys")); err != nil {
		t.Fatal(err)
	}

	if err := setupUserSSHKey("alice", validTestKey1, false); err == nil {
		t.Fatal("setupUserSSHKey wrote through a symlinked authorized_keys; want refusal")
	}
	got, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "keep\n" {
		t.Errorf("symlink target was overwritten: %q", string(got))
	}
}

// Behaviour on a regular file is unchanged: the key is appended once, the
// file is 0600, and a second add of the same key is a no-op.
func TestUpdateUserSSHKeyAppendsToRegularFile(t *testing.T) {
	root := fakeHome(t, "alice")
	withTestHomeRoot(t, root, func(string) bool { return true })

	sshDir := filepath.Join(root, "alice", ".ssh")
	if err := os.Mkdir(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	akPath := filepath.Join(sshDir, "authorized_keys")
	if err := os.WriteFile(akPath, []byte(validTestKey1+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := updateUserSSHKey("alice", validTestKey2, false); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := updateUserSSHKey("alice", validTestKey2, false); err != nil {
		t.Fatalf("second append: %v", err)
	}
	got, err := os.ReadFile(akPath)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(got), validTestKey2); n != 1 {
		t.Errorf("key2 appears %d times, want 1", n)
	}
	fi, err := os.Stat(akPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("authorized_keys mode = %o, want 600", fi.Mode().Perm())
	}
}
