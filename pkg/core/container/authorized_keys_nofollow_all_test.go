//go:build unix

package container

import (
	"os"
	"path/filepath"
	"testing"
)

// Every host-side authorized_keys operation reads and writes through the .ssh
// fd, so a planted symlink is refused and its target is never changed (#3652,
// F3). Each test plants a symlink at authorized_keys pointing at a victim file.
func plantAuthorizedKeysSymlink(t *testing.T) (root, victim string) {
	t.Helper()
	root = fakeHome(t, "alice")
	withTestHomeRoot(t, root, func(string) bool { return true })

	sshDir := filepath.Join(root, "alice", ".ssh")
	if err := os.Mkdir(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	victim = filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(sshDir, "authorized_keys")); err != nil {
		t.Fatal(err)
	}
	return root, victim
}

func assertVictimUnchanged(t *testing.T, victim string) {
	t.Helper()
	got, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "keep\n" {
		t.Errorf("symlink target was modified: %q", string(got))
	}
}

func TestAddAuthorizedKeyRefusesSymlinkedAuthorizedKeys(t *testing.T) {
	_, victim := plantAuthorizedKeysSymlink(t)
	if err := AddAuthorizedKey("alice", validTestKey1); err == nil {
		t.Fatal("AddAuthorizedKey followed a symlinked authorized_keys; want refusal")
	}
	assertVictimUnchanged(t, victim)
}

func TestRemoveAuthorizedKeyRefusesSymlinkedAuthorizedKeys(t *testing.T) {
	_, victim := plantAuthorizedKeysSymlink(t)
	if err := RemoveAuthorizedKey("alice", validTestKey1); err == nil {
		t.Fatal("RemoveAuthorizedKey followed a symlinked authorized_keys; want refusal")
	}
	assertVictimUnchanged(t, victim)
}

func TestCountAuthorizedKeysRefusesSymlinkedAuthorizedKeys(t *testing.T) {
	_, victim := plantAuthorizedKeysSymlink(t)
	n, err := CountAuthorizedKeys("alice")
	if err == nil {
		t.Fatalf("CountAuthorizedKeys read through a symlink (count=%d); want refusal", n)
	}
	assertVictimUnchanged(t, victim)
}

func TestReplaceAuthorizedKeysRefusesSymlinkedAuthorizedKeys(t *testing.T) {
	_, victim := plantAuthorizedKeysSymlink(t)
	if _, err := ReplaceAuthorizedKeys("alice", []string{validTestKey2}, ReplaceHooks{}); err == nil {
		t.Fatal("ReplaceAuthorizedKeys followed a symlinked authorized_keys; want refusal")
	}
	assertVictimUnchanged(t, victim)
}

// Remove and Count on a host with no .ssh must succeed and must not create the
// directory: they open it without creating it.
func TestRemoveAndCountDoNotCreateSSHDir(t *testing.T) {
	root := fakeHome(t, "alice")
	withTestHomeRoot(t, root, func(string) bool { return true })

	if err := RemoveAuthorizedKey("alice", validTestKey1); err != nil {
		t.Fatalf("remove on missing .ssh: %v", err)
	}
	if n, err := CountAuthorizedKeys("alice"); err != nil || n != 0 {
		t.Fatalf("count on missing .ssh: n=%d err=%v", n, err)
	}
	if _, err := os.Stat(filepath.Join(root, "alice", ".ssh")); !os.IsNotExist(err) {
		t.Errorf(".ssh was created by a read-only operation: %v", err)
	}
}
