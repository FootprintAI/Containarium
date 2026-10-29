package sshauthz

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileHolders(t *testing.T) {
	home := t.TempDir()
	shared, solo := testKey(t), testKey(t)
	write := func(user string, lines ...string) {
		dir := filepath.Join(home, user, ".ssh")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		body := "# platform\n" + SentinelKeyMarker + "\n" + shared + "\n" // sentinel block is never a holding
		for _, l := range lines {
			body += l + "\n"
		}
		if err := os.WriteFile(filepath.Join(dir, "authorized_keys"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("alice", shared, solo)
	write("bob", shared)
	write("carol")

	fp := func(pub string) string { return mustRecordT(t, pub).Fingerprint }
	h := FileHolders{HomeRoot: home}
	for _, tc := range []struct {
		name, key, exclude string
		want               bool
	}{
		{"bob holds shared, asked as alice", shared, "alice", true},
		{"alice holds shared, asked as bob", shared, "bob", true},
		{"only alice holds solo", solo, "alice", false},
		{"alice holds solo, asked as bob", solo, "bob", true},
		{"nobody holds an unknown key", testKey(t), "alice", false},
		{"collaborator account is another account", shared, "alice-container-bob", true},
	} {
		got, err := h.OtherAccountHolds(t.Context(), fp(tc.key), tc.exclude)
		if err != nil || got != tc.want {
			t.Errorf("%s: got %v, %v; want %v", tc.name, got, err, tc.want)
		}
	}
	if _, err := (FileHolders{HomeRoot: home + "/missing"}).OtherAccountHolds(t.Context(), fp(solo), "alice"); err == nil {
		t.Error("an unreadable home root must be an error (fail closed), not 'no holder'")
	}
}

func mustRecordT(t *testing.T, pub string) KeyRecord {
	t.Helper()
	rec, err := NewKeyRecord(pub, "probe", SourceAPI, caseNow)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

// badAccounts lays out one account per way a home cannot be read as a plain
// authorized_keys file: a symlinked home, a symlinked authorized_keys, a .ssh
// that is a file, and (when the test does not run as root) a file with no
// read permission. The scan cannot tell what keys such an account holds.
func badAccounts(t *testing.T, root string) []string {
	t.Helper()
	elsewhere := t.TempDir()
	if err := os.WriteFile(filepath.Join(elsewhere, "keys"), []byte("# not read\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var names []string
	add := func(name string) string { names = append(names, name); return filepath.Join(root, name) }

	if err := os.Symlink(elsewhere, add("linkedhome")); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(add("linkedkeys"), ".ssh")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(elsewhere, "keys"), filepath.Join(dir, "authorized_keys")); err != nil {
		t.Fatal(err)
	}
	home := add("sshisfile")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		writeHome(t, root, "noperm", "# unreadable\n")
		names = append(names, "noperm")
		if err := os.Chmod(filepath.Join(root, "noperm", ".ssh", "authorized_keys"), 0); err != nil {
			t.Fatal(err)
		}
	}
	return names
}

// A home the scan cannot read might hold the key, so it is not "no holder"
// (#3241). Each kind of bad account must fail the holder check closed.
func TestFileHolders_UnreadableAccountFailsClosed(t *testing.T) {
	home := t.TempDir()
	solo := testKey(t)
	writeHome(t, home, "alice", solo+"\n")
	bad := badAccounts(t, home)
	fp := mustRecordT(t, solo).Fingerprint

	for _, name := range bad {
		t.Run(name, func(t *testing.T) {
			only := t.TempDir()
			writeHome(t, only, "alice", solo+"\n")
			copyAccount(t, home, only, name)
			if held, err := (FileHolders{HomeRoot: only}).OtherAccountHolds(t.Context(), fp, "alice"); err == nil {
				t.Fatalf("unreadable account %q read as 'no holder' (held=%v)", name, held)
			}
		})
	}
}

// Containment: a readable holder still answers (true, the revoke is refused),
// and the excluded account's own state is irrelevant to whether another
// account holds the key.
func TestFileHolders_UnreadableAccountDoesNotBlockDecidedCases(t *testing.T) {
	home := t.TempDir()
	shared := testKey(t)
	writeHome(t, home, "alice", shared+"\n")
	writeHome(t, home, "bob", shared+"\n")
	badAccounts(t, home)
	fp := mustRecordT(t, shared).Fingerprint

	held, err := (FileHolders{HomeRoot: home}).OtherAccountHolds(t.Context(), fp, "alice")
	if err != nil || !held {
		t.Fatalf("a readable holder must answer true despite unreadable accounts: %v, %v", held, err)
	}
}

// The caller's own unreadable home must not block its own revoke: no readable
// account holds the key, and the only unreadable account is the caller's, so
// the answer is "no other holder" with no error. A different unreadable
// account in the same position must still fail closed.
func TestFileHolders_CallersOwnUnreadableHomeDoesNotBlockItsRevoke(t *testing.T) {
	lonely := testKey(t) // held by no readable account
	fp := mustRecordT(t, lonely).Fingerprint

	own := t.TempDir()
	writeHome(t, own, "alice", "# nothing\n")
	if err := os.Symlink(t.TempDir(), filepath.Join(own, "mallory")); err != nil {
		t.Fatal(err)
	}
	held, err := (FileHolders{HomeRoot: own}).OtherAccountHolds(t.Context(), fp, "mallory")
	if err != nil || held {
		t.Fatalf("the caller's own unreadable home must not block its revoke: held=%v err=%v", held, err)
	}

	other := t.TempDir()
	writeHome(t, other, "alice", "# nothing\n")
	if err := os.Symlink(t.TempDir(), filepath.Join(other, "mallory")); err != nil {
		t.Fatal(err)
	}
	if held, err := (FileHolders{HomeRoot: other}).OtherAccountHolds(t.Context(), fp, "alice"); err == nil {
		t.Fatalf("another account's unreadable home must fail closed (held=%v)", held)
	}
}

// The error reaches an API caller who may belong to a different tenant, so it
// must name neither the unreadable account nor the filesystem state behind it.
func TestFileHolders_UnreadableErrorDoesNotLeakAccountOrPath(t *testing.T) {
	home := t.TempDir()
	key := testKey(t)
	writeHome(t, home, "alice", "# nothing\n")
	secretTarget := t.TempDir()
	if err := os.Symlink(secretTarget, filepath.Join(home, "victimtenant")); err != nil {
		t.Fatal(err)
	}
	fp := mustRecordT(t, key).Fingerprint

	_, err := (FileHolders{HomeRoot: home}).OtherAccountHolds(t.Context(), fp, "alice")
	if err == nil {
		t.Fatal("an unreadable account must fail closed")
	}
	for _, leak := range []string{"victimtenant", home, secretTarget, "symlink"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("caller-facing error leaks %q: %v", leak, err)
		}
	}
}

func TestFileHolders_UnreadableErrorIsSentinel(t *testing.T) {
	home := t.TempDir()
	writeHome(t, home, "alice", "# nothing\n")
	if err := os.Symlink(t.TempDir(), filepath.Join(home, "victimtenant")); err != nil {
		t.Fatal(err)
	}
	_, err := (FileHolders{HomeRoot: home}).OtherAccountHolds(t.Context(), mustRecordT(t, testKey(t)).Fingerprint, "alice")
	if !errors.Is(err, ErrHolderUnknown) {
		t.Fatalf("want ErrHolderUnknown, got %v", err)
	}
}

// copyAccount recreates the named bad account from src under dst. A symlink is
// recreated as a symlink; any other account is copied.
func copyAccount(t *testing.T, src, dst, name string) {
	t.Helper()
	from, to := filepath.Join(src, name), filepath.Join(dst, name)
	fi, err := os.Lstat(from)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(from)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, to); err != nil {
			t.Fatal(err)
		}
		return
	}
	if name == "noperm" { // not copyable while unreadable: recreate it
		writeHome(t, dst, name, "# unreadable\n")
		if err := os.Chmod(filepath.Join(to, ".ssh", "authorized_keys"), 0); err != nil {
			t.Fatal(err)
		}
		return
	}
	if err := os.CopyFS(to, os.DirFS(from)); err != nil {
		t.Fatal(err)
	}
}
