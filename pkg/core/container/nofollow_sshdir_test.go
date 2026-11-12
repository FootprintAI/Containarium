//go:build unix

package container

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// stubSSHOwner makes the test's jump account the current process's uid/gid,
// so the tests run without a real host user. Restored via t.Cleanup.
func stubSSHOwner(t *testing.T) {
	t.Helper()
	orig := userSSHOwner
	userSSHOwner = func(string) (int, int, error) { return os.Getuid(), os.Getgid(), nil }
	t.Cleanup(func() { userSSHOwner = orig })
}

// fakeHome creates <root>/<user>/ as a real directory and returns root.
func fakeHome(t *testing.T, user string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, user), 0o755); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestOpenUserSSHDirCreatesMode0700(t *testing.T) {
	stubSSHOwner(t)
	root := fakeHome(t, "alice")

	fd, uid, gid, err := openUserSSHDir(root, "alice")
	if err != nil {
		t.Fatalf("openUserSSHDir: %v", err)
	}
	defer func() { _ = unix.Close(fd) }()

	if uid != os.Getuid() || gid != os.Getgid() {
		t.Errorf("owner = %d:%d, want %d:%d", uid, gid, os.Getuid(), os.Getgid())
	}
	fi, err := os.Stat(filepath.Join(root, "alice", ".ssh"))
	if err != nil {
		t.Fatalf("stat .ssh: %v", err)
	}
	if !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Errorf(".ssh mode = %v, want directory 0700", fi.Mode())
	}
}

// A symlink at .ssh must be refused. Before this change, MkdirAll followed it
// and the path-based chown then ran against the link's target.
func TestOpenUserSSHDirRefusesSymlinkedSSH(t *testing.T) {
	stubSSHOwner(t)
	root := fakeHome(t, "alice")
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "alice", ".ssh")); err != nil {
		t.Fatal(err)
	}

	fd, _, _, err := openUserSSHDir(root, "alice")
	if err == nil {
		_ = unix.Close(fd)
		t.Fatal("openUserSSHDir followed a symlinked .ssh; want refusal")
	}
	entries, _ := os.ReadDir(outside)
	if len(entries) != 0 {
		t.Errorf("symlink target was modified: %d entries created", len(entries))
	}
}

func TestOpenUserSSHDirRefusesSymlinkedHome(t *testing.T) {
	stubSSHOwner(t)
	root := t.TempDir()
	elsewhere := t.TempDir()
	if err := os.Symlink(elsewhere, filepath.Join(root, "alice")); err != nil {
		t.Fatal(err)
	}

	fd, _, _, err := openUserSSHDir(root, "alice")
	if err == nil {
		_ = unix.Close(fd)
		t.Fatal("openUserSSHDir followed a symlinked home; want refusal")
	}
	if _, err := os.Stat(filepath.Join(elsewhere, ".ssh")); !os.IsNotExist(err) {
		t.Errorf("a .ssh was created under the symlink target: %v", err)
	}
}

// A symlink to a directory inside .ssh is not descended into: the link is
// re-owned itself (AT_SYMLINK_NOFOLLOW) and the walk moves on. The target's
// contents stay as they were.
func TestChownTreeNoFollowDoesNotDescendSymlinkedDir(t *testing.T) {
	stubSSHOwner(t)
	root := fakeHome(t, "alice")
	outside := t.TempDir()
	victim := filepath.Join(outside, "victim")
	if err := os.WriteFile(victim, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	sshDir := filepath.Join(root, "alice", ".ssh")
	if err := os.Mkdir(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(sshDir, "sub")); err != nil {
		t.Fatal(err)
	}

	fd, uid, gid, err := openUserSSHDir(root, "alice")
	if err != nil {
		t.Fatalf("openUserSSHDir: %v", err)
	}
	defer func() { _ = unix.Close(fd) }()

	if err := chownTreeNoFollow(fd, uid, gid); err != nil {
		t.Fatalf("chownTreeNoFollow: %v", err)
	}
	fi, err := os.Lstat(filepath.Join(sshDir, "sub"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("symlink was replaced; mode = %v", fi.Mode())
	}
	if _, err := os.Stat(victim); err != nil {
		t.Errorf("symlink target changed: %v", err)
	}
}

// A regular tree is chowned end to end, including nested files. Owner is only
// observable as a change when running as root, so the assertion is that the
// call succeeds and every entry carries the requested owner.
func TestChownTreeNoFollowWalksRegularTree(t *testing.T) {
	stubSSHOwner(t)
	root := fakeHome(t, "alice")
	sshDir := filepath.Join(root, "alice", ".ssh")
	if err := os.MkdirAll(filepath.Join(sshDir, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sshDir, "nested", "f"), []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}

	fd, uid, gid, err := openUserSSHDir(root, "alice")
	if err != nil {
		t.Fatalf("openUserSSHDir: %v", err)
	}
	defer func() { _ = unix.Close(fd) }()

	if err := chownTreeNoFollow(fd, uid, gid); err != nil {
		t.Fatalf("chownTreeNoFollow: %v", err)
	}
	for _, p := range []string{sshDir, filepath.Join(sshDir, "nested"), filepath.Join(sshDir, "nested", "f")} {
		fi, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		st := fi.Sys().(*syscall.Stat_t)
		if int(st.Uid) != uid || int(st.Gid) != gid {
			t.Errorf("%s owner = %d:%d, want %d:%d", p, st.Uid, st.Gid, uid, gid)
		}
	}
}

// Root-only: a symlink inside .ssh must not change its target's owner. The
// link itself is re-owned (AT_SYMLINK_NOFOLLOW), the target stays root.
func TestChownTreeNoFollowLeavesSymlinkTargetOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to assert a cross-owner chown is not applied to the target")
	}
	root := fakeHome(t, "alice")
	outside := t.TempDir()
	target := filepath.Join(outside, "target")
	if err := os.WriteFile(target, []byte("root"), 0o600); err != nil {
		t.Fatal(err)
	}
	sshDir := filepath.Join(root, "alice", ".ssh")
	if err := os.Mkdir(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(sshDir, "authorized_keys")); err != nil {
		t.Fatal(err)
	}
	innerDir := filepath.Join(outside, "inner")
	if err := os.Mkdir(innerDir, 0o700); err != nil {
		t.Fatal(err)
	}
	innerFile := filepath.Join(innerDir, "f")
	if err := os.WriteFile(innerFile, []byte("root"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(innerDir, filepath.Join(sshDir, "dirlink")); err != nil {
		t.Fatal(err)
	}

	stubSSHOwner(t)
	userSSHOwner = func(string) (int, int, error) { return 1234, 1234, nil }

	fd, uid, gid, err := openUserSSHDir(root, "alice")
	if err != nil {
		t.Fatalf("openUserSSHDir: %v", err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := chownTreeNoFollow(fd, uid, gid); err != nil {
		t.Fatalf("chownTreeNoFollow: %v", err)
	}

	fi, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if owner := fi.Sys().(*syscall.Stat_t).Uid; owner != 0 {
		t.Errorf("symlink target owner = %d, want 0 (chown must not follow the link)", owner)
	}
	fi, err = os.Stat(innerFile)
	if err != nil {
		t.Fatal(err)
	}
	if owner := fi.Sys().(*syscall.Stat_t).Uid; owner != 0 {
		t.Errorf("file under symlinked dir owner = %d, want 0 (must not descend)", owner)
	}
}
