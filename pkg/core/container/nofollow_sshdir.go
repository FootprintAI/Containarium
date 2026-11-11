//go:build unix

package container

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// The daemon runs as root, and a jump account's home is owned by that account.
// The account can therefore replace any path under its home with a symlink
// pointing anywhere. Path-based chown/mkdir follows that symlink as root.
// The helpers below walk the .ssh directory one component at a time with
// openat(O_NOFOLLOW) and change ownership with fchownat(AT_SYMLINK_NOFOLLOW),
// so a planted symlink is refused or left alone, never followed.

// openUserSSHDir returns an open fd for <homeRoot>/<username>/.ssh, creating
// .ssh with mode 0700 if it is missing, together with the owner it should
// carry. The caller closes the fd. Every component is opened with O_NOFOLLOW,
// so a symlink at .ssh, or at the home directory, fails instead of being
// followed.
func openUserSSHDir(homeRoot, username string) (fd, uid, gid int, err error) {
	uid, gid, err = userSSHOwner(username)
	if err != nil {
		return -1, 0, 0, err
	}

	rootFd, err := unix.Open(homeRoot, unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, 0, 0, fmt.Errorf("open home root %s: %w", homeRoot, err)
	}
	defer func() { _ = unix.Close(rootFd) }()

	userFd, err := openDirNoFollow(rootFd, username, true)
	if err != nil {
		return -1, 0, 0, err
	}
	defer func() { _ = unix.Close(userFd) }()

	fd, err = openDirNoFollow(userFd, ".ssh", true)
	if err != nil {
		return -1, 0, 0, err
	}
	return fd, uid, gid, nil
}

// openDirNoFollow opens name, a directory directly under parent, without
// following a symlink. With create set, it first makes the directory with
// mode 0700 if it does not exist. A symlink or non-directory in its place is
// an error.
func openDirNoFollow(parent int, name string, create bool) (int, error) {
	if create {
		if err := unix.Mkdirat(parent, name, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
			return -1, fmt.Errorf("mkdir %s: %w", name, err)
		}
	}
	fd, err := unix.Openat(parent, name, unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
			return -1, fmt.Errorf("%s is a symlink or not a directory; refusing to follow", name)
		}
		return -1, fmt.Errorf("open %s: %w", name, err)
	}
	return fd, nil
}

// chownTreeNoFollow sets uid:gid on the directory fd, then on everything under
// it, recursively. Entries are changed with AT_SYMLINK_NOFOLLOW, so a symlink
// changes only its own owner and never its target. Subdirectories are reopened
// with O_NOFOLLOW before descending.
func chownTreeNoFollow(fd, uid, gid int) error {
	if err := unix.Fchown(fd, uid, gid); err != nil {
		return fmt.Errorf("chown dir: %w", err)
	}

	// Read entries through a dup so the os.File's finalizer cannot close fd.
	dup, err := unix.Dup(fd)
	if err != nil {
		return fmt.Errorf("dup dir fd: %w", err)
	}
	dir := os.NewFile(uintptr(dup), "ssh-dir")
	entries, err := dir.ReadDir(-1)
	_ = dir.Close()
	if err != nil {
		return fmt.Errorf("read dir: %w", err)
	}

	for _, e := range entries {
		name := e.Name()
		if err := unix.Fchownat(fd, name, uid, gid, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return fmt.Errorf("chown %s: %w", filepath.Base(name), err)
		}
		if !e.IsDir() {
			continue
		}
		child, err := openDirNoFollow(fd, name, false)
		if err != nil {
			return err
		}
		err = chownTreeNoFollow(child, uid, gid)
		_ = unix.Close(child)
		if err != nil {
			return err
		}
	}
	return nil
}

// closeFD closes an fd from openUserSSHDir.
func closeFD(fd int) { _ = unix.Close(fd) }

// fchownFD sets uid:gid on an open directory fd (not its contents).
func fchownFD(fd, uid, gid int) error { return unix.Fchown(fd, uid, gid) }
