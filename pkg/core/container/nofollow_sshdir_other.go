//go:build !unix

package container

import (
	"errors"
	"os"
)

// errNoFollowUnsupported is returned where the openat/fchownat helpers are not
// available. The jump-account paths that need them only run on Unix hosts.
var errNoFollowUnsupported = errors.New("ssh dir no-follow handling is not supported on this platform")

func openUserSSHDir(homeRoot, username string) (fd, uid, gid int, err error) {
	return -1, 0, 0, errNoFollowUnsupported
}

func chownTreeNoFollow(fd, uid, gid int) error { return errNoFollowUnsupported }

func fchownFD(fd, uid, gid int) error { return errNoFollowUnsupported }

func closeFD(fd int) {}

func openFileNoFollow(dirFd int, name string, flags int, perm os.FileMode) (*os.File, error) {
	return nil, errNoFollowUnsupported
}

func readFileNoFollow(dirFd int, name string) ([]byte, error) { return nil, errNoFollowUnsupported }

func writeFileNoFollow(dirFd int, name string, data []byte, perm os.FileMode) error {
	return errNoFollowUnsupported
}

func openUserSSHDirMode(homeRoot, username string, create bool) (fd, uid, gid int, err error) {
	return -1, 0, 0, errNoFollowUnsupported
}

func createTempFileAt(dirFd int, prefix string) (*os.File, string, error) {
	return nil, "", errNoFollowUnsupported
}

func renameFileAt(dirFd int, oldName, newName string) error { return errNoFollowUnsupported }

func removeFileAt(dirFd int, name string) error { return errNoFollowUnsupported }

func syncDirFD(dirFd int) error { return errNoFollowUnsupported }
