//go:build !unix

package container

import "errors"

// errNoFollowUnsupported is returned where the openat/fchownat helpers are not
// available. The jump-account paths that need them only run on Unix hosts.
var errNoFollowUnsupported = errors.New("ssh dir no-follow handling is not supported on this platform")

func openUserSSHDir(homeRoot, username string) (fd, uid, gid int, err error) {
	return -1, 0, 0, errNoFollowUnsupported
}

func chownTreeNoFollow(fd, uid, gid int) error { return errNoFollowUnsupported }

func fchownFD(fd, uid, gid int) error { return errNoFollowUnsupported }

func closeFD(fd int) {}
