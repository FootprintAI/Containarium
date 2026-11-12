//go:build unix

package container

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"golang.org/x/sys/unix"
)

// createTempFileAt creates a new file named prefix+random directly under dirFd,
// with O_EXCL and O_NOFOLLOW and mode 0600. It returns the open file and name.
func createTempFileAt(dirFd int, prefix string) (*os.File, string, error) {
	var b [8]byte
	for attempt := 0; attempt < 16; attempt++ {
		if _, err := rand.Read(b[:]); err != nil {
			return nil, "", err
		}
		name := prefix + hex.EncodeToString(b[:])
		fd, err := unix.Openat(dirFd, name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return nil, "", err
		}
		return os.NewFile(uintptr(fd), name), name, nil
	}
	return nil, "", fmt.Errorf("no free temp name for %s", prefix)
}

// renameFileAt renames oldName to newName within dirFd. renameat replaces a
// symlink at newName; it never follows one.
func renameFileAt(dirFd int, oldName, newName string) error {
	return unix.Renameat(dirFd, oldName, dirFd, newName)
}

// removeFileAt unlinks name within dirFd. A missing name is not an error.
func removeFileAt(dirFd int, name string) error {
	err := unix.Unlinkat(dirFd, name, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// syncDirFD fsyncs the directory fd, so a rename into it survives a crash.
func syncDirFD(dirFd int) error { return unix.Fsync(dirFd) }
