//go:build !windows

package sshcontrol

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
)

// lockState claims exclusive checkpoint ownership across controller processes.
func lockState(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		_ = f.Close()
		return nil, fmt.Errorf("unsafe upstream state lock")
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("upstream checkpoint already owned: %w", err)
	}
	return f, nil
}
