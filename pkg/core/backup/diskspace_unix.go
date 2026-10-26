//go:build !windows

package backup

import "golang.org/x/sys/unix"

// statDiskSpace reports the free space an unprivileged writer sees at path,
// and the filesystem it is on.
func statDiskSpace(path string) (diskSpace, error) {
	var fs unix.Statfs_t
	if err := unix.Statfs(path, &fs); err != nil {
		return diskSpace{}, err
	}
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return diskSpace{}, err
	}
	return diskSpace{
		Free:   uint64(fs.Bavail) * uint64(fs.Bsize), // #nosec G115 -- statfs block counts and sizes are non-negative
		Device: uint64(st.Dev),                       // #nosec G115 -- device numbers are non-negative
	}, nil
}
