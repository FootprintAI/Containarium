//go:build !windows

package sshsession

import (
	"os"
	"syscall"
)

// inodeOf returns fi's inode. The shipper identifies "the same file" across
// rename-style rotation by inode, since the path alone cannot tell a rotated
// file from its replacement.
func inodeOf(fi os.FileInfo) (uint64, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(st.Ino), true // #nosec G115 -- inode numbers are unsigned
}
