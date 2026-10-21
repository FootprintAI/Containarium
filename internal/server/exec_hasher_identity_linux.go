//go:build linux

package server

import (
	"os"
	"syscall"
)

// exeIdentityOf is the cache key of an opened executable (#2768): device,
// inode, size, mtime and ctime. ctime cannot be set from user space, so
// rewriting a binary and putting its mtime back still changes the key.
func exeIdentityOf(fi os.FileInfo) (exeIdentity, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return exeIdentity{}, false
	}
	return exeIdentity{
		dev: uint64(st.Dev), ino: st.Ino, size: st.Size, // #nosec G115 -- device number, compared not computed
		mtime: st.Mtim.Nano(), ctime: st.Ctim.Nano(),
	}, true
}
