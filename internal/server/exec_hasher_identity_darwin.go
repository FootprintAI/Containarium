//go:build darwin

package server

import (
	"os"
	"syscall"
)

// exeIdentityOf: see exec_hasher_identity_linux.go. Darwin builds run the
// unit tests; the daemon itself runs on Linux.
func exeIdentityOf(fi os.FileInfo) (exeIdentity, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return exeIdentity{}, false
	}
	return exeIdentity{
		dev: uint64(st.Dev), ino: st.Ino, size: st.Size, // #nosec G115 -- device number, compared not computed
		mtime: st.Mtimespec.Nano(), ctime: st.Ctimespec.Nano(),
	}, true
}
