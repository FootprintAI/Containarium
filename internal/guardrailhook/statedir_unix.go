//go:build !windows

package guardrailhook

import (
	"fmt"
	"os"
	"syscall"
)

// checkPrivateDir refuses a state directory another user could read or
// replace: it must belong to the calling user and carry no group or other
// permission bits.
func checkPrivateDir(dir string, info os.FileInfo) error {
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("guardrail state directory %s has mode %04o and is open to other users; it must be 0700 (chmod 700 it, or remove it to start again)", dir, perm)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return fmt.Errorf("guardrail state directory %s belongs to another user (uid %d); it must belong to the user the agent runs as", dir, st.Uid)
	}
	return nil
}
