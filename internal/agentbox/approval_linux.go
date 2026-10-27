//go:build linux

package agentbox

import "golang.org/x/sys/unix"

// makeNonDumpable clears the process's dumpable flag, which makes
// /proc/<pid>/mem, /proc/<pid>/environ and ptrace attach unavailable to other
// processes of the same user that lack CAP_SYS_PTRACE, whatever the host's
// yama ptrace_scope is.
func makeNonDumpable() error {
	return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}
