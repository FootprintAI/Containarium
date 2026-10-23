//go:build !windows

package audit

import (
	"os/exec"
	"syscall"
)

// bindToProcessGroup puts the command in its own process group and makes
// cancellation kill the whole group, so a child gcloud started (and which
// holds our stdout/stderr pipes) dies with it.
func bindToProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
