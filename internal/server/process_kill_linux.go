//go:build linux

package server

import (
	"errors"

	"golang.org/x/sys/unix"
)

// pidfdHandle signals through a pidfd (Linux 5.3+): the fd refers to the
// process that held the pid when it was opened, so a later pid reuse turns
// the signal into ESRCH instead of a kill of the new process.
type pidfdHandle struct{ fd int }

func (h pidfdHandle) Kill() error {
	err := unix.PidfdSendSignal(h.fd, unix.SIGKILL, nil, 0)
	if errors.Is(err, unix.ESRCH) {
		return errKillProcessGone
	}
	return err
}

func (h pidfdHandle) Close() error { return unix.Close(h.fd) }

// pidHandleNoFD is the fallback for a kernel without pidfd_open: a plain
// kill(2), with the cgroup re-check as the only reuse defence.
type pidHandleNoFD struct{ pid int }

func (h pidHandleNoFD) Kill() error {
	err := unix.Kill(h.pid, unix.SIGKILL)
	if errors.Is(err, unix.ESRCH) {
		return errKillProcessGone
	}
	return err
}

func (pidHandleNoFD) Close() error { return nil }

func openPID(pid int) (pidHandle, error) {
	fd, err := unix.PidfdOpen(pid, 0)
	switch {
	case err == nil:
		return pidfdHandle{fd: fd}, nil
	case errors.Is(err, unix.ESRCH):
		return nil, errKillProcessGone
	case errors.Is(err, unix.ENOSYS):
		return pidHandleNoFD{pid: pid}, nil
	default:
		return nil, err
	}
}
