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

func openPID(pid int) (pidHandle, error) {
	fd, err := unix.PidfdOpen(pid, 0)
	switch {
	case err == nil:
		return pidfdHandle{fd: fd}, nil
	case errors.Is(err, unix.ESRCH):
		return nil, errKillProcessGone
	case errors.Is(err, unix.ENOSYS):
		// No pidfd (kernel < 5.3, below the exec object's 5.8 floor anyway):
		// refuse rather than fall back to a check-then-kill(2) race.
		return nil, errors.New("pidfd_open unsupported; refusing an unpinned kill")
	default:
		return nil, err
	}
}
