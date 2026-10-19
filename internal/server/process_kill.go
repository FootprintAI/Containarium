package server

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// Host-side kill for a miner-signature match (#2638; design component 7,
// the kill_process row): re-read /proc/<pid>/cgroup, confirm the pid still
// belongs to the same container, then SIGKILL it. The pid comes from an exec
// event that may be seconds old; between the exec and the kill the process
// can exit and its pid be reused by an unrelated process, on the host or in
// another tenant's box. The cgroup re-check is what makes that reuse a
// skipped kill rather than a signal to a stranger.

var (
	// errKillPIDReused: the pid now lives in a different cgroup than the
	// container's, so it is no longer the matched process.
	errKillPIDReused = errors.New("pid reused: no longer in the container's cgroup")
	// errKillProcessGone: the process exited before the signal.
	errKillProcessGone = errors.New("process already exited")
	// errKillContainerInit: the pid is the container's init. Signalling it
	// from the host would stop the whole box; the policy action (freeze,
	// throttle) is the tool for that, not the kill.
	errKillContainerInit = errors.New("pid is the container's init")
)

// processKiller is what the responder needs for kill_process. An interface
// so the responder is unit-testable without signalling real processes.
type processKiller interface {
	// KillInContainer SIGKILLs host pid if, and only if, it is still a
	// process of container. errKillPIDReused, errKillProcessGone or
	// errKillContainerInit (wrapped) when it refuses.
	KillInContainer(container string, pid uint32) error
}

// pidHandle pins one process for the check-then-signal sequence. On Linux it
// is a pidfd, so a pid reused after the handle was opened can never receive
// the signal; see process_kill_linux.go.
type pidHandle interface {
	Kill() error
	Close() error
}

// hostProcessKiller is the real processKiller.
type hostProcessKiller struct {
	procRoot string
	// initPID returns the container's init pid on the host (0 = not running).
	initPID func(container string) (int64, error)
	// open pins pid; errKillProcessGone when it no longer exists.
	open func(pid int) (pidHandle, error)
}

func newHostProcessKiller(initPID func(string) (int64, error)) *hostProcessKiller {
	return &hostProcessKiller{procRoot: execProcRoot, initPID: initPID, open: openPID}
}

// KillInContainer implements processKiller. Order matters: pin the process
// first, then compare cgroups, then signal through the pin. A reuse that
// happens after the pin makes the signal fail (the pinned process is gone)
// instead of reaching the newcomer.
func (k *hostProcessKiller) KillInContainer(container string, pid uint32) error {
	if pid <= 1 {
		return fmt.Errorf("refusing to signal pid %d", pid)
	}
	initPID, err := k.initPID(container)
	if err != nil {
		return fmt.Errorf("read init pid of %s: %w", container, err)
	}
	if initPID <= 0 {
		return fmt.Errorf("container %s is not running: %w", container, errKillProcessGone)
	}
	if int64(pid) == initPID {
		return fmt.Errorf("pid %d: %w", pid, errKillContainerInit)
	}
	h, err := k.open(int(pid))
	if err != nil {
		return fmt.Errorf("pid %d: %w", pid, err)
	}
	defer func() { _ = h.Close() }()

	want, err := containerCgroupOf(k.procRoot, initPID)
	if err != nil {
		return fmt.Errorf("resolve cgroup of %s init %d: %w", container, initPID, err)
	}
	got, err := containerCgroupOf(k.procRoot, int64(pid))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("pid %d: %w", pid, errKillProcessGone)
		}
		return fmt.Errorf("resolve cgroup of pid %d: %w", pid, err)
	}
	if got != want {
		return fmt.Errorf("pid %d in %q, container %s in %q: %w", pid, got, container, want, errKillPIDReused)
	}
	if err := h.Kill(); err != nil {
		return fmt.Errorf("pid %d: %w", pid, err)
	}
	return nil
}

// containerCgroupOf reads /proc/<pid>/cgroup and returns the container root
// cgroup it sits under (containerCgroupRoot), the same resolution the exec
// watcher registers with the kernel.
func containerCgroupOf(procRoot string, pid int64) (string, error) {
	// #nosec G304 -- procRoot is a constant (or a test fixture) and pid an
	// integer from Incus or the kernel's exec record.
	raw, err := os.ReadFile(filepath.Join(procRoot, strconv.FormatInt(pid, 10), "cgroup"))
	if err != nil {
		return "", err
	}
	rel := incus.CgroupV2PathFromProc(string(raw))
	if rel == "" {
		return "", fmt.Errorf("pid %d: no cgroup v2 path", pid)
	}
	return containerCgroupRoot(rel), nil
}
