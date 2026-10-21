package server

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/footprintai/containarium/internal/threatdetect"
	"github.com/footprintai/containarium/pkg/core/incus"
)

// Host-side kill for a miner-signature match (#2638; design component 7,
// the kill_process row): re-read /proc/<pid>/cgroup, confirm the pid still
// belongs to the same container, then SIGKILL it. The pid comes from an exec
// event that may be seconds old; between the exec and the kill the process
// can exit and its pid be reused by an unrelated process, on the host or in
// another tenant's box. The cgroup re-check is what makes that reuse a
// skipped kill rather than a signal to a stranger; the start-time compare
// (#2765) does the same for a reuse inside the same box.

var (
	// errKillPIDReused: the pid is no longer the matched process: it now
	// lives in a different cgroup than the container's, or its start time
	// differs from the matched exec's (reused inside the same box, #2765).
	// The wrapping error says which.
	errKillPIDReused = errors.New("pid reused")
	// errKillProcessGone: the process exited before the signal.
	errKillProcessGone = errors.New("process already exited")
	// errKillContainerInit: the pid is the container's init. Signalling it
	// from the host would stop the whole box; the policy action (freeze,
	// throttle) is the tool for that, not the kill.
	errKillContainerInit = errors.New("pid is the container's init")
	// errKillStartTimeUnknown: the matched exec carries no start time (#2765):
	// its process had already exited when the watcher decoded the exec, so
	// whatever holds the pid now cannot be confirmed as the matched process.
	errKillStartTimeUnknown = errors.New("start time unknown: the matched process had exited before its exec was decoded")
)

// processKiller is what the responder needs for kill_process. An interface
// so the responder is unit-testable without signalling real processes.
type processKiller interface {
	// KillInContainer SIGKILLs host pid if, and only if, it is still the
	// process of container that started at start (the matched exec's
	// /proc/<pid>/stat start time, #2765). errKillPIDReused,
	// errKillProcessGone, errKillContainerInit or errKillStartTimeUnknown
	// (wrapped) when it refuses.
	KillInContainer(container string, pid uint32, start threatdetect.ProcStartTicks) error
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
// first, then compare cgroups and start time, then signal through the pin.
// A reuse that happens after the pin makes the signal fail (the pinned
// process is gone) instead of reaching the newcomer. The cgroup check
// catches a reuse by the host or another box; the start-time check catches
// a reuse inside the same box between the exec and the pin (#2765): both
// sides are /proc/<pid>/stat field 22, the same clock and unit.
func (k *hostProcessKiller) KillInContainer(container string, pid uint32, start threatdetect.ProcStartTicks) error {
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
	if start == 0 {
		return fmt.Errorf("pid %d: %w", pid, errKillStartTimeUnknown)
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
	// After the pin: while the pinned process lives it holds the pid, so
	// /proc/<pid> is that process; if it died since, /proc/<pid> is gone
	// or a newcomer, and either way the compare refuses.
	cur, err := readProcStartTime(k.procRoot, pid)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("pid %d: %w", pid, errKillProcessGone)
		}
		return fmt.Errorf("read start time of pid %d: %w", pid, err)
	}
	if cur != start {
		return fmt.Errorf("pid %d started at %d ticks, matched exec at %d: %w", pid, cur, start, errKillPIDReused)
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

// procStatStartTimeField is the 1-based field of /proc/<pid>/stat holding
// the process start time (proc(5): "(22) starttime", clock ticks since
// boot). Fields are counted from 3 after the comm's closing parenthesis.
const procStatStartTimeField = 22

// readProcStartTime reads pid's start time from <procRoot>/<pid>/stat. A
// missing file (fs.ErrNotExist) means the process is gone.
func readProcStartTime(procRoot string, pid uint32) (threatdetect.ProcStartTicks, error) {
	// #nosec G304 -- procRoot is a constant (or a test fixture) and pid an
	// integer from the kernel's exec record.
	raw, err := os.ReadFile(filepath.Join(procRoot, strconv.FormatUint(uint64(pid), 10), "stat"))
	if err != nil {
		return 0, err
	}
	return parseProcStatStartTime(raw)
}

// parseProcStatStartTime returns field 22 of a /proc/<pid>/stat line. The
// comm (field 2) is in parentheses and may itself contain spaces and
// parentheses, so the fields are split after the LAST ')' — a process
// cannot rename itself into shifting the start time. 0 is never a valid
// start time here (it is the "unknown" value), so it is an error.
func parseProcStatStartTime(stat []byte) (threatdetect.ProcStartTicks, error) {
	i := bytes.LastIndexByte(stat, ')')
	if i < 0 {
		return 0, errors.New("stat: no comm terminator")
	}
	fields := strings.Fields(string(stat[i+1:]))
	const idx = procStatStartTimeField - 3 // fields[0] is field 3 (state)
	if len(fields) <= idx {
		return 0, fmt.Errorf("stat: %d fields after comm, need %d", len(fields), idx+1)
	}
	v, err := strconv.ParseUint(fields[idx], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("stat: start time %q: %w", fields[idx], err)
	}
	if v == 0 {
		return 0, errors.New("stat: start time 0")
	}
	return threatdetect.ProcStartTicks(v), nil
}
