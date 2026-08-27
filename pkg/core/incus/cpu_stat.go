package incus

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// cgroupV2Root is where the unified cgroup v2 hierarchy is mounted on the host
// the daemon runs on.
const cgroupV2Root = "/sys/fs/cgroup"

// cpuThrottle holds the CFS bandwidth-throttling counters a cgroup reports in
// cpu.stat.
//
// These are what separate a *throttled* box from an *idle* one. Cumulative
// CPU-seconds alone reads as the same low number in both cases, which is why a
// starved tenant has no observable signal saying so today (#1573). A box whose
// nr_throttled climbs is hitting its own CFS quota — the
// limits.cpu.allowance ceiling written by cpu_limits.go. A box with flat
// nr_throttled and low usage is either genuinely idle or losing the host CPU
// race to its neighbours; the box's own cgroup cannot tell those apart, so that
// distinction needs the host's committed:physical ratio as well (#1571).
//
// All three are cumulative over the container's lifetime, matching how
// CPUUsageSeconds already behaves — callers take deltas between two reads.
type cpuThrottle struct {
	NrPeriods     int64 // CFS periods elapsed
	NrThrottled   int64 // periods in which the container was throttled
	ThrottledUsec int64 // total time spent throttled, in microseconds
}

// parseCPUStat parses the contents of a cgroup cpu.stat file.
//
// The bool reports whether any throttling counter was found — not whether the
// container was throttled. A cgroup with no CPU bandwidth limit omits the
// throttling keys entirely on some kernels and reports usage only; that is a
// legitimate "no signal available" answer rather than a parse error, and the
// caller leaves the fields unset instead of publishing a misleading zero.
//
// Unparseable values are skipped individually so one malformed line cannot
// discard the counters around it.
func parseCPUStat(content string) (cpuThrottle, bool) {
	var t cpuThrottle
	found := false

	for _, line := range strings.Split(content, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		if err != nil {
			continue
		}
		switch key {
		case "nr_periods":
			t.NrPeriods, found = n, true
		case "nr_throttled":
			t.NrThrottled, found = n, true
		case "throttled_usec":
			t.ThrottledUsec, found = n, true
		case "throttled_time":
			// cgroup v1 spells the same counter in nanoseconds. Normalize so
			// callers see one unit regardless of the host's hierarchy.
			t.ThrottledUsec, found = n/1000, true
		}
	}

	return t, found
}

// cgroupV2PathFromProc extracts the unified-hierarchy cgroup path from the
// contents of a /proc/<pid>/cgroup file, relative to the cgroup root.
//
// Only the "0::" line is usable: on a hybrid host the v1 controllers are listed
// first with their own paths, and cpu.stat lives under the v2 mount. A process
// in the root cgroup ("0::/") yields "" — there is no per-container subtree to
// read.
//
// Deriving the path from the container's init PID rather than assembling a
// conventional name ("lxc.payload.<name>") keeps this working across Incus's
// scope-naming variations and systemd-managed nesting.
func cgroupV2PathFromProc(content string) string {
	for _, line := range strings.Split(content, "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "0::")
		if !ok {
			continue
		}
		return strings.Trim(rest, "/")
	}
	return ""
}

// readCPUThrottle resolves a process's cgroup and reads its throttling counters
// from cgroupRoot.
//
// Every failure is a silent "no signal": metrics collection must not fail — or
// log per container per scrape — just because a host mounts its cgroups
// differently or the container exited between the state read and this one.
func readCPUThrottle(procCgroupPath, cgroupRoot string) (cpuThrottle, bool) {
	// #nosec G304 -- callers build this as /proc/<pid>/cgroup from an int64
	// PID that Incus reported; it is a parameter only so the resolve-and-read
	// path is testable against a fixture tree.
	raw, err := os.ReadFile(procCgroupPath)
	if err != nil {
		return cpuThrottle{}, false
	}

	rel := cgroupV2PathFromProc(string(raw))
	if rel == "" {
		return cpuThrottle{}, false
	}

	// The cgroup path is read out of /proc, so it is host-derived rather than
	// tenant-supplied — but it is still a variable path being resolved against
	// a host directory, so contain it at the OS level instead of by inspection.
	// os.Root refuses any traversal out of cgroupRoot, symlinks included, which
	// a filepath.Clean check cannot promise.
	root, err := os.OpenRoot(cgroupRoot)
	if err != nil {
		return cpuThrottle{}, false
	}
	defer func() { _ = root.Close() }()

	f, err := root.Open(filepath.Join(rel, "cpu.stat"))
	if err != nil {
		return cpuThrottle{}, false
	}
	defer func() { _ = f.Close() }()

	stat, err := io.ReadAll(f)
	if err != nil {
		return cpuThrottle{}, false
	}
	return parseCPUStat(string(stat))
}

// containerCPUThrottle reads the CFS throttling counters for the container
// whose init process is pid. A non-positive pid (a stopped container) has no
// cgroup to read.
func containerCPUThrottle(pid int64) (cpuThrottle, bool) {
	if pid <= 0 {
		return cpuThrottle{}, false
	}
	return readCPUThrottle(fmt.Sprintf("/proc/%d/cgroup", pid), cgroupV2Root)
}
