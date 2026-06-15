package cloud

import (
	"bufio"
	"context"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/footprintai/containarium/internal/hostcheck"
	"github.com/footprintai/containarium/internal/safecast"
	"github.com/footprintai/containarium/pkg/version"
)

// DefaultStatusProbe is the daemon's host-capability probe: it self-measures
// hardware (CPU cores, RAM, disk, GPU), reports the running agent version, and
// runs the `doctor` capability self-check (the DEGRADED signal — running-as-
// root / caps / useradd probe). It satisfies StatusProbe so the actuation
// client's status loop pushes it to the cloud, making the BYO fleet view show
// real specs + headroom + health.
//
// Introspection is intentionally lightweight (runtime + /proc + statfs +
// /dev/nvidia* + nvidia-smi) so it's cheap enough to run every report cycle —
// distinct from the daemon's one-shot nvidia.runtime LXC GPU validation.
type DefaultStatusProbe struct{}

// Probe gathers the current capability snapshot. Best-effort: a field it can't
// measure on this platform is reported as zero rather than failing the whole
// report (the cloud treats zero as "not reported"). The self-check is run
// in-process; for an accurate caps/useradd result the daemon must run under
// its hardened systemd unit (same caveat as `containarium doctor`).
func (DefaultStatusProbe) Probe(_ context.Context) (HostStatus, error) {
	totalRAM, availRAM := readMemInfoMB()
	totalDisk, availDisk := diskGB()
	gpuCount, gpuSpec := gpuInfo()
	raw := hostcheck.Run()
	checks := make([]HostCheck, 0, len(raw))
	for _, c := range raw {
		checks = append(checks, HostCheck{Name: c.Name, OK: c.OK, Detail: c.Detail})
	}
	return HostStatus{
		AgentVersion:  version.GetVersion(),
		CPUCores:      safecast.I32(runtime.NumCPU()),
		TotalRAMMB:    totalRAM,
		AvailRAMMB:    availRAM,
		TotalDiskGB:   totalDisk,
		AvailDiskGB:   availDisk,
		TotalGPUCount: gpuCount,
		// No host-local in-use tracking; the cloud scheduler accounts for
		// assigned GPUs. Report all detected GPUs as available headroom.
		AvailGPUCount: gpuCount,
		GPUSpec:       gpuSpec,
		SelfCheckOK:   hostcheck.AllRequiredPass(raw),
		Checks:        checks,
	}, nil
}

// readMemInfoMB reads MemTotal + MemAvailable from /proc/meminfo (Linux) and
// returns them in MB. Returns (0, 0) on any non-Linux / unreadable host — the
// report still goes out, just without RAM numbers.
func readMemInfoMB() (total, avail int32) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "MemTotal:"):
			total = kbFieldToMB(line)
		case strings.HasPrefix(line, "MemAvailable:"):
			avail = kbFieldToMB(line)
		}
	}
	return total, avail
}

// kbFieldToMB parses a "/proc/meminfo" line like "MemTotal:  32791234 kB" and
// returns the value in MB (0 on parse failure).
func kbFieldToMB(line string) int32 {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0
	}
	kb, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return 0
	}
	return safecast.I32(int(kb / 1024))
}
