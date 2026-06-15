package cloud

import (
	"bufio"
	"context"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/footprintai/containarium/internal/safecast"
	"github.com/footprintai/containarium/pkg/version"
)

// DefaultStatusProbe is the daemon's host-capability probe: it self-measures
// hardware (CPU cores, total + available RAM) and reports the running agent
// version. It satisfies StatusProbe so the actuation client's status loop can
// push it to the cloud, making the BYO fleet view show real specs + headroom.
//
// NOTE: the `doctor` capability self-check (the DEGRADED signal — running-as-
// root / caps / useradd probe) is NOT yet reported here. Those checks live in
// internal/cmd/doctor.go and can't be imported from the daemon layer without a
// shared-package extraction; that's a fast follow-up. Until then the probe
// reports SelfCheckOK=true with no checks, so a reporting host shows CONNECTED
// with its hardware. Disk + GPU are likewise left for a follow-up (0 = not
// reported), since they need Incus/storage introspection.
type DefaultStatusProbe struct{}

// Probe gathers the current capability snapshot. Best-effort: a field it can't
// measure on this platform is reported as zero rather than failing the whole
// report (the cloud treats zero as "not reported").
func (DefaultStatusProbe) Probe(_ context.Context) (HostStatus, error) {
	total, avail := readMemInfoMB()
	return HostStatus{
		AgentVersion: version.GetVersion(),
		CPUCores:     safecast.I32(runtime.NumCPU()),
		TotalRAMMB:   total,
		AvailRAMMB:   avail,
		SelfCheckOK:  true, // doctor self-check reporting is a follow-up
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
