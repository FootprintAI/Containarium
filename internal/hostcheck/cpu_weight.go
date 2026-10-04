//go:build !windows

package hostcheck

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// DefaultCgroupSystemSlice is where cgroup v2 exposes each system unit's
// realized resource controls on an Ubuntu 24.04 host.
const DefaultCgroupSystemSlice = "/sys/fs/cgroup/system.slice"

// platformCPUWeightCheck reports whether incusd and the containarium daemon
// are actually running at PlatformCPUWeight (#2284). It reads the EFFECTIVE
// weight from each unit's cgroup (`cpu.weight`), not the unit file: a
// drop-in that was written but never applied — no daemon-reload, no
// restart, cgroup v1 host — is exactly the gap this check exists to show.
//
// Posture rules apply: a cgroup file that is missing or unparseable is
// "could not determine", never a pass.
func platformCPUWeightCheck(p posturePaths) Check {
	c := Check{Name: "platform daemons CPU weight"}
	slice := p.cgroupSystemSlice
	if slice == "" {
		slice = DefaultCgroupSystemSlice
	}

	var ok, low, unknown []string
	for _, unit := range PlatformCPUUnits {
		path := filepath.Join(slice, unit, "cpu.weight")
		raw, err := os.ReadFile(path) // #nosec G304 -- package-owned constant dir + fixed unit names
		if err != nil {
			unknown = append(unknown, fmt.Sprintf("%s (%s: %v)", unit, path, err))
			continue
		}
		w, perr := strconv.Atoi(strings.TrimSpace(string(raw)))
		if perr != nil {
			unknown = append(unknown, fmt.Sprintf("%s (cpu.weight=%q is not a number)", unit, strings.TrimSpace(string(raw))))
			continue
		}
		if w < PlatformCPUWeight {
			low = append(low, fmt.Sprintf("%s=%d", unit, w))
			continue
		}
		ok = append(ok, fmt.Sprintf("%s=%d", unit, w))
	}

	switch {
	case len(unknown) > 0:
		c.Detail = fmt.Sprintf("could not determine the effective cpu.weight of %s — unit not running, cgroup v1, or not a systemd host; need >= %d",
			strings.Join(unknown, ", "), PlatformCPUWeight)
		if len(low) > 0 {
			c.Detail += "; below " + strconv.Itoa(PlatformCPUWeight) + ": " + strings.Join(low, ", ")
		}
	case len(low) > 0:
		c.Detail = fmt.Sprintf("%s below %d: the platform's own daemons compete with tenants at tenant priority; "+
			"re-run `containariumd service install` (writes the drop-in) and `systemctl daemon-reload`",
			strings.Join(low, ", "), PlatformCPUWeight)
	default:
		c.OK = true
		c.Detail = "effective cpu.weight " + strings.Join(ok, ", ")
	}
	return c
}
