package incus

import (
	"fmt"
	"strconv"
	"strings"
)

// cpuLimit holds the Incus instance-config representation of a CPU request.
// At most one of Count or Allowance is non-empty:
//
//   - Count     → set as `limits.cpu` (whole-core count "2" or CPU set "0-3").
//   - Allowance → set as `limits.cpu.allowance` (fractional share expressed as
//     a percentage, e.g. "25%").
//
// Incus's `limits.cpu` key only accepts an integer core count or a set/range;
// fractional CPU must go through `limits.cpu.allowance`. Passing millicpu
// notation ("250m") straight to `limits.cpu` is rejected by Incus with
// "Invalid CPU limit syntax". See issue #401.
type cpuLimit struct {
	Count     string
	Allowance string
}

// parseCPULimit translates a Containarium CPU request string into the Incus
// config key it maps to.
//
// Accepted inputs:
//   - whole-core count:    "1", "4"           → limits.cpu
//   - CPU set / pinning:   "0-3", "0,2-4"     → limits.cpu (passed through)
//   - Kubernetes millicpu: "250m" (0.25 core) → limits.cpu.allowance "25%"
//   - decimal cores:       "0.25", "1.5"      → limits.cpu.allowance "25%" / "150%"
//
// Millicpu / decimals that resolve to a whole number of cores ("1000m",
// "2.0") map back to limits.cpu as an integer count. An empty request returns
// a zero cpuLimit (no keys to set).
func parseCPULimit(cpu string) (cpuLimit, error) {
	cpu = strings.TrimSpace(cpu)
	if cpu == "" {
		return cpuLimit{}, nil
	}

	// CPU set / pinning notation ("0-3", "0,2-4") — pass through to limits.cpu.
	// A leading "-" is a negative sign, not a range separator, so only treat an
	// interior "-" as set notation; negatives fall through to be rejected below.
	if strings.Contains(cpu, ",") || (strings.Contains(cpu, "-") && cpu[0] != '-') {
		return cpuLimit{Count: cpu}, nil
	}

	// Resolve the request to a fractional number of cores.
	var cores float64
	if strings.HasSuffix(cpu, "m") {
		// Kubernetes millicpu: "250m" == 0.25 core.
		milli, err := strconv.Atoi(strings.TrimSuffix(cpu, "m"))
		if err != nil || milli < 0 {
			return cpuLimit{}, fmt.Errorf("invalid millicpu CPU request %q", cpu)
		}
		cores = float64(milli) / 1000
	} else {
		f, err := strconv.ParseFloat(cpu, 64)
		if err != nil || f < 0 {
			return cpuLimit{}, fmt.Errorf("invalid CPU request %q", cpu)
		}
		cores = f
	}

	if cores == 0 {
		return cpuLimit{}, fmt.Errorf("CPU request %q resolves to zero cores", cpu)
	}

	// Whole-core requests map to an integer limits.cpu count.
	if cores == float64(int64(cores)) {
		return cpuLimit{Count: strconv.FormatInt(int64(cores), 10)}, nil
	}

	// Fractional requests become a percentage allowance. 0.25 core → "25%".
	pct := cores * 100
	return cpuLimit{Allowance: strconv.FormatFloat(pct, 'f', -1, 64) + "%"}, nil
}

// formatCPULimitFromConfig renders the CPU request stored in an Incus instance
// config back into the Containarium representation, for display in container
// info. A whole-core count or set is returned verbatim from `limits.cpu`; a
// fractional `limits.cpu.allowance` percentage is converted back to Kubernetes
// millicpu ("25%" → "250m"). A non-percentage (time-slice) allowance has no
// millicpu equivalent and is returned as-is. Returns "" when neither key is
// set.
func formatCPULimitFromConfig(config map[string]string) string {
	if v, ok := config["limits.cpu"]; ok && v != "" {
		return v
	}
	allowance, ok := config["limits.cpu.allowance"]
	if !ok || allowance == "" {
		return ""
	}
	if !strings.HasSuffix(allowance, "%") {
		return allowance
	}
	pct, err := strconv.ParseFloat(strings.TrimSuffix(allowance, "%"), 64)
	if err != nil {
		return allowance
	}
	milli := int64(pct * 10) // 25% → 250m
	return strconv.FormatInt(milli, 10) + "m"
}
