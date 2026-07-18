package incus

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// cpuLimit holds the Incus instance-config representation of a CPU request.
//
//   - Count     → set as `limits.cpu` (whole-core count "2" or CPU set "0-3").
//   - Allowance → set as `limits.cpu.allowance` (fractional share expressed as
//     a percentage, e.g. "25%").
//
// Incus's `limits.cpu` key only accepts an integer core count or a set/range;
// fractional CPU must go through `limits.cpu.allowance`. Passing millicpu
// notation ("250m") straight to `limits.cpu` is rejected by Incus with
// "Invalid CPU limit syntax". See issue #401.
//
// Fractional requests set BOTH fields: Count is the ceiling whole-core count
// (so LXCFS has a cpuset to derive an honest /proc/cpuinfo processor count
// from — allowance-only containers otherwise report the host's full core
// count, see #1019/#1021) and Allowance is the actual CFS-bandwidth throttle
// within that visible core count. Whole-core / CPU-set requests set only
// Count.
type cpuLimit struct {
	Count     string
	Allowance string
}

// parseCPULimit translates a Containarium CPU request string into the Incus
// config key(s) it maps to.
//
// Accepted inputs:
//   - whole-core count:    "1", "4"           → limits.cpu
//   - CPU set / pinning:   "0-3", "0,2-4"     → limits.cpu (passed through)
//   - Kubernetes millicpu: "250m" (0.25 core) → limits.cpu "1" + limits.cpu.allowance "25%"
//   - decimal cores:       "0.25", "1.5"      → limits.cpu "1"/"2" + limits.cpu.allowance "25%"/"150%"
//
// Millicpu / decimals that resolve to a whole number of cores ("1000m",
// "2.0") map back to limits.cpu as an integer count, with no allowance set.
// Other fractional requests set both limits.cpu (ceil(cores), so LXCFS can
// report an honest /proc/cpuinfo processor count) and limits.cpu.allowance
// (the actual throttle) — see the cpuLimit doc comment. An empty request
// returns a zero cpuLimit (no keys to set).
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

	// Fractional requests become a percentage allowance, plus a whole-core
	// ceiling count so LXCFS can report an honest /proc/cpuinfo processor
	// count instead of the host's full core count (#1019/#1021).
	// 0.25 core → limits.cpu="1", limits.cpu.allowance="25%".
	pct := cores * 100
	return cpuLimit{
		Count:     strconv.FormatInt(int64(math.Ceil(cores)), 10),
		Allowance: strconv.FormatFloat(pct, 'f', -1, 64) + "%",
	}, nil
}

// formatCPULimitFromConfig renders the CPU request stored in an Incus instance
// config back into the Containarium representation, for display in container
// info. `limits.cpu.allowance` is checked first and, if present, converted
// back to Kubernetes millicpu ("25%" → "250m") — fractional requests set both
// `limits.cpu` (a whole-core ceiling, for LXCFS) and `limits.cpu.allowance`
// (the actual throttle), and allowance is the precise value; falling back to
// `limits.cpu` first would display a "250m" request back as "1", losing the
// fractional precision. `limits.cpu` is used verbatim only when no allowance
// is set (genuine whole-core count or CPU set/range). A non-percentage
// (time-slice) allowance has no millicpu equivalent and is returned as-is.
// Returns "" when neither key is set.
func formatCPULimitFromConfig(config map[string]string) string {
	allowance, ok := config["limits.cpu.allowance"]
	if !ok || allowance == "" {
		if v, ok := config["limits.cpu"]; ok && v != "" {
			return v
		}
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
