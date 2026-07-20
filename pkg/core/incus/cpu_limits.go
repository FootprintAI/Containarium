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
//   - Allowance → set as `limits.cpu.allowance`, always in the time-slice form
//     ("25ms/100ms", "800ms/100ms").
//
// Incus's `limits.cpu` key only accepts an integer core count or a set/range;
// fractional CPU must go through `limits.cpu.allowance`. Passing millicpu
// notation ("250m") straight to `limits.cpu` is rejected by Incus with
// "Invalid CPU limit syntax". See issue #401.
//
// Both whole-core and fractional requests set BOTH fields: Count is the
// visible cpuset (so LXCFS can derive an honest /proc/cpuinfo processor
// count — allowance-only containers otherwise report the host's full core
// count, see #1019/#1021) and Allowance is the CFS-bandwidth quota scoped to
// that visible count. Without Allowance, `limits.cpu` only bounds *which*
// cores are visible, not how much CPU *time* they may consume — a whole-core
// request of "8" on an 8-core host was otherwise unthrottled (see #1029).
// CPU-set / pinning notation ("0-3") is the one exception: it sets only
// Count, since a meaningful allowance can't be derived from an arbitrary
// core-index set.
//
// The time-slice form is deliberate (#1034). Incus reads the two allowance
// syntaxes differently:
//
//	400%          → soft share, applied only under contention; cpu.max stays "max"
//	400ms/100ms   → hard CFS quota; cpu.max reads "400000 100000"
//
// A soft share is work-conserving and utilization-friendly, but it does not
// give a tenant a *bounded* entitlement: with idle neighbours a single
// container still bursts to the whole host, which is exactly the shape that
// saturated a backend host and wedged `incus exec` for every other tenant in
// #1029. We bill and schedule against the nominal request, and the request
// syntax is Kubernetes millicpu — whose `limits.cpu` is likewise a hard CFS
// quota — so a hard ceiling is the semantic that matches both the contract
// and the caller's expectation.
type cpuLimit struct {
	Count     string
	Allowance string
}

// parseCPULimit translates a Containarium CPU request string into the Incus
// config key(s) it maps to.
//
// Accepted inputs:
//   - whole-core count:    "1", "4"           → limits.cpu "1"/"4" + limits.cpu.allowance "100ms/100ms"/"400ms/100ms"
//   - CPU set / pinning:   "0-3", "0,2-4"     → limits.cpu (passed through, no allowance)
//   - Kubernetes millicpu: "250m" (0.25 core) → limits.cpu "1" + limits.cpu.allowance "25ms/100ms"
//   - decimal cores:       "0.25", "1.5"      → limits.cpu "1"/"2" + limits.cpu.allowance "25ms/100ms"/"150ms/100ms"
//
// Every numeric request (whole or fractional) sets both limits.cpu
// (ceil(cores), so LXCFS can report an honest /proc/cpuinfo processor count)
// and limits.cpu.allowance (the hard CFS quota) — see the cpuLimit doc
// comment, #1029 and #1034. Only CPU-set/pinning notation sets Count alone.
// An empty request returns a zero cpuLimit (no keys to set).
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

	// Whole-core requests map to an integer limits.cpu count, plus a matching
	// quota so the visible cores are also time-bounded (#1029) — a bare
	// limits.cpu on an N-core host otherwise leaves N cores fully
	// unthrottled. 4 cores → limits.cpu="4", allowance="400ms/100ms".
	if cores == float64(int64(cores)) {
		return cpuLimit{
			Count:     strconv.FormatInt(int64(cores), 10),
			Allowance: cpuQuota(cores),
		}, nil
	}

	// Fractional requests get the same quota, plus a whole-core ceiling count
	// so LXCFS can report an honest /proc/cpuinfo processor count instead of
	// the host's full core count (#1019/#1021).
	// 0.25 core → limits.cpu="1", allowance="25ms/100ms".
	return cpuLimit{
		Count:     strconv.FormatInt(int64(math.Ceil(cores)), 10),
		Allowance: cpuQuota(cores),
	}, nil
}

// cpuQuotaPeriodMs is the CFS period the quota is expressed against. 100ms is
// the kernel default and what Incus's own documentation uses, so an operator
// reading `limits.cpu.allowance` sees the same shape they'd type by hand.
const cpuQuotaPeriodMs = 100

// cpuQuota renders a core count as Incus's hard-quota allowance form.
// Granularity is 1ms of quota == 1% of a core; a request finer than that
// (below ~10m) rounds up to the 1ms floor rather than to zero, since a zero
// quota would be rejected by Incus and a container that may never run is
// never what the caller meant.
func cpuQuota(cores float64) string {
	ms := int64(math.Round(cores * cpuQuotaPeriodMs))
	if ms < 1 {
		ms = 1
	}
	return fmt.Sprintf("%dms/%dms", ms, cpuQuotaPeriodMs)
}

// formatCPULimitFromConfig renders the CPU request stored in an Incus instance
// config back into the Containarium representation, for display in container
// info. `limits.cpu.allowance` is checked first and, if present, converted
// back to Kubernetes millicpu ("25ms/100ms" → "250m") — requests set both
// `limits.cpu` (a whole-core ceiling, for LXCFS) and `limits.cpu.allowance`
// (the actual quota), and allowance is the precise value; falling back to
// `limits.cpu` first would display a "250m" request back as "1", losing the
// fractional precision. An allowance that resolves to a whole number of cores
// formats back as the plain core count ("400ms/100ms" → "4") rather than
// millicpu ("4000m") — numerically equivalent, but the plain count matches
// what the caller originally typed.
//
// Both allowance syntaxes are accepted on the way back: the time-slice form
// this package now writes (#1034) and the percentage form written before it,
// which containers created by an older daemon still carry.
//
// `limits.cpu` is used verbatim only when no allowance is set (a CPU
// set/range, or a pre-#1029 whole-core config with no allowance key yet). An
// allowance in neither recognised form is returned as-is. Returns "" when
// neither key is set.
func formatCPULimitFromConfig(config map[string]string) string {
	allowance, ok := config["limits.cpu.allowance"]
	if !ok || allowance == "" {
		if v, ok := config["limits.cpu"]; ok && v != "" {
			return v
		}
		return ""
	}
	cores, ok := parseAllowanceCores(allowance)
	if !ok {
		return allowance
	}
	if cores == float64(int64(cores)) {
		return strconv.FormatInt(int64(cores), 10)
	}
	milli := int64(math.Round(cores * 1000)) // 0.25 core → 250m
	return strconv.FormatInt(milli, 10) + "m"
}

// parseAllowanceCores resolves a `limits.cpu.allowance` value back to a core
// count: "400ms/100ms" → 4, "25%" → 0.25. Reports false for anything it
// doesn't recognise (including a zero period, which would divide by zero).
func parseAllowanceCores(allowance string) (float64, bool) {
	if pctStr, ok := strings.CutSuffix(allowance, "%"); ok {
		pct, err := strconv.ParseFloat(pctStr, 64)
		if err != nil {
			return 0, false
		}
		return pct / 100, true
	}
	quotaStr, periodStr, ok := strings.Cut(allowance, "/")
	if !ok {
		return 0, false
	}
	quota, qerr := strconv.ParseFloat(strings.TrimSuffix(quotaStr, "ms"), 64)
	period, perr := strconv.ParseFloat(strings.TrimSuffix(periodStr, "ms"), 64)
	if qerr != nil || perr != nil || period == 0 {
		return 0, false
	}
	return quota / period, true
}
