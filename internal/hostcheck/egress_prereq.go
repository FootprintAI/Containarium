package hostcheck

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Host prerequisites for the coding-CLI egress program (#2379,
// docs/architecture/coding-cli-egress-allowlist.md): a cgroup_skb/egress
// program attached to a box's cgroup needs kernel >= 6.6, a unified cgroup v2
// hierarchy, and the cgroup_skb program type. Not Required: the daemon runs
// without them; only that feature cannot be enforced.

// EgressPrereqReason names why an egress prerequisite check failed. Every
// failing check's Detail starts with "<reason>: ".
type EgressPrereqReason string

const (
	ReasonKernelTooOld     EgressPrereqReason = "kernel_too_old"
	ReasonKernelUnknown    EgressPrereqReason = "kernel_version_unknown"
	ReasonCgroupNotV2      EgressPrereqReason = "cgroup_not_v2"
	ReasonCgroupUnknown    EgressPrereqReason = "cgroup_version_unknown"
	ReasonNoCgroupSKB      EgressPrereqReason = "no_cgroup_skb"
	ReasonCgroupSKBUnknown EgressPrereqReason = "cgroup_skb_unknown"
)

// Minimum kernel for the egress program (the design's documented baseline).
const (
	egressMinKernelMajor = 6
	egressMinKernelMinor = 6
)

const (
	egressCheckKernel    = "egress: kernel >= 6.6"
	egressCheckCgroupV2  = "egress: cgroup v2"
	egressCheckCgroupSKB = "egress: cgroup_skb program type"
)

// errCgroupSKBUnsupported is what a cgroupSKB probe wraps when the kernel
// definitively lacks the program type (as opposed to "could not tell").
var errCgroupSKBUnsupported = errors.New("cgroup_skb program type not supported by this kernel")

// egressPrereqProbes are the host reads behind the checks, injectable so the
// verdict logic is table-tested without a particular kernel.
type egressPrereqProbes struct {
	kernelRelease func() (string, error) // uname -r
	cgroupV2      func() (bool, error)   // /sys/fs/cgroup is a cgroup2 mount
	cgroupSKB     func() error           // nil = supported
}

// EgressPrereqChecks runs the egress prerequisite checks on this host.
func EgressPrereqChecks() []Check { return egressPrereqChecks(defaultEgressPrereqProbes()) }

func egressPrereqChecks(p egressPrereqProbes) []Check {
	return []Check{kernelCheck(p), cgroupV2Check(p), cgroupSKBCheck(p)}
}

func failed(c Check, r EgressPrereqReason, format string, args ...any) Check {
	c.Detail = string(r) + ": " + fmt.Sprintf(format, args...)
	return c
}

func kernelCheck(p egressPrereqProbes) Check { return kernelTCXCheck(p.kernelRelease) }

// kernelTCXCheck reports the running kernel and whether it can attach TCX
// hooks (>= 6.6). A nil probe, a probe error or an unparseable release is
// "unknown", which fails the check rather than passing it.
func kernelTCXCheck(release func() (string, error)) Check {
	c := Check{Name: egressCheckKernel}
	if release == nil {
		return failed(c, ReasonKernelUnknown, "no kernel release probe")
	}
	rel, err := release()
	if err != nil {
		return failed(c, ReasonKernelUnknown, "cannot read kernel release: %v", err)
	}
	supported, known := KernelSupportsTCX(rel)
	if !known {
		return failed(c, ReasonKernelUnknown, "cannot parse kernel release %q", rel)
	}
	if !supported {
		return failed(c, ReasonKernelTooOld, "kernel %s is below %d.%d (TCX attach needs it)", strings.TrimSpace(rel), egressMinKernelMajor, egressMinKernelMinor)
	}
	c.OK, c.Detail = true, "kernel "+strings.TrimSpace(rel)
	return c
}

// KernelSupportsTCX reports whether a kernel release string (as printed by
// `uname -r`, e.g. "6.8.0-45-generic", "6.6.12+", "5.15.0-1050-gcp") is new
// enough for TCX attach (kernel >= 6.6). known is false when the release
// cannot be parsed; supported is then false too, and callers must treat that
// as "could not tell", not as a pass. Pure.
func KernelSupportsTCX(release string) (supported bool, known bool) {
	major, minor, ok := parseKernelRelease(release)
	if !ok {
		return false, false
	}
	return major > egressMinKernelMajor || (major == egressMinKernelMajor && minor >= egressMinKernelMinor), true
}

// parseKernelRelease reads "major.minor" from a release like
// "6.8.0-137-generic" or "6.6.12+". Both must be plain digit runs.
func parseKernelRelease(rel string) (major, minor int, ok bool) {
	parts := strings.SplitN(strings.TrimSpace(rel), ".", 3)
	if len(parts) < 2 {
		return 0, 0, false
	}
	minorStr := parts[1]
	if i := strings.IndexFunc(minorStr, func(r rune) bool { return r < '0' || r > '9' }); i >= 0 {
		minorStr = minorStr[:i]
	}
	if !allDigits(parts[0]) || !allDigits(minorStr) {
		return 0, 0, false
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(minorStr)
	return major, minor, err1 == nil && err2 == nil
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func cgroupV2Check(p egressPrereqProbes) Check {
	c := Check{Name: egressCheckCgroupV2}
	v2, err := p.cgroupV2()
	if err != nil {
		return failed(c, ReasonCgroupUnknown, "cannot determine the cgroup hierarchy: %v", err)
	}
	if !v2 {
		return failed(c, ReasonCgroupNotV2, "/sys/fs/cgroup is not a unified cgroup v2 mount (cgroup v1 or hybrid)")
	}
	c.OK, c.Detail = true, "/sys/fs/cgroup is cgroup2"
	return c
}

func cgroupSKBCheck(p egressPrereqProbes) Check {
	c := Check{Name: egressCheckCgroupSKB}
	err := p.cgroupSKB()
	switch {
	case errors.Is(err, errCgroupSKBUnsupported):
		return failed(c, ReasonNoCgroupSKB, "%v", err)
	case err != nil:
		return failed(c, ReasonCgroupSKBUnknown, "cannot probe the cgroup_skb program type (needs root/CAP_BPF): %v", err)
	}
	c.OK, c.Detail = true, "kernel loads cgroup_skb programs"
	return c
}
