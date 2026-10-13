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

func kernelCheck(p egressPrereqProbes) Check {
	c := Check{Name: egressCheckKernel}
	rel, err := p.kernelRelease()
	if err != nil {
		return failed(c, ReasonKernelUnknown, "cannot read kernel release: %v", err)
	}
	major, minor, ok := parseKernelRelease(rel)
	if !ok {
		return failed(c, ReasonKernelUnknown, "cannot parse kernel release %q", rel)
	}
	if major < egressMinKernelMajor || (major == egressMinKernelMajor && minor < egressMinKernelMinor) {
		return failed(c, ReasonKernelTooOld, "kernel %s is below %d.%d", rel, egressMinKernelMajor, egressMinKernelMinor)
	}
	c.OK, c.Detail = true, "kernel "+rel
	return c
}

// parseKernelRelease reads "major.minor" from a release like "6.8.0-137-generic".
func parseKernelRelease(rel string) (major, minor int, ok bool) {
	parts := strings.SplitN(rel, ".", 3)
	if len(parts) < 2 {
		return 0, 0, false
	}
	minorStr := parts[1]
	if i := strings.IndexFunc(minorStr, func(r rune) bool { return r < '0' || r > '9' }); i >= 0 {
		minorStr = minorStr[:i]
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(minorStr)
	return major, minor, err1 == nil && err2 == nil
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
