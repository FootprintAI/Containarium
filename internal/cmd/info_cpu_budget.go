package cmd

import (
	"fmt"
	"strings"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// renderCPUBudget is the "CPU Budget" block of `containarium info` (#2284):
// tenant-committed, core-committed and physical cores, the admission gate's
// posture, and — when the gate is advisory and the host is already past its
// ceiling — a WARNING saying the gate is not enforcing. Empty when the
// daemon reported no budget (local mode, or a daemon predating the field).
func renderCPUBudget(b *incus.CPUBudget) string {
	if b == nil {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("CPU Budget:\n")
	physical := "unknown"
	if b.PhysicalCPUs > 0 {
		physical = fmt.Sprintf("%.0f", b.PhysicalCPUs)
	}
	fmt.Fprintf(&sb, "  %-18s %s\n", "Physical CPUs:", physical)
	tenant := fmt.Sprintf("%.2f cores", b.TenantCommittedCores)
	if b.PhysicalCPUs > 0 {
		tenant += fmt.Sprintf(" (%.2f×)", b.TenantRatio())
	}
	fmt.Fprintf(&sb, "  %-18s %s\n", "Tenant committed:", tenant)
	fmt.Fprintf(&sb, "  %-18s %.2f cores\n", "Core committed:", b.CoreCommittedCores)
	fmt.Fprintf(&sb, "  %-18s %s\n", "Admission gate:", describeCPUAdmission(b))
	if msg, warn := b.AdvisoryWarning(); warn {
		fmt.Fprintf(&sb, "  WARNING: %s\n", msg)
	}
	sb.WriteString("\n")
	return sb.String()
}

func describeCPUAdmission(b *incus.CPUBudget) string {
	switch b.AdmissionMode {
	case incus.CPUAdmissionAdvisory, incus.CPUAdmissionEnforcing:
		if c := b.Ceiling(); c > 0 {
			return fmt.Sprintf("%s, factor %.2f× (ceiling %.2f cores)", b.AdmissionMode, b.OvercommitFactor, c)
		}
		return fmt.Sprintf("%s, factor %.2f×", b.AdmissionMode, b.OvercommitFactor)
	case incus.CPUAdmissionDisabled:
		return "disabled"
	default:
		return "not reported"
	}
}
