package mcp

import (
	"fmt"
	"strings"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// cpuAdmissionModeFromWire maps the proto enum NAME grpc-gateway emits onto
// the core posture type. This package keeps plain wire structs rather than
// pkg/pb (see the ListBackendsResponse comment in client.go), so the names
// are matched here the same way the passthrough-route protocol names are.
func cpuAdmissionModeFromWire(name string) incus.CPUAdmissionMode {
	switch name {
	case "CPU_ADMISSION_MODE_DISABLED":
		return incus.CPUAdmissionDisabled
	case "CPU_ADMISSION_MODE_ADVISORY":
		return incus.CPUAdmissionAdvisory
	case "CPU_ADMISSION_MODE_ENFORCING":
		return incus.CPUAdmissionEnforcing
	default:
		return incus.CPUAdmissionUnknown
	}
}

// formatCPUBudget renders SystemInfo's CPU budget (#2284) for
// get_system_info — a thin wrapper over the same numbers and the same
// advisory warning `containarium info` prints.
func formatCPUBudget(info SystemInfo) string {
	mode := cpuAdmissionModeFromWire(info.CpuAdmissionMode)
	if mode == incus.CPUAdmissionUnknown {
		return "CPU budget: not reported (daemon predates this field)\n"
	}
	b := incus.CPUBudget{
		PhysicalCPUs:         float64(info.TotalCpus),
		TenantCommittedCores: info.CommittedCpuCores,
		CoreCommittedCores:   info.CoreCommittedCpuCores,
		OvercommitFactor:     info.CpuOvercommitFactor,
		AdmissionMode:        mode,
	}
	var sb strings.Builder
	sb.WriteString("CPU budget:\n")
	if b.PhysicalCPUs > 0 {
		fmt.Fprintf(&sb, "  Physical CPUs: %.0f\n", b.PhysicalCPUs)
		fmt.Fprintf(&sb, "  Tenant committed: %.2f cores (%.2f×)\n", b.TenantCommittedCores, b.TenantRatio())
	} else {
		sb.WriteString("  Physical CPUs: unknown\n")
		fmt.Fprintf(&sb, "  Tenant committed: %.2f cores\n", b.TenantCommittedCores)
	}
	fmt.Fprintf(&sb, "  Core committed: %.2f cores\n", b.CoreCommittedCores)
	switch mode {
	case incus.CPUAdmissionDisabled:
		sb.WriteString("  Admission gate: disabled\n")
	default:
		if c := b.Ceiling(); c > 0 {
			fmt.Fprintf(&sb, "  Admission gate: %s, factor %.2f× (ceiling %.2f cores)\n", mode, b.OvercommitFactor, c)
		} else {
			fmt.Fprintf(&sb, "  Admission gate: %s, factor %.2f×\n", mode, b.OvercommitFactor)
		}
	}
	if msg, warn := b.AdvisoryWarning(); warn {
		fmt.Fprintf(&sb, "  ⚠ WARNING: %s\n", msg)
	}
	return sb.String()
}
