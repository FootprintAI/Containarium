package client

import (
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// cpuBudgetFromWire decodes SystemInfo's CPU budget fields (#2284) into the
// core type `containarium info` renders. Returns nil when the daemon did
// not report a posture (UNSPECIFIED — a pre-#2284 daemon), so the CLI says
// "not reported" instead of inventing a zero-core host with a disabled gate.
func cpuBudgetFromWire(totalCPUs int32, tenant, core float64, mode pb.CPUAdmissionMode, factor float64) *incus.CPUBudget {
	m := cpuAdmissionModeFromProto(mode)
	if m == incus.CPUAdmissionUnknown {
		return nil
	}
	return &incus.CPUBudget{
		PhysicalCPUs:         float64(totalCPUs),
		TenantCommittedCores: tenant,
		CoreCommittedCores:   core,
		OvercommitFactor:     factor,
		AdmissionMode:        m,
	}
}

func cpuAdmissionModeFromProto(m pb.CPUAdmissionMode) incus.CPUAdmissionMode {
	switch m {
	case pb.CPUAdmissionMode_CPU_ADMISSION_MODE_DISABLED:
		return incus.CPUAdmissionDisabled
	case pb.CPUAdmissionMode_CPU_ADMISSION_MODE_ADVISORY:
		return incus.CPUAdmissionAdvisory
	case pb.CPUAdmissionMode_CPU_ADMISSION_MODE_ENFORCING:
		return incus.CPUAdmissionEnforcing
	default:
		return incus.CPUAdmissionUnknown
	}
}
