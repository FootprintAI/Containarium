package client

import "testing"

// grpc-gateway renders proto int64 fields as quoted decimal strings, so a
// plain int64 field fails the whole response decode and `containarium info`
// prints an error instead of the host's data (#3250). The recorded wire body
// below is what the gateway emits for SystemInfo.
func TestGetSystemInfoDecodesQuotedInt64(t *testing.T) {
	_, c := newBodyRecorder(t, `{"info":{
		"incusVersion":"6.0.2","kernelVersion":"6.8.0","operatingSystem":"Ubuntu 24.04",
		"totalContainers":7,"runningContainers":3,"totalCpuCores":16,
		"totalMemoryBytes":"34359738368","availableMemoryBytes":"17179869184",
		"totalCpus":12,"committedCpuCores":4.5,"coreCommittedCpuCores":2.25,
		"cpuAdmissionMode":"CPU_ADMISSION_MODE_ENFORCING","cpuOvercommitFactor":2.5
	}}`)

	info, err := c.GetSystemInfo()
	if err != nil {
		t.Fatalf("GetSystemInfo: %v", err)
	}
	if info.Version != "6.0.2" || info.KernelVersion != "6.8.0" {
		t.Errorf("got version %q kernel %q", info.Version, info.KernelVersion)
	}
	if info.CPUBudget == nil || info.CPUBudget.PhysicalCPUs != 12 {
		t.Errorf("CPU budget not decoded: %+v", info.CPUBudget)
	}
}
