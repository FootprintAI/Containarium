package client

import (
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// grpc-gateway renders proto int64 fields as quoted decimal strings, so a
// plain int64 field fails the whole response decode and `containarium info`
// prints an error instead of the host's data (#3250). Assert the public
// result, including memory and pools, using the proto's actual JSON names.
func TestGetSystemInfoDecodesQuotedInt64(t *testing.T) {
	body := `{"info":{
		"incusVersion":"6.0.2","kernelVersion":"6.8.0","os":"Ubuntu 24.04",
		"containersTotal":7,"containersRunning":3,
		"totalMemoryBytes":"34359738368","availableMemoryBytes":"17179869184",
		"totalCpus":12,"committedCpuCores":4.5,"coreCommittedCpuCores":2.25,
		"cpuAdmissionMode":"CPU_ADMISSION_MODE_ENFORCING","cpuOvercommitFactor":2.5,
		"storagePools":[{"pool":"p1","driver":"STORAGE_DRIVER_ZFS","usedBytes":"96","totalBytes":"100",
			"level":"STORAGE_POOL_CAPACITY_LEVEL_CRITICAL","observedAt":"2026-10-21T00:00:00Z"}]
	}}`
	_, c := newBodyRecorder(t, body)

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

	if info.TotalMemoryBytes != 34359738368 {
		t.Errorf("totalMemoryBytes = %d, want 34359738368", info.TotalMemoryBytes)
	}
	if info.AvailableMemoryBytes != 17179869184 {
		t.Errorf("availableMemoryBytes = %d, want 17179869184", info.AvailableMemoryBytes)
	}
	wantPool := incus.StoragePoolCapacity{
		StoragePoolUsage: incus.StoragePoolUsage{Name: "p1", Driver: "zfs", UsedBytes: 96, TotalBytes: 100},
		Level:            incus.StoragePoolLevelCritical,
	}
	if len(info.StoragePools) != 1 || info.StoragePools[0] != wantPool {
		t.Errorf("storage pools = %+v, want %+v", info.StoragePools, wantPool)
	}
}
