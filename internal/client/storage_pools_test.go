package client

import (
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// SystemInfo.storage_pools decodes into the core type `containarium info`
// renders (#2823). TestGetSystemInfoDecodesQuotedInt64 covers gateway JSON.
func TestStoragePoolsFromWire(t *testing.T) {
	want := []incus.StoragePoolCapacity{{
		StoragePoolUsage: incus.StoragePoolUsage{Name: "p1", Driver: "zfs", UsedBytes: 96, TotalBytes: 100},
		Level:            incus.StoragePoolLevelCritical,
	}}
	got := storagePoolsFromWire([]*pb.StoragePoolCapacity{{
		Pool: "p1", Driver: pb.StorageDriver_STORAGE_DRIVER_ZFS, UsedBytes: 96, TotalBytes: 100,
		Level: pb.StoragePoolCapacityLevel_STORAGE_POOL_CAPACITY_LEVEL_CRITICAL,
	}})
	if len(got) != 1 || got[0] != want[0] {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if got := storagePoolsFromWire(nil); got != nil {
		t.Errorf("no pools: want nil, got %+v", got)
	}
}
