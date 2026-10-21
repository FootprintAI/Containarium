package client

import (
	"encoding/json"
	"testing"

	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// SystemInfo.storage_pools decodes into the core type `containarium info`
// renders, from the gRPC message and from grpc-gateway JSON alike (#2823).
func TestStoragePoolsFromWire(t *testing.T) {
	want := []incus.StoragePoolCapacity{{
		StoragePoolUsage: incus.StoragePoolUsage{Name: "p1", Driver: "zfs", UsedBytes: 96, TotalBytes: 100},
		Level:            incus.StoragePoolLevelCritical,
	}}
	grpcGot := storagePoolsFromWire([]*pb.StoragePoolCapacity{{
		Pool: "p1", Driver: pb.StorageDriver_STORAGE_DRIVER_ZFS, UsedBytes: 96, TotalBytes: 100,
		Level: pb.StoragePoolCapacityLevel_STORAGE_POOL_CAPACITY_LEVEL_CRITICAL,
	}})
	var raw []json.RawMessage
	if err := json.Unmarshal([]byte(`[{"pool":"p1","driver":"STORAGE_DRIVER_ZFS","usedBytes":"96","totalBytes":"100",
		"level":"STORAGE_POOL_CAPACITY_LEVEL_CRITICAL","observedAt":"2026-10-21T00:00:00Z"}]`), &raw); err != nil {
		t.Fatal(err)
	}
	for name, got := range map[string][]incus.StoragePoolCapacity{"grpc": grpcGot, "http": storagePoolsFromJSON(raw)} {
		if len(got) != 1 || got[0] != want[0] {
			t.Errorf("%s: got %+v, want %+v", name, got, want)
		}
	}
	if got := storagePoolsFromWire(nil); got != nil {
		t.Errorf("no pools: want nil, got %+v", got)
	}
}
