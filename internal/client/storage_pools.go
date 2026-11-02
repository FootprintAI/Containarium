package client

import (
	"strings"

	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// storagePoolsFromWire decodes SystemInfo.storage_pools (#2823) into the core
// type `containarium info` renders. Nil when the daemon reported none.
func storagePoolsFromWire(pools []*pb.StoragePoolCapacity) []incus.StoragePoolCapacity {
	if len(pools) == 0 {
		return nil
	}
	out := make([]incus.StoragePoolCapacity, 0, len(pools))
	for _, p := range pools {
		out = append(out, incus.StoragePoolCapacity{
			StoragePoolUsage: incus.StoragePoolUsage{
				Name: p.GetPool(), Driver: storageDriverName(p.GetDriver()),
				UsedBytes: p.GetUsedBytes(), TotalBytes: p.GetTotalBytes(),
			},
			Level: storagePoolLevelFromProto(p.GetLevel()),
		})
	}
	return out
}

// storageDriverName is the lower-case driver name for a StorageDriver enum
// ("zfs", "dir", ...), or "" when unspecified.
func storageDriverName(d pb.StorageDriver) string {
	if d == pb.StorageDriver_STORAGE_DRIVER_UNSPECIFIED {
		return ""
	}
	return strings.ToLower(strings.TrimPrefix(d.String(), "STORAGE_DRIVER_"))
}

func storagePoolLevelFromProto(l pb.StoragePoolCapacityLevel) incus.StoragePoolLevel {
	switch l {
	case pb.StoragePoolCapacityLevel_STORAGE_POOL_CAPACITY_LEVEL_OK:
		return incus.StoragePoolLevelOK
	case pb.StoragePoolCapacityLevel_STORAGE_POOL_CAPACITY_LEVEL_WARNING:
		return incus.StoragePoolLevelWarning
	case pb.StoragePoolCapacityLevel_STORAGE_POOL_CAPACITY_LEVEL_CRITICAL:
		return incus.StoragePoolLevelCritical
	default:
		return incus.StoragePoolLevelUnknown
	}
}
