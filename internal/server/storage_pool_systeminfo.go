package server

import (
	"strings"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/footprintai/containarium/internal/poolcapacity"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// SetStoragePoolSource wires the pool capacity monitor's snapshot into
// GetSystemInfo (#2823).
func (s *ContainerServer) SetStoragePoolSource(fn func() poolcapacity.Snapshot) {
	s.storagePools = fn
}

// storagePoolCapacities projects the monitor's last snapshot onto
// SystemInfo.storage_pools. It never calls Incus, so GetSystemInfo stays as
// fast as before; nil when no monitor is wired or it has not read yet.
func (s *ContainerServer) storagePoolCapacities() []*pb.StoragePoolCapacity {
	if s.storagePools == nil {
		return nil
	}
	snap := s.storagePools()
	if len(snap.Pools) == 0 {
		return nil
	}
	out := make([]*pb.StoragePoolCapacity, 0, len(snap.Pools))
	for _, p := range snap.Pools {
		out = append(out, &pb.StoragePoolCapacity{
			Pool:       p.Name,
			Driver:     storageDriverToProto(incus.StorageDriver(p.Driver)),
			UsedBytes:  p.UsedBytes,
			TotalBytes: p.TotalBytes,
			Level:      storagePoolLevelToProto(p.Level),
			ObservedAt: timestamppb.New(snap.At),
		})
	}
	return out
}

func storagePoolLevelToProto(l poolcapacity.Level) pb.StoragePoolCapacityLevel {
	switch l {
	case poolcapacity.LevelOK:
		return pb.StoragePoolCapacityLevel_STORAGE_POOL_CAPACITY_LEVEL_OK
	case poolcapacity.LevelWarning:
		return pb.StoragePoolCapacityLevel_STORAGE_POOL_CAPACITY_LEVEL_WARNING
	case poolcapacity.LevelCritical:
		return pb.StoragePoolCapacityLevel_STORAGE_POOL_CAPACITY_LEVEL_CRITICAL
	default:
		return pb.StoragePoolCapacityLevel_STORAGE_POOL_CAPACITY_LEVEL_UNSPECIFIED
	}
}

// storagePoolUsagesFromProto turns a peer's reported pools back into usage
// values for the metrics collector.
func storagePoolUsagesFromProto(pools []*pb.StoragePoolCapacity) []incus.StoragePoolUsage {
	out := make([]incus.StoragePoolUsage, 0, len(pools))
	for _, p := range pools {
		driver := ""
		if p.GetDriver() != pb.StorageDriver_STORAGE_DRIVER_UNSPECIFIED {
			driver = strings.ToLower(strings.TrimPrefix(p.GetDriver().String(), "STORAGE_DRIVER_"))
		}
		out = append(out, incus.StoragePoolUsage{Name: p.GetPool(), Driver: driver, UsedBytes: p.GetUsedBytes(), TotalBytes: p.GetTotalBytes()})
	}
	return out
}
