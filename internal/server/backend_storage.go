package server

import (
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// backendStorageFromPool projects an observed incus pool driver onto the wire
// contract, so an operator can answer "which of my backends can have one
// tenant stall another's fsync?" (#1206) from ListBackends rather than by
// reading a daemon startup log on each host. See #1209.
//
// Returns nil when nothing was observed. Null rather than a zero-valued
// struct so a caller can tell "we don't know" from "isolated" — the same rule
// host_load follows, and the difference between an operator seeing an honest
// blank and wrongly seeing a safe-looking default.
func backendStorageFromPool(pool string, driver incus.StorageDriver) *pb.BackendStorage {
	if driver == "" {
		return nil
	}

	return &pb.BackendStorage{
		Pool:       pool,
		Driver:     storageDriverToProto(driver),
		Isolation:  storageIsolationToProto(driver.Isolation()),
		DriverName: string(driver),
	}
}

// storageDriverToProto maps the incus driver onto the proto enum. A driver we
// read but do not classify becomes OTHER, never UNSPECIFIED — UNSPECIFIED is
// reserved for "could not read the pool at all", and collapsing the two would
// make an observed driver indistinguishable from a failure.
func storageDriverToProto(d incus.StorageDriver) pb.StorageDriver {
	switch d {
	case incus.StorageDriverZFS:
		return pb.StorageDriver_STORAGE_DRIVER_ZFS
	case incus.StorageDriverBtrfs:
		return pb.StorageDriver_STORAGE_DRIVER_BTRFS
	case incus.StorageDriverLVM:
		return pb.StorageDriver_STORAGE_DRIVER_LVM
	case incus.StorageDriverCeph:
		return pb.StorageDriver_STORAGE_DRIVER_CEPH
	case incus.StorageDriverDir:
		return pb.StorageDriver_STORAGE_DRIVER_DIR
	default:
		return pb.StorageDriver_STORAGE_DRIVER_OTHER
	}
}

// storageIsolationToProto maps the isolation classification onto the wire.
func storageIsolationToProto(i incus.StorageIsolation) pb.StorageIsolation {
	switch i {
	case incus.StorageIsolationPerContainer:
		return pb.StorageIsolation_STORAGE_ISOLATION_PER_CONTAINER
	case incus.StorageIsolationSharedFilesystem:
		return pb.StorageIsolation_STORAGE_ISOLATION_SHARED_FILESYSTEM
	default:
		return pb.StorageIsolation_STORAGE_ISOLATION_UNKNOWN_DRIVER
	}
}
