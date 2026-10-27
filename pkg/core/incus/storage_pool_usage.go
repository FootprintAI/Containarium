package incus

import (
	"fmt"
	"strings"

	"github.com/footprintai/containarium/internal/safecast"
)

// StoragePoolUsage is one Incus storage pool's capacity as Incus reports it
// (GET /1.0/storage-pools/<name>/resources). For ZFS the Incus driver derives
// Total as used + available, so slop space is already excluded — read from the
// driver, not verified on a live pool (#2823).
type StoragePoolUsage struct {
	Name       string
	Driver     string
	UsedBytes  int64
	TotalBytes int64
	// ZpoolName is the ZFS pool behind a zfs-driver pool (see ZpoolNameFor);
	// empty for every other driver and when it cannot be derived (#2853).
	ZpoolName string
	// Zpool is what `zpool list` says about that pool, filled by
	// poolcapacity.WithZpool. Nil when not ZFS, when zpool is absent or slow,
	// and always for a peer's pools (they arrive through SystemInfo).
	Zpool *ZpoolStat
}

// ZpoolStat is the part of `zpool list` Incus does not expose (#2853): the
// pool's raw capacity as ZFS counts it, and its fragmentation. A heavily
// fragmented pool degrades sharply before used bytes reach any fill threshold.
type ZpoolStat struct {
	CapacityPercent      int64
	FragmentationPercent int64
	// FragmentationKnown is false when zpool printed "-" (a pool that does not
	// report it); FragmentationPercent is 0 then and must not be exported.
	FragmentationKnown bool
}

// ZpoolNameFor returns the zpool behind an Incus ZFS pool, or "" if the pool
// is not ZFS or the name cannot be told. `zpool list` takes a pool name, never
// a dataset or a device path, and Incus's own settings can hold either:
// zfs.pool_name is "tank" or "tank/incus", and source may be the same or a
// loop-file path. The pool is the part before the first slash; a path-shaped
// value with no zfs.pool_name to fall back on is not guessed at.
func ZpoolNameFor(driver string, config map[string]string) string {
	if driver != "zfs" {
		return ""
	}
	name := strings.TrimSpace(config["zfs.pool_name"])
	if name == "" {
		name = strings.TrimSpace(config["source"])
	}
	if name == "" || strings.HasPrefix(name, "/") {
		return ""
	}
	if i := strings.IndexByte(name, '/'); i >= 0 {
		name = name[:i]
	}
	return name
}

// StoragePoolLevel is a pool's fill classification against the daemon's
// thresholds (internal/poolcapacity, #2823).
type StoragePoolLevel int

const (
	StoragePoolLevelUnknown StoragePoolLevel = iota // total not reported
	StoragePoolLevelOK
	StoragePoolLevelWarning
	StoragePoolLevelCritical
)

func (l StoragePoolLevel) String() string {
	switch l {
	case StoragePoolLevelOK:
		return "ok"
	case StoragePoolLevelWarning:
		return "warning"
	case StoragePoolLevelCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// StoragePoolCapacity is one pool reading with its level.
type StoragePoolCapacity struct {
	StoragePoolUsage
	Level StoragePoolLevel
}

// StoragePoolUsages reads every pool's used/total through the per-pool
// resources endpoint only. It never touches GET /1.0/resources, which can hang
// on a saturated host (#2325), and it is uncached so a full pool is never
// hidden behind a stale value. Call it on a client built with
// NewWithSocketAndTimeout so each request is bounded.
//
// A pool whose read fails is left out; only a failed pool list is an error.
func (c *Client) StoragePoolUsages() ([]StoragePoolUsage, error) {
	pools, err := c.server.GetStoragePools()
	if err != nil {
		return nil, fmt.Errorf("list storage pools: %w", err)
	}
	out := make([]StoragePoolUsage, 0, len(pools))
	for _, p := range pools {
		res, err := c.server.GetStoragePoolResources(p.Name)
		if err != nil {
			continue
		}
		out = append(out, StoragePoolUsage{
			Name:       p.Name,
			Driver:     p.Driver,
			UsedBytes:  safecast.I64FromU64(res.Space.Used),
			TotalBytes: safecast.I64FromU64(res.Space.Total),
			ZpoolName:  ZpoolNameFor(p.Driver, p.Config),
		})
	}
	return out, nil
}
