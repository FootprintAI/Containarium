package incus

import (
	"fmt"

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
		})
	}
	return out, nil
}
