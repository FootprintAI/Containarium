package incus

import (
	"fmt"
	"net/http"

	"github.com/lxc/incus/v6/shared/api"
)

// Storage-pool operations for per-tenant encrypted pools (#1338).
//
// Per-tenant ZFS encryption puts each tenant's containers on their own Incus
// storage pool, sourced at that tenant's encrypted dataset. Incus creates an
// instance volume by cloning the image snapshot, and a ZFS clone inherits
// encryption from its origin rather than its location (#1335) — so the only
// way an instance can be encrypted is for the dataset it is cloned WITHIN to
// be encrypted. That dataset is the pool's source.
//
// See docs/architecture/per-tenant-encrypted-storage-pools.md.
//
// EnsureStorage, next door, provisions the ONE pool the daemon is configured
// with and picks its driver by probing the host. These are the other shape:
// an explicitly named pool on an explicitly named dataset, for a caller that
// already knows both. No key material passes through this file — the hook
// owns key custody, and this package only ever learns a dataset name.

// CreateZFSPool creates an Incus storage pool on the zfs driver, sourced at
// an existing ZFS dataset.
//
// The source is passed through verbatim and is the whole point of the call:
// a source that arrives altered puts the pool on a different dataset than the
// one the caller encrypted, and every container on it would be unencrypted
// while the create reported success.
func (c *Client) CreateZFSPool(name, source string) error {
	if name == "" {
		return fmt.Errorf("storage pool name is required")
	}
	// An empty source is the dangerous argument, not merely an invalid one:
	// Incus would happily create the pool on a fresh loop device instead of
	// the caller's encrypted dataset, and report success. Refuse here rather
	// than let a container discover it by being unencrypted.
	if source == "" {
		return fmt.Errorf("a source dataset is required to create storage pool %s: "+
			"without one Incus would provision its own backing store and the pool would "+
			"not be the encrypted dataset the caller asked for", name)
	}

	req := api.StoragePoolsPost{
		Name:   name,
		Driver: string(StorageDriverZFS),
		StoragePoolPut: api.StoragePoolPut{
			Config: map[string]string{"source": source},
		},
	}
	if err := c.server.CreateStoragePool(req); err != nil {
		return fmt.Errorf("create storage pool %s on %s: %w", name, source, err)
	}
	return nil
}

// StoragePoolSource reports the dataset a pool is sourced at, and whether the
// pool exists at all.
//
// Three states, and the middle one is why this exists rather than callers
// reaching for GetStoragePool:
//
//	("tank/tenants/alice", true,  nil) — reuse it if the source is the one expected
//	("",                   true,  nil) — the name is taken by a pool with no source; refuse
//	("",                   false, nil) — nothing there; create it
//
// A pool that could not be READ is none of those and returns an error, with
// exists=false so a caller that ignores the error cannot act on it. Reporting
// an unreadable pool as absent would have the caller create over the top of
// one that exists — the same distinction reviewExistingStorage draws for the
// driver, where "we could not check" must not be reported as a clean answer.
func (c *Client) StoragePoolSource(name string) (source string, exists bool, err error) {
	if name == "" {
		return "", false, fmt.Errorf("storage pool name is required")
	}

	pool, _, err := c.server.GetStoragePool(name)
	if err != nil {
		if api.StatusErrorCheck(err, http.StatusNotFound) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("read storage pool %s: %w", name, err)
	}
	if pool == nil {
		return "", false, nil
	}
	return pool.Config["source"], true, nil
}

// DeleteStoragePool removes a storage pool.
//
// A pool that is already gone is the end state the caller wanted, so that is
// not an error: tenant offboarding (#1343) has to be re-runnable after a
// partial failure, and failing the second run would leave an operator unable
// to finish a teardown they had already started. Every other failure is
// surfaced — a pool still holding volumes must not look like a completed
// teardown.
func (c *Client) DeleteStoragePool(name string) error {
	if name == "" {
		return fmt.Errorf("storage pool name is required")
	}

	if err := c.server.DeleteStoragePool(name); err != nil {
		if api.StatusErrorCheck(err, http.StatusNotFound) {
			return nil
		}
		return fmt.Errorf("delete storage pool %s: %w", name, err)
	}
	return nil
}
