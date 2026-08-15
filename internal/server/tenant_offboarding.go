package server

import (
	"context"
	"fmt"
	"log"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Tenant offboarding (#1343).
//
// Per-tenant encryption creates two durable resources — an Incus storage pool
// and the encrypted dataset it is sourced at — and until now nothing removed
// them. A tenant who left kept both forever, the dataset holding their
// key-encrypted data indefinitely.
//
// The ORDER is the whole issue. Destroying the dataset first leaves an Incus
// pool pointing at nothing, and EnsureStorage/reviewExistingStorage walk every
// pool at daemon start — so a mis-ordered teardown breaks startup for every
// tenant on the host, not only the departing one.

// DeleteTenantStorage destroys a departing tenant's encrypted storage.
//
// Irreversible: the dataset is the tenant's encryptionroot, so destroying it
// destroys the only key path to their data. Admin only, like every other
// operation on tenant key custody.
func (s *ContainerServer) DeleteTenantStorage(ctx context.Context, req *pb.DeleteTenantStorageRequest) (*pb.DeleteTenantStorageResponse, error) {
	if req.GetTenant() == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant is required")
	}
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}

	pool := tenantPoolName(req.GetTenant())
	dataset, err := tenantDataset(s.encryption.tenantRootOrEmpty(), req.GetTenant())
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "resolve the tenant's dataset: %v", err)
	}

	if err := s.encryption.DestroyTenantStorage(ctx, req.GetTenant()); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
	}

	return &pb.DeleteTenantStorageResponse{
		Message: fmt.Sprintf(
			"destroyed tenant %s's encrypted storage: pool %s and dataset %s. Their data is "+
				"unrecoverable — the dataset was the only thing that could decrypt it",
			req.GetTenant(), pool, dataset),
		StoragePool: pool,
		Dataset:     dataset,
	}, nil
}

// tenantRootOrEmpty reports the configured tenant dataset root, or "" when
// encryption is not wired. Lets a caller build the same names the hooks use
// without duplicating the nil-receiver dance.
func (h *encryptionHooks) tenantRootOrEmpty() string {
	if h == nil {
		return ""
	}
	return h.tenantRoot
}

// DestroyTenantStorage removes a tenant's Incus pool and then their encrypted
// dataset, refusing while any of their containers still exist.
//
// Re-runnable: a pool that is already gone is not an error, so a teardown
// interrupted halfway can be finished rather than leaving an operator stuck
// between two half-removed resources.
func (h *encryptionHooks) DestroyTenantStorage(ctx context.Context, tenant string) error {
	if !h.enabled() {
		return fmt.Errorf("encryption is not configured on this daemon, so there is no tenant storage to destroy")
	}
	dataset, err := tenantDataset(h.tenantRoot, tenant)
	if err != nil {
		return err
	}
	pool := tenantPoolName(tenant)

	// Refuse while anything still lives under the tenant's encryptionroot.
	// Deleting the pool from under a live box destroys its storage, and the
	// containers are the reason the pool exists at all.
	//
	// The question goes to ZFS, not to the daemon's records: storage is what
	// is about to be destroyed, so storage is what gets asked. A container
	// whose record was lost would otherwise read as "no containers" and its
	// data would be destroyed with the pool.
	occupied, err := h.zfs.HasChildren(ctx, dataset)
	if err != nil {
		return fmt.Errorf("cannot determine whether tenant %s still has container storage, so "+
			"refusing to destroy theirs: %w", tenant, err)
	}
	if occupied {
		return fmt.Errorf(
			"tenant %s still has container datasets under %s; delete their containers first. "+
				"Removing the pool underneath a live container destroys its storage",
			tenant, dataset)
	}

	// Pool first. The pool REFERENCES the dataset; destroying the dataset
	// first leaves the pool dangling, and the daemon reads every pool at
	// startup — which would break startup for every tenant on this host.
	if err := h.pools.DeleteStoragePool(pool); err != nil {
		return fmt.Errorf("could not delete storage pool %s, so tenant %s's dataset was left "+
			"untouched: %w", pool, tenant, err)
	}

	if err := h.zfs.Destroy(ctx, dataset); err != nil {
		return fmt.Errorf(
			"storage pool %s was deleted but its dataset %s could not be destroyed (%w). Nothing "+
				"references that dataset now and it still holds tenant %s's encrypted data — it "+
				"needs manual removal", pool, dataset, err, tenant)
	}

	log.Printf("[encryption] offboarded tenant %s: pool %s deleted, dataset %s destroyed", tenant, pool, dataset)
	return nil
}
