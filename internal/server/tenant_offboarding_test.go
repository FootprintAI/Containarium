package server

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/zfskey"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Tenant offboarding (#1343).
//
// Per-tenant encryption creates two durable resources — an Incus storage pool
// and the encrypted dataset it is sourced at — and nothing removed them. A
// tenant who leaves kept both forever, the dataset holding their
// key-encrypted data indefinitely.
//
// The ORDER is the whole issue. Destroying the dataset first leaves an Incus
// pool pointing at nothing, and `EnsureStorage`/`reviewExistingStorage` walk
// every pool at daemon start — so a mis-ordered teardown breaks startup for
// every tenant on the host, not just the departing one.

func offboardHooks(t *testing.T, z *zfsFake, containers map[string]zfskey.KeyRef) (*encryptionHooks, *fakePools, *fakeRefStore) {
	t.Helper()
	// The shared fake defaults `zfs list` to failing, which means "dataset
	// absent" for Exists. Offboarding asks the same verb a different
	// question — "does this root have children?" — so the tests here supply
	// a real listing instead.
	delete(z.errs, "list")
	pools := newFakePools()
	pools.sources["containarium-tenant-alice"] = "tank/tenants/alice"
	placed := map[string]string{}
	for name := range containers {
		placed[name] = "containarium-tenant-alice"
	}
	refs := &fakeRefStore{refs: containers, pools: placed}
	return testHooksWith(t, z, &fakeKeyProvider{key: aKey(t)}, refs, pools), pools, refs
}

// The guard: a tenant with containers still on their pool is not offboarded.
// Deleting the pool underneath a live container destroys its storage.
func TestDestroyTenantStorage_RefusesWhileContainersRemain(t *testing.T) {
	z := newZFSFake()
	// ZFS reports a container dataset still living under the tenant root.
	z.stdout["list"] = "tank/tenants/alice\ntank/tenants/alice/containers/alice-container"
	h, pools, _ := offboardHooks(t, z, map[string]zfskey.KeyRef{})

	err := h.DestroyTenantStorage(context.Background(), "alice")
	if err == nil {
		t.Fatal("offboarded a tenant that still has containers — their storage would be deleted " +
			"out from under a live box")
	}
	if !strings.Contains(err.Error(), "tank/tenants/alice") {
		t.Errorf("the error does not name what is still there, so an operator cannot act: %v", err)
	}
	if len(pools.deleted) != 0 {
		t.Errorf("the pool was deleted anyway: %v", pools.deleted)
	}
	if z.ran("destroy") {
		t.Errorf("the dataset was destroyed anyway; calls=%v", z.calls)
	}
}

// The order: pool first, dataset second.
func TestDestroyTenantStorage_DeletesThePoolBeforeTheDataset(t *testing.T) {
	z := newZFSFake()
	z.stdout["list"] = "tank/tenants/alice" // empty: only the root itself
	h, pools, _ := offboardHooks(t, z, map[string]zfskey.KeyRef{})

	// Observe what had already happened when the pool was deleted. This is
	// the ordering assertion; a flag the fake sets unconditionally would be
	// true either way round and prove nothing.
	datasetGoneFirst := false
	pools.onDelete = func() { datasetGoneFirst = z.ran("destroy") }

	if err := h.DestroyTenantStorage(context.Background(), "alice"); err != nil {
		t.Fatalf("DestroyTenantStorage: %v", err)
	}

	if len(pools.deleted) != 1 || pools.deleted[0] != "containarium-tenant-alice" {
		t.Fatalf("deleted pools = %v, want the tenant's", pools.deleted)
	}
	if !z.ran("destroy") || !z.ran("tank/tenants/alice") {
		t.Fatalf("the tenant dataset was not destroyed; calls=%v", z.calls)
	}
	if datasetGoneFirst {
		t.Error("the dataset was destroyed BEFORE the pool was deleted — the pool would then " +
			"point at nothing, and EnsureStorage walks every pool at daemon start, so the next " +
			"restart breaks for every tenant on this host")
	}
}

// If the dataset survives a successful pool delete, the operator has to be
// told exactly what is left: the pool is gone, so nothing will ever reference
// that dataset again, and it holds the tenant's encrypted data.
func TestDestroyTenantStorage_SaysWhatIsLeftWhenTheDatasetSurvives(t *testing.T) {
	z := newZFSFake()
	z.stdout["list"] = "tank/tenants/alice"
	z.errs["destroy"] = errors.New("dataset is busy")
	h, pools, _ := offboardHooks(t, z, map[string]zfskey.KeyRef{})

	err := h.DestroyTenantStorage(context.Background(), "alice")
	if err == nil {
		t.Fatal("a surviving dataset was reported as a clean offboarding")
	}
	if len(pools.deleted) != 1 {
		t.Errorf("the pool delete did not happen: %v", pools.deleted)
	}
	for _, want := range []string{"tank/tenants/alice", "manual"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %q, so the leftover is invisible: %v", want, err)
		}
	}
}

// A pool that is already gone must not stop the dataset being cleaned up —
// offboarding has to be re-runnable after a partial failure.
func TestDestroyTenantStorage_IsRerunnableAfterAPartialTeardown(t *testing.T) {
	z := newZFSFake()
	z.stdout["list"] = "tank/tenants/alice"
	h, pools, _ := offboardHooks(t, z, map[string]zfskey.KeyRef{})
	delete(pools.sources, "containarium-tenant-alice") // the pool went first time

	if err := h.DestroyTenantStorage(context.Background(), "alice"); err != nil {
		t.Fatalf("a re-run after a partial teardown failed: %v — an operator cannot finish what "+
			"they started", err)
	}
	if !z.ran("destroy") {
		t.Errorf("the leftover dataset was not cleaned up; calls=%v", z.calls)
	}
}

func TestDestroyTenantStorage_RequiresEncryptionToBeConfigured(t *testing.T) {
	var h *encryptionHooks
	if err := h.DestroyTenantStorage(context.Background(), "alice"); err == nil {
		t.Fatal("a daemon with no encryption claimed to have offboarded a tenant")
	}
}

// --- the RPC ------------------------------------------------------------

func TestDeleteTenantStorage_RequiresAdmin(t *testing.T) {
	z := newZFSFake()
	z.stdout["list"] = "tank/tenants/alice"
	h, _, _ := offboardHooks(t, z, map[string]zfskey.KeyRef{})
	s := &ContainerServer{encryption: h}

	_, err := s.DeleteTenantStorage(
		tenantWithScopes("alice", auth.ScopeContainersWrite),
		&pb.DeleteTenantStorageRequest{Tenant: "alice"})
	if err == nil {
		t.Fatal("a non-admin destroyed a tenant's encrypted storage")
	}
	if got := status.Code(err); got != codes.PermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", got)
	}
}

func TestDeleteTenantStorage_ReportsWhatItRemoved(t *testing.T) {
	z := newZFSFake()
	z.stdout["list"] = "tank/tenants/alice"
	h, _, _ := offboardHooks(t, z, map[string]zfskey.KeyRef{})
	s := &ContainerServer{encryption: h}

	resp, err := s.DeleteTenantStorage(adminCtx(), &pb.DeleteTenantStorageRequest{Tenant: "alice"})
	if err != nil {
		t.Fatalf("DeleteTenantStorage: %v", err)
	}
	if resp.StoragePool == "" || resp.Dataset == "" {
		t.Errorf("the response does not name what was destroyed (pool=%q dataset=%q) — an "+
			"operator has no record of what this removed", resp.StoragePool, resp.Dataset)
	}
}

func TestDeleteTenantStorage_RejectsAnEmptyTenant(t *testing.T) {
	z := newZFSFake()
	z.stdout["list"] = "tank/tenants/alice"
	h, _, _ := offboardHooks(t, z, map[string]zfskey.KeyRef{})
	s := &ContainerServer{encryption: h}

	if _, err := s.DeleteTenantStorage(adminCtx(), &pb.DeleteTenantStorageRequest{}); err == nil {
		t.Fatal("an empty tenant was accepted — tenantDataset would name the root itself")
	}
}
