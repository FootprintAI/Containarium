//go:build incus

package server

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/events"
	"github.com/footprintai/containarium/internal/metrics/platformstats"
	"github.com/footprintai/containarium/internal/testsupport/incusenv"
	"github.com/footprintai/containarium/pkg/core/box"
	boxlxc "github.com/footprintai/containarium/pkg/core/box/lxc"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/zfscrypt"
	"github.com/footprintai/containarium/pkg/core/zfskey"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #1199 AC1, end to end: a container created with encrypted=true lands under
// its own tenant's encryptionroot, and another tenant's key will not open it.
//
// Driven through ContainerServer.CreateContainer — the gRPC method a real
// caller reaches — against a real Incus on a real ZFS pool. Everything below
// it (EnsureTenantStorage, the pool placement, the placement record) is
// production code; only the KeyProvider is injected, because configuring one
// on the daemon is #1342 and deliberately comes last.

// encTestServer builds a ContainerServer wired for encryption over a real
// Incus, with a file-backed KeyProvider under the test's temp dir.
func encTestServer(t *testing.T, client *incus.Client, tenantRoot string) *ContainerServer {
	t.Helper()

	keys, err := zfskey.NewFileKeyProvider(filepath.Join(t.TempDir(), "keys"))
	if err != nil {
		t.Fatalf("NewFileKeyProvider: %v", err)
	}
	mgr := container.NewWithBackend(client)
	s := &ContainerServer{
		manager:          mgr,
		boxBackend:       boxlxc.New(mgr),
		keyProvider:      keys,
		pendingCreations: map[string]*PendingCreation{},
		platformStats:    platformstats.New(),
		// NewContainerServer always sets this; a directly-constructed server
		// must too, or the create panics on a nil *Emitter after the box is
		// already built.
		emitter: events.NewEmitter(events.GetBus()),
	}
	// The production wiring, then the provider on top — SetEncryptionStorage
	// reads s.keyProvider, which is set above.
	s.SetEncryptionStorage(tenantRoot, client)
	return s
}

// encTestEnv prepares the daemon's infrastructure and returns a wired server
// plus the tenant dataset root everything is created under.
func encTestEnv(t *testing.T) (*ContainerServer, *incus.Client, string) {
	t.Helper()
	client := incusenv.Require(t)
	if err := client.InitializeInfrastructure(incus.DefaultNetworkConfig()); err != nil {
		t.Fatalf("the daemon's own infrastructure init failed: %v", err)
	}
	// Derived exactly as the daemon derives it at startup, so the test does
	// not invent a layout the daemon would not use.
	tenantRoot := DefaultTenantRoot(client)
	if tenantRoot == "" {
		t.Fatalf("could not derive a tenant dataset root from storage pool %q", client.StoragePool())
	}
	return encTestServer(t, client, tenantRoot), client, tenantRoot
}

// createEncrypted drives the real gRPC method and cleans up after itself.
func createEncrypted(t *testing.T, s *ContainerServer, tenant string) string {
	t.Helper()
	instance := tenant + "-container"
	t.Cleanup(func() { incusenv.DeleteInstance(t, instance) })

	ctx, cancel := context.WithTimeout(
		tenantWithScopes(tenant, auth.ScopeContainersWrite), 25*time.Minute)
	defer cancel()

	if _, err := s.CreateContainer(ctx, &pb.CreateContainerRequest{
		Username:  tenant,
		Image:     "images:ubuntu/24.04",
		OsType:    pb.OSType_OS_TYPE_UBUNTU_2404,
		Encrypted: true,
		Resources: &pb.ResourceLimits{Disk: "5GB"},
	}); err != nil {
		t.Fatalf("encrypted CreateContainer(%s): %v", tenant, err)
	}
	return instance
}

func TestIntegrationIncus_EncryptedCreateLandsUnderTheTenantEncryptionroot(t *testing.T) {
	s, _, tenantRoot := encTestEnv(t)
	zfs := zfscrypt.NewManager(zfscrypt.ExecRunner{})
	ctx := context.Background()

	tenant := fmt.Sprintf("enc%d", os.Getpid())
	t.Cleanup(func() { _ = zfs.Destroy(context.Background(), tenantRoot+"/"+tenant) })

	instance := createEncrypted(t, s, tenant)

	dataset := incusenv.DatasetFor(t, instance)
	if dataset == "" {
		t.Fatalf("instance %s has no ZFS dataset", instance)
	}
	root, err := zfs.EncryptionRoot(ctx, dataset)
	if err != nil {
		t.Fatalf("read encryptionroot of %s: %v — an unencrypted dataset has none, which would "+
			"mean the create reported encryption it did not deliver", dataset, err)
	}
	want := tenantRoot + "/" + tenant
	if root != want {
		t.Fatalf("instance dataset %s has encryptionroot %q, want the tenant's %q", dataset, root, want)
	}
	t.Logf("encrypted create landed on %s under encryptionroot %s", dataset, root)
}

// The assertion that actually draws the boundary.
//
// Two datasets reporting different encryptionroot STRINGS would still pass a
// string comparison while sharing key material. Only a failed unlock rules
// that out, so this loads one tenant's key and tries it against the other's
// dataset.
func TestIntegrationIncus_TwoTenantsCannotUnlockEachOther(t *testing.T) {
	s, _, tenantRoot := encTestEnv(t)
	zfs := zfscrypt.NewManager(zfscrypt.ExecRunner{})
	ctx := context.Background()

	alice := fmt.Sprintf("alc%d", os.Getpid())
	bob := fmt.Sprintf("bob%d", os.Getpid())
	for _, tn := range []string{alice, bob} {
		tenant := tn
		t.Cleanup(func() { _ = zfs.Destroy(context.Background(), tenantRoot+"/"+tenant) })
	}

	aliceDS := incusenv.DatasetFor(t, createEncrypted(t, s, alice))
	bobDS := incusenv.DatasetFor(t, createEncrypted(t, s, bob))

	aliceRoot, err := zfs.EncryptionRoot(ctx, aliceDS)
	if err != nil {
		t.Fatalf("EncryptionRoot(%s): %v", aliceDS, err)
	}
	bobRoot, err := zfs.EncryptionRoot(ctx, bobDS)
	if err != nil {
		t.Fatalf("EncryptionRoot(%s): %v", bobDS, err)
	}
	if aliceRoot == bobRoot {
		t.Fatalf("both tenants are under encryptionroot %q — one tenant's key unlocks the "+
			"other's data", aliceRoot)
	}

	// Now the part a string comparison cannot do: offer ALICE'S ACTUAL KEY
	// to bob's encryptionroot and require ZFS to refuse it.
	//
	// The key comes from the server's own provider, not a fresh one. A
	// second FileKeyProvider under a different directory would mint
	// different material for the same tenant, and the unlock would fail
	// because the key was wrong rather than because the tenants are
	// isolated — the test would pass no matter how broken the boundary was.
	aliceKey, _, err := s.encryption.provider.Wrap(ctx, alice)
	if err != nil {
		t.Fatalf("Wrap(%s) from the server's own provider: %v", alice, err)
	}

	// Bob's key is loaded while his container runs, and ZFS will not unload
	// a key that a mounted dataset is using. Stop his container the way the
	// daemon does, then drop the key through the hook that production runs.
	// Deliberately NOT a t.Skip: a skipped cross-tenant check is the one
	// result that must never be mistaken for a pass.
	if err := s.boxes().Stop(ctx, box.BoxRef{Tenant: bob}, true); err != nil {
		t.Fatalf("stopping bob's container: %v", err)
	}
	s.encryption.PostStop(ctx, bob+"-container")

	if status, err := zfs.KeyStatus(ctx, bobRoot); err != nil {
		t.Fatalf("KeyStatus(%s): %v", bobRoot, err)
	} else if status != zfscrypt.KeyUnavailable {
		t.Fatalf("bob's key is still %q after his last container stopped, so the unlock below "+
			"would be answered from the loaded key rather than tested", status)
	}

	if err := zfs.LoadKey(ctx, bobRoot, aliceKey); err == nil {
		t.Fatalf("alice's key unlocked bob's encryptionroot %s — the tenants share key material "+
			"despite reporting different roots, which is exactly the failure a comparison of "+
			"encryptionroot strings cannot see", bobRoot)
	}
	t.Logf("alice's key is refused against bob's encryptionroot %s", bobRoot)
}

func TestIntegrationIncus_SecondContainerForATenantSharesItsEncryptionroot(t *testing.T) {
	s, _, tenantRoot := encTestEnv(t)
	zfs := zfscrypt.NewManager(zfscrypt.ExecRunner{})
	ctx := context.Background()

	tenant := fmt.Sprintf("two%d", os.Getpid())
	t.Cleanup(func() { _ = zfs.Destroy(context.Background(), tenantRoot+"/"+tenant) })

	first := incusenv.DatasetFor(t, createEncrypted(t, s, tenant))

	// A tenant's second container. The daemon names containers
	// "<username>-container", so a second one needs its own username under
	// the same tenant — which is what tenant_id expresses on a multi-tenant
	// build. Here the second create simply re-runs EnsureTenantStorage for
	// the same tenant, which must reuse the pool rather than mint a second
	// encryptionroot.
	pool, ref, err := s.encryption.EnsureTenantStorage(ctx, tenant)
	if err != nil {
		t.Fatalf("second EnsureTenantStorage(%s): %v", tenant, err)
	}
	if ref.URI == "" {
		t.Error("the second call returned no key ref")
	}

	source, exists, err := s.encryption.pools.StoragePoolSource(pool)
	if err != nil || !exists {
		t.Fatalf("StoragePoolSource(%s) = (%q, %v, %v)", pool, source, exists, err)
	}
	firstRoot, err := zfs.EncryptionRoot(ctx, first)
	if err != nil {
		t.Fatalf("EncryptionRoot(%s): %v", first, err)
	}
	if source != firstRoot {
		t.Errorf("the tenant's second container would be placed on a pool sourced at %q, but "+
			"their first container is under encryptionroot %q — the tenant would end up with two "+
			"keys and their containers could not share datasets", source, firstRoot)
	}
}

// The load-bearing negative. Everything above could pass while an ORDINARY
// create had quietly changed — landing on a tenant pool, or gaining an
// encryptionroot it should not have.
func TestIntegrationIncus_UnencryptedCreateIsUnchanged(t *testing.T) {
	s, client, tenantRoot := encTestEnv(t)
	zfs := zfscrypt.NewManager(zfscrypt.ExecRunner{})
	ctx := context.Background()

	tenant := fmt.Sprintf("plain%d", os.Getpid())
	instance := tenant + "-container"
	t.Cleanup(func() { incusenv.DeleteInstance(t, instance) })

	rpcCtx, cancel := context.WithTimeout(
		tenantWithScopes(tenant, auth.ScopeContainersWrite), 25*time.Minute)
	defer cancel()

	if _, err := s.CreateContainer(rpcCtx, &pb.CreateContainerRequest{
		Username:  tenant,
		Image:     "images:ubuntu/24.04",
		OsType:    pb.OSType_OS_TYPE_UBUNTU_2404,
		Resources: &pb.ResourceLimits{Disk: "5GB"},
		// Encrypted deliberately unset.
	}); err != nil {
		t.Fatalf("unencrypted CreateContainer: %v", err)
	}

	dataset := incusenv.DatasetFor(t, instance)
	if dataset == "" {
		t.Fatalf("instance %s has no ZFS dataset", instance)
	}

	// It must be on the daemon's default pool, not a tenant pool.
	defaultSource, _, err := client.StoragePoolSource(client.StoragePool())
	if err != nil {
		t.Fatalf("StoragePoolSource(%s): %v", client.StoragePool(), err)
	}
	if want := defaultSource + "/containers/" + instance; dataset != want {
		t.Errorf("an unencrypted container landed on %q, want %q — the default placement changed",
			dataset, want)
	}

	// And it must have no encryptionroot at all. EncryptionRoot errors for an
	// unencrypted dataset, which is the expected outcome here.
	if root, err := zfs.EncryptionRoot(ctx, dataset); err == nil {
		t.Errorf("an unencrypted create produced a dataset with encryptionroot %q — encryption "+
			"is leaking into the default path", root)
	}

	// No tenant storage should have been provisioned for it either.
	if _, exists, err := client.StoragePoolSource(tenantPoolName(tenant)); err == nil && exists {
		t.Errorf("a tenant storage pool was created for an unencrypted create")
	}
	if exists, err := zfs.Exists(ctx, tenantRoot+"/"+tenant); err == nil && exists {
		t.Errorf("a tenant encryptionroot was created for an unencrypted create")
		_ = zfs.Destroy(ctx, tenantRoot+"/"+tenant)
	}
}

// The question #1340 could not answer without an Incus: does Incus keep its
// pool's SOURCE dataset mounted?
//
// If it does, PostStop can never `zfs unload-key` the tenant encryptionroot,
// and "a stopped container's dataset is ciphertext, including to host root" —
// the claim the whole feature exists to make — would not hold in production,
// while every ZFS-lane test still passed.
func TestIntegrationIncus_StoppingTheLastContainerUnloadsTheTenantKey(t *testing.T) {
	s, _, tenantRoot := encTestEnv(t)
	zfs := zfscrypt.NewManager(zfscrypt.ExecRunner{})
	ctx := context.Background()

	tenant := fmt.Sprintf("stp%d", os.Getpid())
	t.Cleanup(func() { _ = zfs.Destroy(context.Background(), tenantRoot+"/"+tenant) })

	instance := createEncrypted(t, s, tenant)
	root := tenantRoot + "/" + tenant

	if status, err := zfs.KeyStatus(ctx, root); err != nil {
		t.Fatalf("KeyStatus(%s): %v", root, err)
	} else if status != zfscrypt.KeyAvailable {
		t.Fatalf("precondition: the running container's key is %q, want %q", status, zfscrypt.KeyAvailable)
	}

	// Stop it the way the daemon does, then run the hook the daemon runs.
	if err := s.boxes().Stop(ctx, box.BoxRef{Tenant: tenant}, true); err != nil {
		t.Fatalf("stopping %s: %v", instance, err)
	}
	s.encryption.PostStop(ctx, instance)

	status, err := zfs.KeyStatus(ctx, root)
	if err != nil {
		t.Fatalf("KeyStatus(%s) after stop: %v", root, err)
	}
	if status != zfscrypt.KeyUnavailable {
		t.Fatalf("the tenant encryptionroot %s still has its key loaded (%q) after its last "+
			"container stopped.\n\nIf Incus keeps the pool's source dataset mounted, "+
			"`zfs unload-key` can never succeed and a stopped container is NOT ciphertext at "+
			"rest — the central claim of #1199. This is the question #1340 could not answer "+
			"without an Incus; if it fails here, that is the answer and the design needs a "+
			"way to release the pool's mount before unloading.", root, status)
	}
	t.Logf("the tenant key is unloaded after the last container stops; %s is ciphertext at rest", root)
}
