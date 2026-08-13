//go:build incus

package incus_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/testsupport/incusenv"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/zfscrypt"
	"github.com/footprintai/containarium/pkg/core/zfskey"
)

// #1338 AC3, and the only claim in this package that a fake cannot make.
//
// The unit tests pin what reaches Incus. Whether Incus will actually build an
// instance inside a pool sourced at an ENCRYPTED dataset — rather than
// refusing it the way it refuses a pre-existing instance dataset (#1335) — is
// a property Incus and ZFS compute between them. #1341 asserts the encryption
// that results; this asserts the pool works at all, so a failure here points
// at the pool operations rather than at the hook wiring above them.
//
// External test package (incus_test) on purpose: it uses the daemon's public
// surface, which is what #1340's hook will hold.

func TestIntegrationIncus_PoolSourcedAtAnEncryptedDataset(t *testing.T) {
	client := incusenv.Require(t)

	zfs := zfscrypt.NewManager(zfscrypt.ExecRunner{})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// The tenant's encryptionroot, made by the production CreateEncrypted —
	// the same call #1340's hook will make.
	dataset := fmt.Sprintf("incus-local/pooltest%d", os.Getpid())
	if err := zfs.CreateEncrypted(ctx, dataset, testKey(t)); err != nil {
		t.Fatalf("create the encrypted source dataset %s: %v", dataset, err)
	}
	t.Cleanup(func() { _ = zfs.Destroy(context.Background(), dataset) })

	pool := fmt.Sprintf("containarium-pooltest%d", os.Getpid())
	if err := client.CreateZFSPool(pool, dataset); err != nil {
		t.Fatalf("CreateZFSPool(%s, %s): %v", pool, dataset, err)
	}
	t.Cleanup(func() { _ = client.DeleteStoragePool(pool) })

	// Incus must report back the source it was given. If it normalises or
	// relocates it, every later assumption about where the encryptionroot
	// lives is wrong — and #1336 was exactly that class of mistake.
	source, exists, err := client.StoragePoolSource(pool)
	if err != nil {
		t.Fatalf("StoragePoolSource(%s): %v", pool, err)
	}
	if !exists {
		t.Fatalf("the pool %s was created and then reported absent", pool)
	}
	if source != dataset {
		t.Errorf("Incus reports source %q for the pool created on %q — the daemon's idea of "+
			"the tenant encryptionroot would not match the one in use", source, dataset)
	}

	// And the pool has to be usable, not merely present. A pool Incus accepts
	// at create time and refuses at volume time would make this whole
	// approach a dead end, which is precisely what happened to the previous
	// mechanism (#1335).
	if err := client.CreateContainer(incus.ContainerConfig{
		Name:  fmt.Sprintf("pooltest%d", os.Getpid()),
		Image: "images:ubuntu/24.04",
		Disk:  &incus.DiskDevice{Path: "/", Pool: pool, Size: "3GB"},
	}); err != nil {
		t.Fatalf("Incus would not build an instance in a pool sourced at an encrypted dataset: %v\n"+
			"That is the mechanism docs/architecture/per-tenant-encrypted-storage-pools.md rests on; "+
			"if it does not hold, #1199 needs another design and not more wiring.", err)
	}
	t.Cleanup(func() { incusenv.DeleteInstance(t, fmt.Sprintf("pooltest%d", os.Getpid())) })

	// The instance landed under the tenant's encryptionroot by inheritance.
	// #1341 owns the full cross-tenant proof; this is the single assertion
	// that the pool operations delivered what they promised.
	instance := incusenv.DatasetFor(t, fmt.Sprintf("pooltest%d", os.Getpid()))
	if instance == "" {
		t.Fatalf("the instance has no ZFS dataset under %s", dataset)
	}
	root, err := zfs.EncryptionRoot(ctx, instance)
	if err != nil {
		t.Fatalf("read encryptionroot of %s: %v", instance, err)
	}
	if root != dataset {
		t.Errorf("instance dataset %s has encryptionroot %q, want %q — the pool exists but does "+
			"not confer the tenant's key on what is created inside it", instance, root, dataset)
	}
}

// testKey returns 32 synthetic random bytes, per run, never written anywhere
// but the runner's throwaway pool.
func testKey(t *testing.T) zfskey.Key {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("generate key: %v", err)
	}
	key, err := zfskey.NewKey(b)
	if err != nil {
		t.Fatalf("wrap key: %v", err)
	}
	return key
}
