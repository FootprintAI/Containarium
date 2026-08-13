//go:build incus

package server

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/footprintai/containarium/internal/events"
	"github.com/footprintai/containarium/internal/metrics/platformstats"
	"github.com/footprintai/containarium/internal/testsupport/incusenv"
	boxlxc "github.com/footprintai/containarium/pkg/core/box/lxc"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/zfscrypt"
)

// #1342: --zfs-keys-dir is the switch. This drives the daemon's own startup
// wiring — keyProviderFromDir, SetKeyProvider, SetEncryptionStorage — rather
// than injecting a provider directly, so what is proven is the path an
// operator actually takes.
//
// Deliberately wires the hooks BEFORE custody, the opposite of dual_server's
// order. If SetKeyProvider ever stopped re-attaching to already-built hooks,
// the unit test would catch it and this would catch it against a real Incus:
// every encrypted create failing on a correctly-configured daemon.
func TestIntegrationIncus_KeysDirMakesEncryptedCreateWork(t *testing.T) {
	client := incusenv.Require(t)
	if err := client.InitializeInfrastructure(incus.DefaultNetworkConfig()); err != nil {
		t.Fatalf("the daemon's own infrastructure init failed: %v", err)
	}
	tenantRoot := DefaultTenantRoot(client)
	if tenantRoot == "" {
		t.Fatalf("could not derive a tenant dataset root from storage pool %q", client.StoragePool())
	}

	keysDir := filepath.Join(t.TempDir(), "keys")
	provider, err := keyProviderFromDir(keysDir)
	if err != nil {
		t.Fatalf("keyProviderFromDir(%s): %v", keysDir, err)
	}
	if provider == nil {
		t.Fatal("a configured --zfs-keys-dir produced no key custody")
	}

	mgr := container.NewWithBackend(client)
	s := &ContainerServer{
		manager:          mgr,
		boxBackend:       boxlxc.New(mgr),
		pendingCreations: map[string]*PendingCreation{},
		platformStats:    platformstats.New(),
		emitter:          events.NewEmitter(events.GetBus()),
	}
	s.SetEncryptionStorage(tenantRoot, client) // hooks first...
	s.SetKeyProvider(provider)                 // ...custody second

	zfs := zfscrypt.NewManager(zfscrypt.ExecRunner{})
	ctx := context.Background()
	tenant := fmt.Sprintf("kd%d", os.Getpid())
	t.Cleanup(func() { _ = zfs.Destroy(context.Background(), tenantRoot+"/"+tenant) })

	instance := createEncrypted(t, s, tenant)

	dataset := incusenv.DatasetFor(t, instance)
	if dataset == "" {
		t.Fatalf("instance %s has no ZFS dataset", instance)
	}
	root, err := zfs.EncryptionRoot(ctx, dataset)
	if err != nil {
		t.Fatalf("read encryptionroot of %s: %v — the create reported encryption it did not "+
			"deliver", dataset, err)
	}
	if want := tenantRoot + "/" + tenant; root != want {
		t.Fatalf("encryptionroot = %q, want %q", root, want)
	}

	// The flag decided WHERE custody lives, so a key must have appeared
	// there. Without this the test would pass on a provider that kept keys
	// somewhere else entirely, which is the one thing --zfs-keys-dir is for.
	entries, err := os.ReadDir(keysDir)
	if err != nil {
		t.Fatalf("read the configured keys dir %s: %v", keysDir, err)
	}
	if len(entries) == 0 {
		t.Fatalf("no key material under the configured --zfs-keys-dir %s — the container is "+
			"encrypted under a key the operator cannot find, back up, or rotate", keysDir)
	}
	t.Logf("encrypted create under %s with custody in %s (%d key file(s))", root, keysDir, len(entries))
}
