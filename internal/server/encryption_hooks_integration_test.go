//go:build zfs

// Integration coverage for the container lifecycle hooks against a REAL
// ZFS pool (#1201, proof enabled by #1200).
//
// encryption_hooks_test.go drives these with a fake zfscrypt runner and
// proves the orchestration: what runs, in what order, what is tolerated.
// It cannot show that PostStop actually leaves a stopped container's
// dataset as ciphertext, which is the entire point of the hook.
//
//	sudo go test -tags=zfs ./internal/server/ -run TestIntegrationEncryption -v
//
// Only the Incus-side plumbing is faked here — the key-ref store and the
// dataset resolver. The KeyProvider, the zfscrypt Manager and the pool are
// all real.
package server

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/testsupport/zfspool"
	"github.com/footprintai/containarium/pkg/core/zfscrypt"
	"github.com/footprintai/containarium/pkg/core/zfskey"
)

// canary is the plaintext hunted for in the raw vdev.
var hookCanary = bytes.Repeat([]byte("CONTAINARIUM-HOOK-CANARY-4e1d8a6b-"), 64)

// memEncryptionState stands in for the Incus config keys the daemon really
// uses to record a container's key ref and storage pool.
type memEncryptionState struct {
	refs  map[string]zfskey.KeyRef
	pools map[string]string
}

func (m *memEncryptionState) GetKeyRef(name string) (zfskey.KeyRef, bool, error) {
	ref, ok := m.refs[name]
	return ref, ok, nil
}

func (m *memEncryptionState) SetKeyRef(name string, ref zfskey.KeyRef) error {
	m.refs[name] = ref
	return nil
}

func (m *memEncryptionState) GetPool(name string) (string, error) { return m.pools[name], nil }

func (m *memEncryptionState) SetPool(name, pool string) error {
	m.pools[name] = pool
	return nil
}

// memPools stands in for Incus's storage-pool API. Incus itself is not
// available in this lane — that is the incus lane's job (#1332) — so what is
// under test here is the ZFS half: that the datasets the hooks create really
// do give each tenant its own encryptionroot.
type memPools struct{ sources map[string]string }

func (m *memPools) CreateZFSPool(name, source string) error {
	m.sources[name] = source
	return nil
}

func (m *memPools) StoragePoolSource(name string) (string, bool, error) {
	src, ok := m.sources[name]
	return src, ok, nil
}

// unavailableKeys stands in for key custody being unreachable.
type unavailableKeys struct{}

func (unavailableKeys) Wrap(context.Context, string) (zfskey.Key, zfskey.KeyRef, error) {
	return zfskey.Key{}, zfskey.KeyRef{}, errors.New("key custody unavailable")
}

func (unavailableKeys) Load(context.Context, zfskey.KeyRef) (zfskey.Key, error) {
	return zfskey.Key{}, errors.New("key custody unavailable")
}

// harness wires real encryption machinery over a throwaway pool.
type harness struct {
	pool  *zfspool.Pool
	hooks *encryptionHooks
	keys  *zfskey.FileKeyProvider
	refs  *memEncryptionState
	pools *memPools
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	zfspool.Require(t)

	keys, err := zfskey.NewFileKeyProvider(filepath.Join(t.TempDir(), "keys"))
	if err != nil {
		t.Fatalf("NewFileKeyProvider: %v", err)
	}
	h := &harness{
		pool:  zfspool.New(t),
		keys:  keys,
		refs:  &memEncryptionState{refs: map[string]zfskey.KeyRef{}, pools: map[string]string{}},
		pools: &memPools{sources: map[string]string{}},
	}
	h.hooks = &encryptionHooks{
		provider: keys,
		zfs:      zfscrypt.NewManager(nil), // the real zfs binary
		cache:    zfskey.NewCache(0),
		refs:     h.refs,
		pools:    h.pools,
		// Tenant encryptionroots are children of the throwaway pool, so
		// tenantDataset produces <pool>/<tenant> — the same shape production
		// gets from --zfs-tenant-root.
		tenantRoot: h.pool.Name,
	}
	return h
}

// createBox provisions a box through EnsureTenantStorage — the hook the
// create path calls — rather than reproducing its steps here.
//
// It used to mint the key, create the dataset and record the ref itself,
// which meant every test below exercised a local imitation of the create
// path instead of the path itself. A divergence between the two would have
// left these tests passing against code production does not run.
//
// The child dataset stands in for the one Incus would clone from the image
// INSIDE the tenant pool. Creating it with a plain `zfs create` is faithful
// to what matters here: it inherits the tenant's key exactly as a clone
// would, which is the property these tests exist to check.
func (h *harness) createBox(t *testing.T, ctx context.Context, container, tenant string) string {
	t.Helper()
	pool, ref, err := h.hooks.EnsureTenantStorage(ctx, tenant)
	if err != nil {
		t.Fatalf("EnsureTenantStorage(%s): %v", tenant, err)
	}

	dataset := h.pool.Dataset(tenant) + "/" + container
	zfspool.Run(t, "zfs", "create", dataset)

	if err := h.hooks.RecordPlacement(container, ref, pool); err != nil {
		t.Fatalf("RecordPlacement(%s): %v", container, err)
	}
	return dataset
}

// mountpointOf maps a dataset under the throwaway pool to its filesystem
// path. Derived rather than composed from the container name: a container's
// dataset now lives under its TENANT's encryptionroot, so the two are no
// longer the same string, and hardcoding the old shape is what made this
// test fail on the first run of the reshape.
func (h *harness) mountpointOf(dataset string) string {
	return filepath.Join(h.pool.Mount, strings.TrimPrefix(dataset, h.pool.Name+"/"))
}

// AC 1 (#1201): after stopping the last container under an encryptionroot,
// the key is unloaded and the dataset reads as ciphertext to host root.
//
// Driven through PostStop itself, not through zfscrypt.Manager — the hook
// is what production calls, and the hook is what has to leave the data
// unreadable.
func TestIntegrationEncryption_PostStopLeavesCiphertext(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	dataset := h.createBox(t, ctx, "box-alice", "alice")
	zfspool.Run(t, "zfs", "set", "compression=off", dataset)

	// Distinct prefixes, and the search uses the FULL prefixed string.
	// Searching for the bare shared suffix would find it inside the
	// control's plaintext — which sits unencrypted on this same vdev — and
	// report the encrypted dataset as leaking when it had not.
	encCanary := append([]byte("ENCRD-"), hookCanary...)
	secret := filepath.Join(h.mountpointOf(dataset), "secret.txt")
	if err := os.WriteFile(secret, encCanary, 0o600); err != nil {
		t.Fatalf("write canary: %v", err)
	}

	// Positive control. Without it, "the canary is absent" would prove
	// nothing: ZFS compresses by default, so an absent canary could just
	// mean lz4 rearranged the bytes, and this test would pass just as
	// happily against a dataset that was never encrypted. A sibling
	// UNENCRYPTED dataset, compression off, establishes that the search can
	// find plaintext at all.
	plain := h.pool.Dataset("plain-control")
	zfspool.Run(t, "zfs", "create", "-o", "compression=off", plain)
	plainCanary := append([]byte("CTRL-"), hookCanary...)
	if err := os.WriteFile(filepath.Join(h.pool.Mount, "plain-control", "secret.txt"), plainCanary, 0o600); err != nil {
		t.Fatalf("write control canary: %v", err)
	}
	zfspool.UnmountIfMounted(t, plain)
	if !h.pool.ContainsPlaintext(t, plainCanary) {
		t.Fatal("POSITIVE CONTROL FAILED: plaintext on an unencrypted dataset was not found in the " +
			"raw vdev, so the check below cannot detect plaintext and would pass for the wrong reason")
	}

	// "Stop the container": Incus unmounts, then the hook runs.
	//
	// BOTH the container's dataset and the tenant encryptionroot above it
	// are unmounted, because `zfs unload-key` refuses while anything under
	// the root is mounted — including the root itself. The old design had
	// them be the same dataset, so one unmount sufficed; they are now two.
	//
	// The harness mounts the tenant root only because zfspool creates the
	// throwaway pool with an inherited mountpoint. Whether a real Incus
	// leaves its pool's SOURCE dataset mounted is a different question, and
	// this lane has no Incus to answer it — see the note on #1341. If it
	// does, PostStop could never unload and "a stopped container is
	// ciphertext" would not hold in production.
	zfspool.UnmountIfMounted(t, dataset)
	zfspool.UnmountIfMounted(t, h.pool.Dataset("alice"))
	h.hooks.PostStop(ctx, "box-alice")

	status, err := h.hooks.zfs.KeyStatus(ctx, dataset)
	if err != nil {
		t.Fatalf("KeyStatus: %v", err)
	}
	if status != zfscrypt.KeyUnavailable {
		t.Errorf("keystatus after PostStop = %q, want %q — the hook did not drop the key",
			status, zfscrypt.KeyUnavailable)
	}

	if h.pool.ContainsPlaintext(t, encCanary) {
		t.Error("the stopped container's data was found verbatim in the raw vdev — PostStop did " +
			"not leave it as ciphertext (#1201)")
	}
}

// AC 2 (#1201): stopping one of several containers under the same
// encryptionroot must NOT unload the key, and the others keep running.
//
// This is the case the hook's ErrKeyInUse branch exists for. Here it is
// exercised against real ZFS: two datasets share an encryptionroot, one is
// unmounted, and the co-tenant's must stay readable.
func TestIntegrationEncryption_PostStopKeepsKeyForRunningCoTenant(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	// One tenant, one key, one encryptionroot — a parent with two children,
	// which is the shape the design gives a tenant's containers, and which
	// EnsureTenantStorage now produces rather than the test assembling it.
	root := h.pool.Dataset("acme")
	boxes := map[string]string{}
	for _, box := range []string{"box-one", "box-two"} {
		boxes[box] = h.createBox(t, ctx, box, "acme")
	}

	// Confirm they really do share one encryptionroot — the property the
	// whole per-tenant isolation claim rests on. Note the direction: each
	// box INHERITS the tenant root rather than being its own, which is
	// exactly what makes a pool-per-tenant work at all.
	for box, ds := range boxes {
		got, err := h.hooks.zfs.EncryptionRoot(ctx, ds)
		if err != nil {
			t.Fatalf("EncryptionRoot(%s): %v", box, err)
		}
		if got != root {
			t.Fatalf("%s encryptionroot = %q, want the tenant root %q", box, got, root)
		}
	}

	// Stop box-one while box-two is still "running" (still mounted).
	zfspool.UnmountIfMounted(t, boxes["box-one"])
	if !zfspool.IsMounted(t, boxes["box-two"]) {
		t.Fatal("precondition: box-two should still be mounted")
	}

	// AC 3: the hook must not panic or block on this path — it returns
	// nothing, because the container has already stopped.
	h.hooks.PostStop(ctx, "box-one")

	// The key must still be loaded: box-two is using it.
	status, err := h.hooks.zfs.KeyStatus(ctx, root)
	if err != nil {
		t.Fatalf("KeyStatus(root): %v", err)
	}
	if status != zfscrypt.KeyAvailable {
		t.Fatalf("keystatus = %q, want %q — stopping one container took the key away from its "+
			"co-tenant, which would break a running box (#1201)", status, zfscrypt.KeyAvailable)
	}

	// And box-two must still be usable, not merely nominally keyed.
	probe := filepath.Join(h.pool.Mount, "acme", "box-two", "still-alive.txt")
	if err := os.WriteFile(probe, []byte("co-tenant still running"), 0o600); err != nil {
		t.Errorf("co-tenant's dataset became unusable after its neighbour stopped: %v", err)
	}
}

// AC 3 (#1201): a failed unload is logged and does not fail the stop.
//
// The container has already stopped; the operator needs to know, not to be
// blocked. Exercised here with a dataset that is still mounted — the
// realistic cause of a refusal — and asserted by the hook returning
// normally rather than by reading logs.
func TestIntegrationEncryption_PostStopDoesNotBlockOnFailure(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	dataset := h.createBox(t, ctx, "box-busy", "busy")
	if !zfspool.IsMounted(t, dataset) {
		t.Skip("dataset is not mounted, so a refusal cannot be provoked")
	}

	// Deliberately do NOT unmount: unload-key will refuse.
	h.hooks.PostStop(ctx, "box-busy")

	// The hook returns nothing, so the assertion is that the stop was not
	// impeded and the dataset is still intact and usable.
	if status, err := h.hooks.zfs.KeyStatus(ctx, dataset); err != nil || status != zfscrypt.KeyAvailable {
		t.Errorf("keystatus = %q (err %v); a refused unload must leave the dataset as it was",
			status, err)
	}
}

// #1199 AC1: a container created encrypted has its own encryptionroot,
// distinct from another tenant's.
//
// Only checkable against real ZFS. The unit tests can show PreCreate asks
// for a per-tenant key, but "these two datasets are under different
// encryptionroots" is a property ZFS computes, not one the caller asserts —
// and it is the property the whole tenant boundary rests on. If two tenants
// landed under one root, either tenant's key would unlock the other's data
// and every unit test would still pass.
func TestIntegrationEncryption_EnsureTenantStorageGivesEachTenantItsOwnRoot(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	aliceOne := h.createBox(t, ctx, "alice-one", "alice")
	aliceTwo := h.createBox(t, ctx, "alice-two", "alice")
	bobOne := h.createBox(t, ctx, "bob-one", "bob")

	rootOf := func(dataset string) string {
		t.Helper()
		root, err := h.hooks.zfs.EncryptionRoot(ctx, dataset)
		if err != nil {
			t.Fatalf("EncryptionRoot(%s): %v", dataset, err)
		}
		return root
	}

	aliceRoot1, aliceRoot2, bobRoot := rootOf(aliceOne), rootOf(aliceTwo), rootOf(bobOne)

	// Each container inherits its TENANT's encryptionroot — not its own.
	// That is the inversion #1335 forced: Incus clones the image to make an
	// instance and a clone takes its key from where it is made, so the key
	// has to live on the dataset the pool is sourced at.
	if want := h.pool.Dataset("alice"); aliceRoot1 != want {
		t.Errorf("alice-one's encryptionroot is %q, want the tenant root %q", aliceRoot1, want)
	}
	if aliceRoot1 != aliceRoot2 {
		t.Errorf("one tenant's two containers have encryptionroots %q and %q — they would need "+
			"two separate load-keys and could not share a pool", aliceRoot1, aliceRoot2)
	}
	if want := h.pool.Dataset("bob"); bobRoot != want {
		t.Errorf("bob-one's encryptionroot is %q, want the tenant root %q", bobRoot, want)
	}

	// The boundary that matters: no tenant's dataset sits under another's
	// root.
	if aliceRoot1 == bobRoot || aliceRoot2 == bobRoot {
		t.Errorf("alice and bob share an encryptionroot (%q) — one tenant's key would unlock "+
			"the other's data", bobRoot)
	}
}

// #1199 AC3, against a real pool: the KeyProvider being down must leave no
// dataset behind. A unit test shows no create was attempted; this shows the
// pool is genuinely unchanged, which is what "no partial dataset" means.
func TestIntegrationEncryption_EnsureTenantStorageLeavesNothingWhenKeysAreUnavailable(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	// The provider is stubbed to fail rather than misconfigured into
	// failing: what is under test is the pool's state afterwards, and a
	// provider that fails for an incidental reason would make the outcome
	// depend on how it happened to break.
	h.hooks.provider = unavailableKeys{}

	dataset := h.pool.Dataset("doomed")

	if _, _, err := h.hooks.EnsureTenantStorage(ctx, "doomed"); err == nil {
		t.Fatal("EnsureTenantStorage succeeded with key custody unavailable")
	}

	exists, err := h.hooks.zfs.Exists(ctx, dataset)
	if err != nil {
		t.Fatalf("Exists(%s): %v", dataset, err)
	}
	if exists {
		t.Errorf("dataset %s survived a failed create — it is unopenable, and the next create "+
			"for this container fails on a name that already exists", dataset)
	}
}

// #1204 AC1 and AC3, against a real pool: rotation completes, the new key
// opens the dataset, and **the old key stops working**.
//
// The negative is the whole point. A rewrap that silently left the old key
// valid would look identical to a successful rotation from the daemon's
// side — same exit code, same recorded ref — while the key the control plane
// just retired still opened the data. Only ZFS can answer whether the old
// key was actually retired, so only a real pool can assert it.
func TestIntegrationEncryption_RotationRetiresTheOldKey(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	// A tenant with its encryptionroot, provisioned through the hook.
	pool, _, err := h.hooks.EnsureTenantStorage(ctx, "acme")
	if err != nil {
		t.Fatalf("EnsureTenantStorage: %v", err)
	}
	root := h.pool.Dataset("acme")
	if _, ok := h.pools.sources[pool]; !ok {
		t.Fatalf("no pool source recorded for %s", pool)
	}

	oldKey, _, err := h.keys.Wrap(ctx, "acme")
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	// Rotate onto fresh material. In production the control plane provisions
	// this and passes only its ref; here the harness plays that part.
	newKeys, err := zfskey.NewFileKeyProvider(filepath.Join(t.TempDir(), "rotated"))
	if err != nil {
		t.Fatalf("NewFileKeyProvider: %v", err)
	}
	newKey, _, err := newKeys.Wrap(ctx, "acme")
	if err != nil {
		t.Fatalf("Wrap(new): %v", err)
	}

	if err := h.hooks.zfs.ChangeKey(ctx, root, newKey); err != nil {
		t.Fatalf("ChangeKey on %s: %v", root, err)
	}

	// Unload so the next load has to actually unwrap rather than answer from
	// the already-loaded key.
	zfspool.UnmountIfMounted(t, root)
	if err := h.hooks.zfs.UnloadKey(ctx, root); err != nil {
		t.Fatalf("UnloadKey: %v", err)
	}

	// AC3: the retired key must be refused.
	if err := h.hooks.zfs.LoadKey(ctx, root, oldKey); err == nil {
		t.Fatal("the OLD key still opens the dataset after rotation — the control plane would " +
			"retire a key that still grants access, which is worse than not rotating at all")
	}

	// AC1: the new key opens it.
	if err := h.hooks.zfs.LoadKey(ctx, root, newKey); err != nil {
		t.Fatalf("the new key does not open the rotated dataset: %v — the tenant's data is now "+
			"unreachable by either key, which is the one outcome rotation must never produce", err)
	}
}
