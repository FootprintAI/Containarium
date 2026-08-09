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
	"os"
	"path/filepath"
	"testing"

	"github.com/footprintai/containarium/internal/testsupport/zfspool"
	"github.com/footprintai/containarium/pkg/core/zfscrypt"
	"github.com/footprintai/containarium/pkg/core/zfskey"
)

// canary is the plaintext hunted for in the raw vdev.
var hookCanary = bytes.Repeat([]byte("CONTAINARIUM-HOOK-CANARY-4e1d8a6b-"), 64)

// memKeyRefStore stands in for the Incus config key the daemon really uses.
type memKeyRefStore struct{ refs map[string]zfskey.KeyRef }

func (m *memKeyRefStore) GetKeyRef(name string) (zfskey.KeyRef, bool, error) {
	ref, ok := m.refs[name]
	return ref, ok, nil
}

func (m *memKeyRefStore) SetKeyRef(name string, ref zfskey.KeyRef) error {
	m.refs[name] = ref
	return nil
}

// fixedResolver maps container names to datasets.
type fixedResolver struct{ datasets map[string]string }

func (f fixedResolver) DatasetFor(name string) (string, error) { return f.datasets[name], nil }

// harness wires real encryption machinery over a throwaway pool.
type harness struct {
	pool  *zfspool.Pool
	hooks *encryptionHooks
	keys  *zfskey.FileKeyProvider
	refs  *memKeyRefStore
	res   fixedResolver
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	zfspool.Require(t)

	keys, err := zfskey.NewFileKeyProvider(filepath.Join(t.TempDir(), "keys"))
	if err != nil {
		t.Fatalf("NewFileKeyProvider: %v", err)
	}
	h := &harness{
		pool: zfspool.New(t),
		keys: keys,
		refs: &memKeyRefStore{refs: map[string]zfskey.KeyRef{}},
		res:  fixedResolver{datasets: map[string]string{}},
	}
	h.hooks = &encryptionHooks{
		provider: keys,
		zfs:      zfscrypt.NewManager(nil), // the real zfs binary
		cache:    zfskey.NewCache(0),
		refs:     h.refs,
		datasets: h.res,
	}
	return h
}

// createBox mints a key, creates the encrypted dataset, and records the ref
// the way the create path does.
func (h *harness) createBox(t *testing.T, ctx context.Context, container, tenant string) string {
	t.Helper()
	key, ref, err := h.keys.Wrap(ctx, tenant)
	if err != nil {
		t.Fatalf("KeyProvider.Wrap(%s): %v", tenant, err)
	}
	dataset := h.pool.Dataset(container)
	if err := h.hooks.zfs.CreateEncrypted(ctx, dataset, key); err != nil {
		t.Fatalf("CreateEncrypted(%s): %v", dataset, err)
	}
	h.res.datasets[container] = dataset
	if err := h.hooks.RecordKeyRef(container, ref); err != nil {
		t.Fatalf("RecordKeyRef: %v", err)
	}
	return dataset
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

	secret := filepath.Join(h.pool.Mount, "box-alice", "secret.txt")
	if err := os.WriteFile(secret, hookCanary, 0o600); err != nil {
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
	zfspool.UnmountIfMounted(t, dataset)
	h.hooks.PostStop(ctx, "box-alice")

	status, err := h.hooks.zfs.KeyStatus(ctx, dataset)
	if err != nil {
		t.Fatalf("KeyStatus: %v", err)
	}
	if status != zfscrypt.KeyUnavailable {
		t.Errorf("keystatus after PostStop = %q, want %q — the hook did not drop the key",
			status, zfscrypt.KeyUnavailable)
	}

	if h.pool.ContainsPlaintext(t, hookCanary) {
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
	// which is the shape the design gives a tenant's containers.
	key, ref, err := h.keys.Wrap(ctx, "acme")
	if err != nil {
		t.Fatalf("KeyProvider.Wrap: %v", err)
	}
	root := h.pool.Dataset("acme")
	if err := h.hooks.zfs.CreateEncrypted(ctx, root, key); err != nil {
		t.Fatalf("CreateEncrypted(root): %v", err)
	}

	for _, box := range []string{"box-one", "box-two"} {
		ds := root + "/" + box
		zfspool.Run(t, "zfs", "create", ds)
		h.res.datasets[box] = ds
		if err := h.hooks.RecordKeyRef(box, ref); err != nil {
			t.Fatalf("RecordKeyRef(%s): %v", box, err)
		}
	}

	// Confirm they really do share one encryptionroot — the property the
	// whole per-tenant isolation claim rests on.
	for _, box := range []string{"box-one", "box-two"} {
		got, err := h.hooks.zfs.EncryptionRoot(ctx, h.res.datasets[box])
		if err != nil {
			t.Fatalf("EncryptionRoot(%s): %v", box, err)
		}
		if got != root {
			t.Fatalf("%s encryptionroot = %q, want %q", box, got, root)
		}
	}

	// Stop box-one while box-two is still "running" (still mounted).
	zfspool.UnmountIfMounted(t, h.res.datasets["box-one"])
	if !zfspool.IsMounted(t, h.res.datasets["box-two"]) {
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
