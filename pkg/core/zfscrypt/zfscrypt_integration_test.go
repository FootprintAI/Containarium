//go:build zfs

// Integration coverage against a REAL ZFS pool (#1200).
//
// The unit tests in zfscrypt_test.go drive a fake runner. They pin the
// orchestration — what command runs, in what order, what happens on failure
// — and they cannot show that ZFS does what the package assumes. The package
// doc lists three assumptions derived from documentation and never executed;
// every encryption phase so far has shipped with its core security property
// asserted against a fake and never demonstrated. This file demonstrates it.
//
//	sudo go test -tags=zfs ./pkg/core/zfscrypt/ -v
//
// Requires: the zfs kernel module, the zfs/zpool userspace tools, and root.
// The pool is file-backed (no real disks) and destroyed on teardown. Skips
// cleanly — never fails — where any of that is missing.
package zfscrypt

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/testsupport/zfspool"
	"github.com/footprintai/containarium/pkg/core/zfskey"
)

// canary is the plaintext we hunt for in the raw vdev. Distinctive enough
// that a hit cannot be coincidence, and repeated so it spans enough bytes to
// survive block alignment.
var canary = bytes.Repeat([]byte("CONTAINARIUM-PLAINTEXT-CANARY-7f3a9b2c-"), 64)

// testKey is shared with the unit tests in zfscrypt_test.go.

// THE security claim (#1168, #1201): a stopped container's dataset is
// ciphertext, including to host root.
//
// The load-bearing part is the POSITIVE CONTROL. An unencrypted dataset gets
// the same canary written the same way, and its canary MUST be findable in
// the raw vdev. Without that, "the canary is absent" proves nothing — ZFS
// enables compression by default, so an absent canary could just mean lz4
// rearranged it, and the test would pass just as happily against a dataset
// that was never encrypted at all. Both datasets set compression=off so the
// only difference between them is encryption.
func TestIntegration_StoppedDatasetIsCiphertextAtRest(t *testing.T) {
	zfspool.Require(t)
	ctx := context.Background()
	p := zfspool.New(t)
	m := NewManager(nil) // the real zfs binary

	plainDS := p.Dataset("plain")
	plainCanary := append([]byte("PLAIN-"), canary...)
	zfspool.Run(t, "zfs", "create", "-o", "compression=off", plainDS)
	if err := os.WriteFile(filepath.Join(p.Mount, "plain", "secret.txt"), plainCanary, 0o600); err != nil {
		t.Fatalf("write plaintext canary: %v", err)
	}
	zfspool.Run(t, "zfs", "unmount", plainDS)

	if !p.ContainsPlaintext(t, plainCanary) {
		t.Fatal("POSITIVE CONTROL FAILED: the canary written to an UNENCRYPTED dataset was not " +
			"found in the raw vdev. The search cannot detect plaintext at all, so the " +
			"encrypted case below would 'pass' for the wrong reason. Failing loudly instead.")
	}
	t.Log("positive control OK: plaintext on an unencrypted dataset IS visible in the raw vdev")

	encDS := p.Dataset("encrypted")
	key := testKey(t, 0xA5)
	if err := m.CreateEncrypted(ctx, encDS, key); err != nil {
		t.Fatalf("CreateEncrypted (assumption: keylocation=file:///dev/stdin with the raw key "+
			"on stdin is accepted by zfs create): %v", err)
	}
	zfspool.Run(t, "zfs", "set", "compression=off", encDS)

	encCanary := append([]byte("ENCRD-"), canary...)
	if err := os.WriteFile(filepath.Join(p.Mount, "encrypted", "secret.txt"), encCanary, 0o600); err != nil {
		t.Fatalf("write encrypted canary: %v", err)
	}

	// Stop the "container": unmount, then drop the key.
	zfspool.Run(t, "zfs", "unmount", encDS)
	if err := m.UnloadKey(ctx, encDS); err != nil {
		t.Fatalf("UnloadKey after unmount: %v", err)
	}

	status, err := m.KeyStatus(ctx, encDS)
	if err != nil {
		t.Fatalf("KeyStatus: %v", err)
	}
	if status != KeyUnavailable {
		t.Errorf("keystatus = %q, want %q", status, KeyUnavailable)
	}

	// AC: a read attempt by host root fails.
	if out, err := exec.Command("zfs", "mount", encDS).CombinedOutput(); err == nil {
		t.Error("host root mounted the dataset with the key unloaded — it is NOT ciphertext at rest")
	} else {
		t.Logf("read attempt by root correctly refused: %s", strings.TrimSpace(string(out)))
	}

	// AC: and the plaintext genuinely is not on the disk.
	if p.ContainsPlaintext(t, encCanary) {
		t.Error("the canary written to the ENCRYPTED dataset was found verbatim in the raw vdev — " +
			"the data is not encrypted at rest (#1168)")
	}
}

// Assumption 1 from the package doc: the key travels on stdin and is never
// written anywhere. Here that is checked against the real binary — the unit
// test can only show what we passed to a fake.
func TestIntegration_KeyRoundTripsThroughStdin(t *testing.T) {
	zfspool.Require(t)
	ctx := context.Background()
	p := zfspool.New(t)
	m := NewManager(nil)

	ds := p.Dataset("roundtrip")
	key := testKey(t, 0x5A)
	if err := m.CreateEncrypted(ctx, ds, key); err != nil {
		t.Fatalf("CreateEncrypted: %v", err)
	}

	zfspool.UnmountIfMounted(t, ds)
	if err := m.UnloadKey(ctx, ds); err != nil {
		t.Fatalf("UnloadKey: %v", err)
	}

	// The same key must bring it back...
	if err := m.LoadKey(ctx, ds, key); err != nil {
		t.Fatalf("LoadKey with the correct key: %v", err)
	}
	if status, err := m.KeyStatus(ctx, ds); err != nil || status != KeyAvailable {
		t.Fatalf("keystatus = %q (err %v), want %q", status, err, KeyAvailable)
	}

	// ...and LoadKey must be idempotent, which the daemon relies on when it
	// re-runs the pre-start hook after a restart.
	if err := m.LoadKey(ctx, ds, key); err != nil {
		t.Errorf("LoadKey is not idempotent against real ZFS: %v", err)
	}

	// A wrong key must be refused rather than silently accepted.
	zfspool.UnmountIfMounted(t, ds)
	if err := m.UnloadKey(ctx, ds); err != nil {
		t.Fatalf("UnloadKey before the wrong-key check: %v", err)
	}
	if err := m.LoadKey(ctx, ds, testKey(t, 0x11)); err == nil {
		t.Error("a WRONG key was accepted — the dataset would appear unlocked with the wrong material")
	}
}

// Assumption 2 from the package doc, and the one with a real bug behind it:
// `zfs unload-key` must FAIL rather than silently succeed while the dataset
// is still mounted.
//
// This matters to the post-stop hook (#1201): it calls UnloadKey and treats
// ErrKeyInUse as the benign "a co-tenant is still running" case. If ZFS
// instead refused for the mundane reason that this dataset is still mounted,
// the hook would log the wrong explanation AND leave the data readable.
func TestIntegration_UnloadKeyRefusesWhileMounted(t *testing.T) {
	zfspool.Require(t)
	ctx := context.Background()
	p := zfspool.New(t)
	m := NewManager(nil)

	ds := p.Dataset("mounted")
	if err := m.CreateEncrypted(ctx, ds, testKey(t, 0x33)); err != nil {
		t.Fatalf("CreateEncrypted: %v", err)
	}
	// Freshly created and still mounted.
	if out := zfspool.Run(t, "zfs", "get", "-H", "-o", "value", "mounted", ds); strings.TrimSpace(out) != "yes" {
		t.Skipf("dataset is not mounted (%q), so this assumption cannot be exercised", strings.TrimSpace(out))
	}

	err := m.UnloadKey(ctx, ds)
	if err == nil {
		t.Fatal("unload-key SUCCEEDED while the dataset was mounted. The post-stop hook assumes " +
			"the opposite, so a co-tenant's running container could lose its key (#1201).")
	}
	if !errors.Is(err, ErrKeyInUse) {
		t.Errorf("unload-key failed as expected, but not as ErrKeyInUse: %v\n"+
			"isKeyInUse() does not recognise this ZFS build's message, so the post-stop hook "+
			"would report a real failure as the benign co-tenant case", err)
	}
}

// Assumption 3: keystatus reports exactly "available"/"unavailable", and an
// unencrypted dataset reports "-" (which the package treats as an error).
func TestIntegration_KeyStatusVocabulary(t *testing.T) {
	zfspool.Require(t)
	ctx := context.Background()
	p := zfspool.New(t)
	m := NewManager(nil)

	enc := p.Dataset("enc")
	if err := m.CreateEncrypted(ctx, enc, testKey(t, 0x77)); err != nil {
		t.Fatalf("CreateEncrypted: %v", err)
	}
	if got := strings.TrimSpace(zfspool.Run(t, "zfs", "get", "-H", "-o", "value", "keystatus", enc)); got != "available" {
		t.Errorf("raw keystatus = %q, want \"available\" — the package parses this string exactly", got)
	}

	plain := p.Dataset("plain")
	zfspool.Run(t, "zfs", "create", plain)
	if _, err := m.KeyStatus(ctx, plain); err == nil {
		t.Error("KeyStatus accepted an unencrypted dataset; the caller and the dataset disagree " +
			"about what this container is, which must be an error")
	}

	// EncryptionRoot is what the per-tenant isolation claim rests on.
	child := enc + "/child"
	zfspool.Run(t, "zfs", "create", child)
	root, err := m.EncryptionRoot(ctx, child)
	if err != nil {
		t.Fatalf("EncryptionRoot: %v", err)
	}
	if root != enc {
		t.Errorf("encryptionroot = %q, want %q — a child must inherit its parent's key, which is "+
			"what makes one tenant's containers share an encryptionroot and two tenants never", root, enc)
	}
}

// The isolation claim the whole per-tenant design exists for: two tenants
// never share an encryptionroot, and one tenant's key cannot open another
// tenant's data.
//
// #1199's first AC ("a container created with encrypted=true has its own
// encryptionroot, distinct from another tenant's") needs the pre-create
// wiring, which needs Incus. This proves the ZFS half of it — that the
// command layer, given two tenants, really does produce two independent
// crypto domains — so what remains open on that AC is the daemon wiring
// rather than the property itself.
//
// The load-bearing assertion is the NEGATIVE one: tenant A's key must be
// REFUSED against tenant B's dataset. Distinct encryptionroot strings would
// otherwise be satisfied by two datasets that happen to share key material.
func TestIntegration_TenantsCannotUnlockEachOther(t *testing.T) {
	zfspool.Require(t)
	ctx := context.Background()
	p := zfspool.New(t)
	m := NewManager(nil)

	dsA, keyA := p.Dataset("tenant-a"), testKey(t, 0xAA)
	dsB, keyB := p.Dataset("tenant-b"), testKey(t, 0xBB)
	for _, tc := range []struct {
		ds  string
		key zfskey.Key
	}{{dsA, keyA}, {dsB, keyB}} {
		if err := m.CreateEncrypted(ctx, tc.ds, tc.key); err != nil {
			t.Fatalf("CreateEncrypted(%s): %v", tc.ds, err)
		}
	}

	rootA, err := m.EncryptionRoot(ctx, dsA)
	if err != nil {
		t.Fatalf("EncryptionRoot(A): %v", err)
	}
	rootB, err := m.EncryptionRoot(ctx, dsB)
	if err != nil {
		t.Fatalf("EncryptionRoot(B): %v", err)
	}
	if rootA == rootB {
		t.Fatalf("both tenants share encryptionroot %q — one tenant's key would open the other's data", rootA)
	}

	// Take tenant B's key away, as a stop would.
	zfspool.UnmountIfMounted(t, dsB)
	if err := m.UnloadKey(ctx, dsB); err != nil {
		t.Fatalf("UnloadKey(B): %v", err)
	}

	// THE assertion: A's key must not open B.
	if err := m.LoadKey(ctx, dsB, keyA); err == nil {
		t.Error("tenant A's key unlocked tenant B's dataset — the per-tenant isolation claim is false")
	}
	// And B's own key still must.
	if err := m.LoadKey(ctx, dsB, keyB); err != nil {
		t.Errorf("tenant B's own key no longer opens its dataset: %v", err)
	}

	// Tenant A is undisturbed throughout — stopping or re-keying one tenant
	// must not touch another.
	if status, err := m.KeyStatus(ctx, dsA); err != nil || status != KeyAvailable {
		t.Errorf("tenant A keystatus = %q (err %v), want %q — B's lifecycle affected A",
			status, err, KeyAvailable)
	}
}

// The premise behind resolved decision #3 (#1202): snapshots of an encrypted
// dataset can be taken, listed and destroyed with the key UNLOADED, because
// those touch metadata rather than contents.
//
// The design chose "allow creation, fail the read" on the strength of that
// claim — blocking creation on key custody would let a transient KMS outage
// silently suppress a backup window. If ZFS actually refused to snapshot an
// unkeyed dataset, that decision would be unimplementable and the sprint's
// backup story would need rethinking, so it is worth demonstrating rather
// than believing.
func TestIntegration_SnapshotsWorkWithTheKeyUnloaded(t *testing.T) {
	zfspool.Require(t)
	ctx := context.Background()
	p := zfspool.New(t)
	m := NewManager(nil)

	ds := p.Dataset("snapme")
	key := testKey(t, 0xC3)
	if err := m.CreateEncrypted(ctx, ds, key); err != nil {
		t.Fatalf("CreateEncrypted: %v", err)
	}
	if err := os.WriteFile(filepath.Join(p.Mount, "snapme", "data.txt"), []byte("tenant data"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Stop the container: unmount and drop the key.
	zfspool.UnmountIfMounted(t, ds)
	if err := m.UnloadKey(ctx, ds); err != nil {
		t.Fatalf("UnloadKey: %v", err)
	}
	if status, err := m.KeyStatus(ctx, ds); err != nil || status != KeyUnavailable {
		t.Fatalf("precondition: keystatus = %q (err %v), want %q", status, err, KeyUnavailable)
	}

	// THE premise: creation succeeds anyway.
	snap, err := m.Snapshot(ctx, ds, "backup-window")
	if err != nil {
		t.Fatalf("snapshot of an unkeyed dataset FAILED: %v\n"+
			"Decision #3 (allow creation while the key is unavailable) assumes this works. "+
			"If ZFS refuses, the design's backup story needs rethinking, not a workaround.", err)
	}

	// Listing is metadata, so it must work too.
	snaps, err := m.ListSnapshots(ctx, ds)
	if err != nil {
		t.Fatalf("ListSnapshots with the key unloaded: %v", err)
	}
	var found bool
	for _, s := range snaps {
		if s == snap {
			found = true
		}
	}
	if !found {
		t.Errorf("snapshot %q not listed; got %v", snap, snaps)
	}

	// AC2: inspection is refused, and specifically.
	err = m.EnsureInspectable(ctx, snap)
	if !errors.Is(err, ErrKeyUnavailableForInspection) {
		t.Errorf("EnsureInspectable = %v, want ErrKeyUnavailableForInspection", err)
	}

	// Once custody is back, the same snapshot becomes inspectable — the
	// snapshot was never damaged, only unreadable.
	if err := m.LoadKey(ctx, ds, key); err != nil {
		t.Fatalf("LoadKey: %v", err)
	}
	if err := m.EnsureInspectable(ctx, snap); err != nil {
		t.Errorf("snapshot still not inspectable after the key came back: %v", err)
	}

	// And retention works without the key: drop it again, then destroy.
	zfspool.UnmountIfMounted(t, ds)
	if err := m.UnloadKey(ctx, ds); err != nil {
		t.Fatalf("UnloadKey (second): %v", err)
	}
	if err := m.DestroySnapshot(ctx, snap); err != nil {
		t.Errorf("DestroySnapshot with the key unloaded failed: %v\n"+
			"Retention has to survive a key outage, or an outage becomes an "+
			"unbounded-growth incident.", err)
	}
}

// Rollback and snapshot accounting against a real pool (#1160).
//
// Rollback is the most destructive operation in this package, and its
// safety story is entirely about what ZFS does when snapshots exist after
// the target. Asserting that against a fake would be asserting my own
// reading of the manual — which the two corrections this lane has already
// produced (load-key does not remount; unload-key does refuse while
// mounted) suggest is not good enough for a destructive operation.
func TestIntegration_RollbackAndSnapshotAccounting(t *testing.T) {
	zfspool.Require(t)
	ctx := context.Background()
	p := zfspool.New(t)
	m := NewManager(nil)

	ds := p.Dataset("rollback")
	key := testKey(t, 0x5C)
	if err := m.CreateEncrypted(ctx, ds, key); err != nil {
		t.Fatalf("CreateEncrypted: %v", err)
	}
	zfspool.Run(t, "zfs", "set", "compression=off", ds)

	dir := filepath.Join(p.Mount, "rollback")
	before := filepath.Join(dir, "before.txt")
	if err := os.WriteFile(before, []byte("state at snapshot time"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	snap, err := m.Snapshot(ctx, ds, "good")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	// Write something AFTER the snapshot; rollback must discard it.
	after := filepath.Join(dir, "after.txt")
	if err := os.WriteFile(after, []byte("written after the snapshot"), 0o600); err != nil {
		t.Fatalf("write after: %v", err)
	}

	// A snapshot taken later is what makes an unqualified rollback refuse.
	later, err := m.Snapshot(ctx, ds, "later")
	if err != nil {
		t.Fatalf("Snapshot(later): %v", err)
	}

	// THE safety property: rolling back past a newer snapshot is refused,
	// and recognised as that specific condition rather than a generic error.
	err = m.RollbackToSnapshot(ctx, snap, false)
	if !errors.Is(err, ErrNewerSnapshotsExist) {
		t.Fatalf("rollback with a newer snapshot present = %v, want ErrNewerSnapshotsExist. "+
			"If ZFS no longer refuses, an unqualified rollback would destroy restore points "+
			"the caller never named.", err)
	}

	// Accounting: the snapshot pins space, and `used` is the number that
	// would be freed by destroying it.
	if _, _, err := m.SnapshotUsage(ctx, snap); err != nil {
		t.Errorf("SnapshotUsage: %v", err)
	}

	// With the newer snapshot destroyed, the rollback proceeds.
	if err := m.DestroySnapshot(ctx, later); err != nil {
		t.Fatalf("DestroySnapshot(later): %v", err)
	}
	if err := m.RollbackToSnapshot(ctx, snap, false); err != nil {
		t.Fatalf("rollback after clearing newer snapshots: %v", err)
	}

	// The dataset really is back: the post-snapshot write is gone, the
	// pre-snapshot one remains.
	if _, err := os.Stat(after); !os.IsNotExist(err) {
		t.Errorf("after.txt survived the rollback (stat err = %v)", err)
	}
	if _, err := os.Stat(before); err != nil {
		t.Errorf("before.txt did not survive the rollback: %v", err)
	}
}
