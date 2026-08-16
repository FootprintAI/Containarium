//go:build zfs

// What ZFS actually permits when cloning an ENCRYPTED snapshot (#1160c).
//
// The container-snapshots design defers clone to its own slice, saying the
// API "carries a real constraint: a ZFS clone must stay within its origin's
// encryptionroot, so a clone across tenants is not expressible", and that it
// is "worth confirming on the lane before designing the API".
//
// This file is that confirmation, and nothing else. It adds no production
// code and no clone primitive — it records what ZFS does, so #1160c is
// designed against demonstrated behaviour rather than against a plausible
// reading of the manual.
//
// The reason to spend a lane test on this is specific and recent. #1199's
// original design was built on an untested assumption about what Incus would
// accept, the assumption was wrong, and the whole mechanism had to be
// redesigned mid-sprint (#1335). The cost of checking first is one test; the
// cost of not checking was a week.
//
//	sudo go test -tags=zfs ./pkg/core/zfscrypt/ -run Clone -v
package zfscrypt

import (
	"context"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/testsupport/zfspool"
)

// Question 1: can a clone land in a DIFFERENT tenant's encryptionroot?
//
// This is the one that decides whether a cross-tenant clone API is even
// expressible. If ZFS permits it, the clone would be readable with the
// destination tenant's key — a cross-tenant data path, and the whole point of
// per-tenant encryption is that no such path exists. If ZFS refuses, the
// constraint is enforced beneath us and the API simply cannot offer it.
func TestIntegrationClone_AcrossEncryptionrootsIsRefused(t *testing.T) {
	zfspool.Require(t)
	ctx := context.Background()
	p := zfspool.New(t)
	m := NewManager(nil)

	dsA, dsB := p.Dataset("tenant-a"), p.Dataset("tenant-b")
	if err := m.CreateEncrypted(ctx, dsA, testKey(t, 0xAA)); err != nil {
		t.Fatalf("CreateEncrypted(A): %v", err)
	}
	if err := m.CreateEncrypted(ctx, dsB, testKey(t, 0xBB)); err != nil {
		t.Fatalf("CreateEncrypted(B): %v", err)
	}

	snap, err := m.Snapshot(ctx, dsA, "src")
	if err != nil {
		t.Fatalf("Snapshot(A): %v", err)
	}

	// A's snapshot, cloned INTO B's encryptionroot.
	target := dsB + "/from-a"
	_, stderr, err := m.run.Run(ctx, nil, "clone", snap, target)
	if err == nil {
		// If this ever passes, the design's constraint is wrong and something
		// much more serious is: A's data would be reachable under B's key.
		root, rootErr := m.EncryptionRoot(ctx, target)
		t.Fatalf("ZFS CLONED %s into another tenant's encryptionroot as %s (its encryptionroot is "+
			"now %q, err %v).\n\nThis contradicts the container-snapshots design AND the isolation "+
			"claim behind #1199: tenant A's data would be readable by whoever holds B's key. "+
			"#1160c cannot be designed until this is understood.", snap, target, root, rootErr)
	}

	t.Logf("confirmed: cloning across encryptionroots is refused by ZFS — %s",
		strings.TrimSpace(stderr))
}

// Question 2: a clone WITHIN the same encryptionroot — the case #1160c would
// actually ship, since a container clone belongs to the same tenant.
//
// Asserted positively so the refusal above is known to be about the
// encryptionroot boundary rather than about cloning being broken in this
// environment. A test that only shows a failure cannot tell those apart.
func TestIntegrationClone_WithinTheSameEncryptionrootWorks(t *testing.T) {
	zfspool.Require(t)
	ctx := context.Background()
	p := zfspool.New(t)
	m := NewManager(nil)

	tenant := p.Dataset("tenant-a")
	if err := m.CreateEncrypted(ctx, tenant, testKey(t, 0xAA)); err != nil {
		t.Fatalf("CreateEncrypted: %v", err)
	}
	// The shape the daemon uses: containers live under the tenant root, which
	// is the encryptionroot they inherit from.
	src := tenant + "/containers-src"
	if _, _, err := m.run.Run(ctx, nil, "create", src); err != nil {
		t.Fatalf("create source dataset: %v", err)
	}

	snap, err := m.Snapshot(ctx, src, "base")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	clone := tenant + "/containers-clone"
	if _, stderr, err := m.run.Run(ctx, nil, "clone", snap, clone); err != nil {
		t.Fatalf("cloning within one encryptionroot failed: %v: %s — if this cannot work, "+
			"#1160c has no viable shape at all", err, strings.TrimSpace(stderr))
	}

	// The clone must inherit the tenant's encryptionroot, not acquire one of
	// its own: a per-clone encryptionroot would be a second key to manage and
	// to lose, for data that is already the tenant's.
	root, err := m.EncryptionRoot(ctx, clone)
	if err != nil {
		t.Fatalf("EncryptionRoot(clone): %v", err)
	}
	if root != tenant {
		t.Errorf("clone %s has encryptionroot %q, want the tenant's %q", clone, root, tenant)
	}
	t.Logf("confirmed: a clone within one encryptionroot works and inherits it (%s)", root)
}

// Question 3: does a clone need the origin's key loaded?
//
// Matters because the lifecycle slice deliberately requires no key (#1160a),
// and an API where two of four verbs silently need key custody up and the
// others do not is one an operator cannot reason about. Whatever the answer,
// #1160c's contract has to state it.
func TestIntegrationClone_KeyRequirement(t *testing.T) {
	zfspool.Require(t)
	ctx := context.Background()
	p := zfspool.New(t)
	m := NewManager(nil)

	tenant := p.Dataset("tenant-a")
	if err := m.CreateEncrypted(ctx, tenant, testKey(t, 0xAA)); err != nil {
		t.Fatalf("CreateEncrypted: %v", err)
	}
	src := tenant + "/src"
	if _, _, err := m.run.Run(ctx, nil, "create", src); err != nil {
		t.Fatalf("create source dataset: %v", err)
	}
	snap, err := m.Snapshot(ctx, src, "base")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	// Take the key away, as stopping the tenant's last container does.
	zfspool.UnmountIfMounted(t, src)
	zfspool.UnmountIfMounted(t, tenant)
	if err := m.UnloadKey(ctx, tenant); err != nil {
		t.Fatalf("UnloadKey: %v — the rest of this test would prove nothing", err)
	}
	if status, err := m.KeyStatus(ctx, tenant); err != nil || status != KeyUnavailable {
		t.Fatalf("precondition: keystatus = %q (err %v), want %q", status, err, KeyUnavailable)
	}

	_, stderr, err := m.run.Run(ctx, nil, "clone", snap, tenant+"/clone")

	// HYPOTHESIS, asserted rather than logged: cloning needs the key, because
	// the clone is a new dataset that has to inherit the origin's wrapping
	// key. A test that merely reports whichever answer it got cannot fail, so
	// it would pin nothing and rot silently — this one fails loudly if ZFS
	// disagrees, and the failure message carries the real answer.
	if err == nil {
		t.Fatalf("FACT for #1160c, and NOT the hypothesis: `zfs clone` SUCCEEDED with the key " +
			"unloaded.\n\nThat is the same rule as snapshot create/delete (#1160a), so the clone " +
			"RPC needs no key precondition — but the clone is then unreadable too, and its " +
			"response has to say so. Rewrite this assertion to pin the real behaviour.")
	}
	t.Logf("confirmed: cloning REQUIRES the key loaded — %s. The clone RPC must therefore refuse "+
		"with a key-custody error (as rollback does, #1160b) rather than following the lifecycle "+
		"slice's no-key rule", strings.TrimSpace(stderr))
}

// Question 4, and the one with a consequence that is already shipping: a
// clone pins its origin snapshot.
//
// #1160a's DeleteContainerSnapshot has a unit test asserting that a failed
// destroy is reported honestly, using ZFS's "dependent clones" message. This
// establishes that the message is real rather than invented, and that clone
// therefore introduces a way for a previously-reliable delete to start
// failing — which #1160c's design owes an answer for (promote? refuse? cascade?).
func TestIntegrationClone_PinsItsOriginSnapshot(t *testing.T) {
	zfspool.Require(t)
	ctx := context.Background()
	p := zfspool.New(t)
	m := NewManager(nil)

	tenant := p.Dataset("tenant-a")
	if err := m.CreateEncrypted(ctx, tenant, testKey(t, 0xAA)); err != nil {
		t.Fatalf("CreateEncrypted: %v", err)
	}
	src := tenant + "/src"
	if _, _, err := m.run.Run(ctx, nil, "create", src); err != nil {
		t.Fatalf("create source dataset: %v", err)
	}
	snap, err := m.Snapshot(ctx, src, "base")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if _, stderr, err := m.run.Run(ctx, nil, "clone", snap, tenant+"/clone"); err != nil {
		// Not t.Skip: the lane asserts that nothing skipped, and a question
		// that quietly answers itself with "could not ask" is worse than one
		// that fails. Question 3 establishes whether a key is needed; if
		// cloning fails HERE, where the key is loaded, something else is
		// wrong and it should be visible.
		t.Fatalf("cloning failed with the key loaded: %v: %s — question 3 covers the unkeyed "+
			"case, so this is a different problem", err, strings.TrimSpace(stderr))
	}

	// HYPOTHESIS: ZFS refuses to destroy a snapshot a clone depends on. This
	// is the assumption #1160a's DeleteContainerSnapshot error-path test was
	// written against, so it is already load-bearing for shipped code.
	if err := m.DestroySnapshot(ctx, snap); err == nil {
		t.Fatalf("FACT for #1160c, and NOT the hypothesis: a snapshot with a live clone WAS " +
			"destroyed.\n\nThat means delete needs no new guard — and that #1160a's " +
			"'dependent clones' error-path test is asserting a message this ZFS never emits. " +
			"Both need revisiting.")
	} else {
		t.Logf("confirmed: a snapshot with a live clone cannot be destroyed — %v.\n\n"+
			"Consequence for the shipped lifecycle: DeleteContainerSnapshot starts failing on "+
			"snapshots a clone depends on. #1160c owes a decision — promote the clone, refuse "+
			"with an error naming the dependent clone, or cascade — rather than leaving the "+
			"operator with whatever ZFS says.", err)
	}
}
