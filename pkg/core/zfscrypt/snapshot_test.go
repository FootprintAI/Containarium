package zfscrypt

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// Unit coverage for the snapshot operations (#1202). These pin the
// orchestration; whether ZFS really permits snapshotting an unkeyed dataset
// is verified against a real pool in zfscrypt_integration_test.go.

// The resolved design decision: creation must NOT consult the key. A
// transient KMS outage suppressing the backup window is worse than a backup
// that cannot be read until custody recovers.
func TestSnapshotDoesNotRequireTheKey(t *testing.T) {
	f := newFakeRunner()
	m := NewManager(f)

	full, err := m.Snapshot(context.Background(), "pool/c/alice", "pre-upgrade")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if full != "pool/c/alice@pre-upgrade" {
		t.Errorf("returned %q", full)
	}

	args := f.allArgs()
	if strings.Contains(args, "keystatus") {
		t.Error("snapshot creation consulted keystatus — a KMS outage would then suppress the " +
			"backup window, which decision #3 explicitly rejects")
	}
	if !strings.Contains(args, "snapshot pool/c/alice@pre-upgrade") {
		t.Errorf("unexpected command: %s", args)
	}
}

// Retention must keep working while custody is down, or an outage becomes an
// unbounded-growth incident.
func TestDestroySnapshotDoesNotRequireTheKey(t *testing.T) {
	f := newFakeRunner()
	m := NewManager(f)

	if err := m.DestroySnapshot(context.Background(), "pool/c/alice@old"); err != nil {
		t.Fatalf("DestroySnapshot: %v", err)
	}
	if strings.Contains(f.allArgs(), "keystatus") {
		t.Error("snapshot destruction consulted keystatus; retention must survive a key outage")
	}
}

// A snapshot name must not be able to redirect the command at another
// object — '@' is the separator, so a name containing one would.
func TestSnapshotNameValidation(t *testing.T) {
	for _, name := range []string{"", "-o", "has space", "has@at", "has/slash", "has\nnewline"} {
		t.Run("name="+name, func(t *testing.T) {
			f := newFakeRunner()
			if _, err := NewManager(f).Snapshot(context.Background(), "pool/c/alice", name); err == nil {
				t.Errorf("accepted snapshot name %q", name)
			}
			if len(f.calls) != 0 {
				t.Error("a rejected name must not reach zfs")
			}
		})
	}
}

func TestSnapshotRejectsABadDataset(t *testing.T) {
	f := newFakeRunner()
	if _, err := NewManager(f).Snapshot(context.Background(), "pool", "snap"); err == nil {
		t.Error("accepted a bare pool name")
	}
	if len(f.calls) != 0 {
		t.Error("a rejected dataset must not reach zfs")
	}
}

// AC2: inspection must fail with a specific error, not an opaque ZFS one.
func TestEnsureInspectableReportsKeyUnavailableDistinctly(t *testing.T) {
	f := newFakeRunner()
	f.stdout["get"] = "unavailable"
	m := NewManager(f)

	err := m.EnsureInspectable(context.Background(), "pool/c/alice@snap")
	if !errors.Is(err, ErrKeyUnavailableForInspection) {
		t.Fatalf("err = %v, want ErrKeyUnavailableForInspection — the caller's remedy is specific "+
			"(restore key custody and retry) and a raw ZFS read error does not convey it", err)
	}
	// The message has to name what to look at.
	for _, want := range []string{"pool/c/alice@snap", "pool/c/alice", "unavailable"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error message is missing %q: %v", want, err)
		}
	}
}

func TestEnsureInspectablePassesWhenKeyLoaded(t *testing.T) {
	f := newFakeRunner()
	f.stdout["get"] = "available"
	if err := NewManager(f).EnsureInspectable(context.Background(), "pool/c/alice@snap"); err != nil {
		t.Errorf("EnsureInspectable with the key loaded: %v", err)
	}
}

func TestEnsureInspectableRejectsANonSnapshot(t *testing.T) {
	f := newFakeRunner()
	if err := NewManager(f).EnsureInspectable(context.Background(), "pool/c/alice"); err == nil {
		t.Error("accepted a dataset where a snapshot reference was required")
	}
}

func TestListSnapshotsParsesAndSkipsBlanks(t *testing.T) {
	f := newFakeRunner()
	f.stdout["list"] = "pool/c/alice@a\npool/c/alice@b\n\n"
	got, err := NewManager(f).ListSnapshots(context.Background(), "pool/c/alice")
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if len(got) != 2 || got[0] != "pool/c/alice@a" || got[1] != "pool/c/alice@b" {
		t.Errorf("got %v", got)
	}
	if strings.Contains(f.allArgs(), "keystatus") {
		t.Error("listing consulted keystatus; snapshot names are metadata and need no key")
	}
}

// Rollback is destructive twice over — it discards everything written since
// the snapshot, AND must destroy any snapshot taken after it. The second is
// gated (#1160).
func TestRollbackDoesNotDestroyNewerSnapshotsByDefault(t *testing.T) {
	f := newFakeRunner()
	m := NewManager(f)

	if err := m.RollbackToSnapshot(context.Background(), "pool/c/alice@snap", false); err != nil {
		t.Fatalf("RollbackToSnapshot: %v", err)
	}
	if strings.Contains(f.allArgs(), "-r") {
		t.Error("rollback passed -r without being asked to: that silently destroys every restore " +
			"point taken after the target, which is a wider blast radius than the caller requested")
	}
}

func TestRollbackDestroysNewerOnlyWhenAsked(t *testing.T) {
	f := newFakeRunner()
	m := NewManager(f)

	if err := m.RollbackToSnapshot(context.Background(), "pool/c/alice@snap", true); err != nil {
		t.Fatalf("RollbackToSnapshot: %v", err)
	}
	if !strings.Contains(f.allArgs(), "rollback -r pool/c/alice@snap") {
		t.Errorf("expected an explicit -r rollback, got: %s", f.allArgs())
	}
}

// ZFS's own refusal does not say which snapshots are in the way, or that the
// remedy is a deliberate flag rather than a retry.
func TestRollbackReportsNewerSnapshotsDistinctly(t *testing.T) {
	f := newFakeRunner()
	f.errs["rollback"] = errors.New("exit status 1")
	f.stderr["rollback"] = "cannot rollback to 'pool/c/alice@snap': more recent snapshots or bookmarks exist\nuse '-r' to force deletion of the following snapshots and bookmarks:\npool/c/alice@later"
	m := NewManager(f)

	err := m.RollbackToSnapshot(context.Background(), "pool/c/alice@snap", false)
	if !errors.Is(err, ErrNewerSnapshotsExist) {
		t.Fatalf("err = %v, want ErrNewerSnapshotsExist", err)
	}
	if !strings.Contains(err.Error(), "pool/c/alice@later") {
		t.Errorf("the error should name what stands in the way, got %q", err)
	}
}

func TestRollbackRejectsANonSnapshot(t *testing.T) {
	f := newFakeRunner()
	if err := NewManager(f).RollbackToSnapshot(context.Background(), "pool/c/alice", false); err == nil {
		t.Error("accepted a dataset where a snapshot reference was required")
	}
	if len(f.calls) != 0 {
		t.Error("a rejected reference must not reach zfs")
	}
}

// A forgotten snapshot silently pins disk, so the number a caller needs is
// `used` — what destroying it would free — not `referenced`, which is mostly
// shared with the live dataset.
func TestSnapshotUsageParsesBothNumbers(t *testing.T) {
	f := newFakeRunner()
	f.stdout["get"] = "1048576\t5242880\n"
	used, referenced, err := NewManager(f).SnapshotUsage(context.Background(), "pool/c/alice@snap")
	if err != nil {
		t.Fatalf("SnapshotUsage: %v", err)
	}
	if used != 1048576 || referenced != 5242880 {
		t.Errorf("used=%d referenced=%d", used, referenced)
	}
	// -p is what makes these exact bytes rather than "1M".
	if !strings.Contains(f.allArgs(), "-Hp") {
		t.Errorf("usage must be read in parseable bytes (-p), got: %s", f.allArgs())
	}
}

func TestSnapshotUsageRejectsUnparseableOutput(t *testing.T) {
	f := newFakeRunner()
	f.stdout["get"] = "1M\t5M\n" // human-readable: what -p exists to prevent
	if _, _, err := NewManager(f).SnapshotUsage(context.Background(), "pool/c/alice@snap"); err == nil {
		t.Error("accepted human-readable sizes as byte counts")
	}
}

// An UNENCRYPTED snapshot's contents are readable, so inspecting one must
// pass (#1160b).
//
// This is not hypothetical tidying. EnsureInspectable propagated KeyStatus's
// error verbatim, and KeyStatus errors on an unencrypted dataset — so the
// guard would have refused inspection and rollback for essentially every
// container on the platform, while the tests above (which only ever supply an
// encrypted dataset) stayed green.
func TestEnsureInspectablePassesForAnUnencryptedDataset(t *testing.T) {
	f := newFakeRunner()
	f.stdout["get"] = "-" // what ZFS reports for a dataset with no encryption
	if err := NewManager(f).EnsureInspectable(context.Background(), "pool/c/bob@snap"); err != nil {
		t.Fatalf("EnsureInspectable on an unencrypted dataset = %v, want nil — its contents can "+
			"be read, which is the question this asks", err)
	}
}

// "zfs did not answer" is not "there is no key here". A guard that treats
// them alike either blocks the fleet or fails open on a broken pool.
func TestEnsureInspectableStillFailsWhenZFSCannotAnswer(t *testing.T) {
	f := newFakeRunner()
	f.errs["get"] = errors.New("exit status 1")
	f.stderr["get"] = "cannot open 'pool/c/bob': dataset does not exist"

	err := NewManager(f).EnsureInspectable(context.Background(), "pool/c/bob@snap")
	if err == nil {
		t.Fatal("an unreadable keystatus was reported as inspectable")
	}
	if errors.Is(err, ErrNotEncrypted) {
		t.Errorf("a zfs failure was classified as 'not encrypted': %v", err)
	}
}

func TestKeyStatusMarksAnUnencryptedDatasetDistinctly(t *testing.T) {
	f := newFakeRunner()
	f.stdout["get"] = "-"

	_, err := NewManager(f).KeyStatus(context.Background(), "pool/c/bob")
	if !errors.Is(err, ErrNotEncrypted) {
		t.Fatalf("err = %v, want ErrNotEncrypted — callers distinguish this from a real failure, "+
			"and matching on the message instead is what the sentinel exists to avoid", err)
	}
}
