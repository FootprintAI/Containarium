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
