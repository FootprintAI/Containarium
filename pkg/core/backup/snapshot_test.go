package backup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type snapshotStorage struct {
	onCreate  func(string)
	deleteErr error
	deletes   int
}

func (s *snapshotStorage) CreateVolumeSnapshot(_ context.Context, tenant, name string) (*SnapshotReference, error) {
	if s.onCreate != nil {
		s.onCreate(name)
	}
	return &SnapshotReference{Namespace: "tenant-" + tenant, Name: name, UID: "uid", StorageClass: "csi", Size: "1Gi"}, nil
}
func (s *snapshotStorage) RestoreVolumeSnapshot(context.Context, string, SnapshotReference) error {
	return nil
}
func (s *snapshotStorage) DeleteVolumeSnapshot(context.Context, string, SnapshotReference) error {
	s.deletes++
	return s.deleteErr
}

func TestSnapshotMetadataFailureDeletesSnapshot(t *testing.T) {
	dir := t.TempDir()
	storage := &snapshotStorage{onCreate: func(id string) {
		if err := os.Mkdir(filepath.Join(dir, id+".meta.json"), 0o700); err != nil {
			t.Fatal(err)
		}
	}}
	mgr := NewManager(nil, nil, dir, WithSnapshots(storage))
	if _, err := mgr.CreateSnapshot(context.Background(), "example"); err == nil {
		t.Fatal("expected metadata failure")
	}
	if storage.deletes != 1 {
		t.Fatal("snapshot not cleaned after metadata failure")
	}
}

func TestSnapshotDeleteFailurePreservesIndexForRetry(t *testing.T) {
	storage := &snapshotStorage{deleteErr: errors.New("storage unavailable")}
	mgr := NewManager(nil, nil, t.TempDir(), WithSnapshots(storage))
	rec, err := mgr.CreateSnapshot(context.Background(), "example")
	if err != nil {
		t.Fatal(err)
	}
	if err = mgr.DeleteContext(context.Background(), rec.ID); err == nil {
		t.Fatal("expected storage failure")
	}
	if _, err = mgr.Get(rec.ID); err != nil {
		t.Fatal("index lost on failed delete:", err)
	}
	storage.deleteErr = nil
	if err = mgr.DeleteContext(context.Background(), rec.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = mgr.Get(rec.ID); err == nil {
		t.Fatal("index remains after successful retry")
	}
}

// TestPrune_SkipsSnapshotRecords pins #3305: prune never deletes a CSI
// snapshot record, and snapshot records do not count toward --keep.
func TestPrune_SkipsSnapshotRecords(t *testing.T) {
	cases := []struct {
		name          string
		snapshots     int
		dumps         int
		keep          int
		wantDeleted   int // dump records pruned
		wantSnapshots int // snapshot records remaining
	}{
		{"snapshots only", 3, 0, 1, 0, 3},
		{"mixed, dumps over keep", 3, 3, 1, 2, 3},
		{"mixed, dumps within keep", 3, 1, 1, 0, 3},
		{"dumps only", 0, 3, 2, 1, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			storage := &snapshotStorage{}
			m := newTestManager(t, newFakeOps([]byte("x")))
			m.snapshots = storage
			m.clock = steppedClock(fixedClock(), time.Second)
			// The snapshot record's Database is the tenant name, which
			// is also a legal database label: the worst case for prune.
			createN(t, m, "alice", "alice", tc.dumps)
			for i := 0; i < tc.snapshots; i++ {
				if _, err := m.CreateSnapshot(context.Background(), "alice"); err != nil {
					t.Fatal(err)
				}
			}
			res, err := m.Prune(PruneOptions{Username: "alice", Keep: tc.keep})
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Deleted) != tc.wantDeleted || len(res.Failures) != 0 {
				t.Fatalf("deleted=%v failures=%v, want %d deleted", res.Deleted, res.Failures, tc.wantDeleted)
			}
			if storage.deletes != 0 {
				t.Fatalf("prune touched %d CSI snapshots", storage.deletes)
			}
			left := 0
			recs, _ := m.List("alice")
			for _, r := range recs {
				if r.Destination == DestSnapshot {
					left++
				}
			}
			if left != tc.wantSnapshots {
				t.Fatalf("snapshot records left = %d, want %d", left, tc.wantSnapshots)
			}
		})
	}
}

// TestDelete_RetentionGuard pins the #3305 seam: every backup record,
// snapshot or dump, goes through one delete guard, and a refusal leaves
// the CSI snapshot, the dump and the index entry untouched.
func TestDelete_RetentionGuard(t *testing.T) {
	guard := func(_ context.Context, r *Record) error {
		if r.Username == "held-tenant" {
			return fmt.Errorf("%w: legal hold", ErrDeleteRefused)
		}
		return nil
	}
	storage := &snapshotStorage{}
	m := newTestManager(t, newFakeOps([]byte("x")))
	m.snapshots = storage
	WithDeleteGuard(guard)(m)

	snapHeld, err := m.CreateSnapshot(context.Background(), "held-tenant")
	if err != nil {
		t.Fatal(err)
	}
	snapFree, err := m.CreateSnapshot(context.Background(), "free-tenant")
	if err != nil {
		t.Fatal(err)
	}
	dumpHeld := createN(t, m, "held-tenant", "app", 1)[0]

	for _, id := range []string{snapHeld.ID, dumpHeld.ID} {
		err := m.DeleteContext(context.Background(), id)
		if !errors.Is(err, ErrDeleteRefused) {
			t.Fatalf("delete %s: err = %v, want ErrDeleteRefused", id, err)
		}
		if _, err := m.Get(id); err != nil {
			t.Fatalf("refused delete removed the index entry for %s", id)
		}
	}
	if storage.deletes != 0 {
		t.Fatalf("refused delete touched the CSI snapshot (%d)", storage.deletes)
	}
	if _, err := os.Stat(dumpHeld.Location); err != nil {
		t.Fatalf("refused delete removed the dump: %v", err)
	}
	if err := m.DeleteContext(context.Background(), snapFree.ID); err != nil || storage.deletes != 1 {
		t.Fatalf("unheld snapshot delete: err=%v deletes=%d", err, storage.deletes)
	}
	// Prune of a held tenant's dump records reports a failure, not a delete.
	m2 := newTestManager(t, newFakeOps([]byte("x")))
	WithDeleteGuard(guard)(m2)
	m2.clock = steppedClock(fixedClock(), time.Second)
	createN(t, m2, "held-tenant", "app", 2)
	res, err := m2.Prune(PruneOptions{Username: "held-tenant", Keep: 1})
	if err != nil || len(res.Deleted) != 0 || len(res.Failures) != 1 {
		t.Fatalf("prune under guard: res=%+v err=%v", res, err)
	}
}
