package backup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
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
