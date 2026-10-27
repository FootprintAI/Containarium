package backup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
)

// SnapshotReference identifies a CSI snapshot independently of a daemon restart.
// UID prevents accidentally using a replacement object with the same name.
type SnapshotReference struct {
	Namespace    string `json:"namespace"`
	Name         string `json:"name"`
	UID          string `json:"uid"`
	StorageClass string `json:"storage_class"`
	Size         string `json:"size"`
}

// SnapshotOps is an optional Kubernetes storage capability. It does not export
// archive bytes and therefore does not participate in age encryption or hashes.
type SnapshotOps interface {
	CreateVolumeSnapshot(context.Context, string, string) (*SnapshotReference, error)
	RestoreVolumeSnapshot(context.Context, string, SnapshotReference) error
	DeleteVolumeSnapshot(context.Context, string, SnapshotReference) error
}

func WithSnapshots(ops SnapshotOps) Option { return func(m *Manager) { m.snapshots = ops } }

func (m *Manager) CreateSnapshot(ctx context.Context, tenant string) (*Record, error) {
	if m.snapshots == nil {
		return nil, fmt.Errorf("CSI snapshots are unavailable on this backend")
	}
	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		return nil, err
	}
	id := "snapshot-" + uuid.NewString()
	ref, err := m.snapshots.CreateVolumeSnapshot(ctx, tenant, id)
	if err != nil {
		return nil, err
	}
	rec := &Record{ID: id, Username: tenant, Database: tenant, CreatedAt: m.now(), Destination: DestSnapshot, Engine: EngineBox, Snapshot: ref, Location: "snapshot://" + ref.Namespace + "/" + ref.Name}
	if err := m.writeSidecar(rec); err != nil {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		return nil, errors.Join(err, m.snapshots.DeleteVolumeSnapshot(cleanup, tenant, *ref))
	}
	return rec, nil
}

func (m *Manager) RestoreSnapshot(ctx context.Context, rec *Record) error {
	if m.snapshots == nil || rec.Snapshot == nil {
		return fmt.Errorf("snapshot backend or metadata unavailable")
	}
	return m.snapshots.RestoreVolumeSnapshot(ctx, rec.Username, *rec.Snapshot)
}
