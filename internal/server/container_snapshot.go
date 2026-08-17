package server

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/zfscrypt"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Container snapshots (#1160, slice a: the lifecycle).
//
// The ZFS mechanism has existed in pkg/core/zfscrypt since #1200 and is
// verified against a real pool. What was missing is any way to reach it: no
// RPC and no CLI, so taking a snapshot meant an operator with a shell on the
// host, which is not a feature.
//
// Ownership is settled in docs/architecture/container-snapshots.md: these live
// on ContainerService, not VolumeService, because the subject is a container.
// The dataset is an implementation detail the daemon resolves, and the tenant
// authorization a container RPC already performs is exactly the check a
// snapshot needs.
//
// None of the three verbs requires the encryption key. That is deliberate and
// load-bearing (encryption design, resolved decision #3): ZFS lets a snapshot
// be created and destroyed with the key unloaded, and gating on key-custody
// reachability would turn a KMS outage into a silently missed backup window,
// or into unbounded snapshot growth. Reading a snapshot's CONTENTS does need
// the key — that is what zfscrypt.EnsureInspectable exists for, and it belongs
// with the inspection verbs rather than here.

// incusSnapshotPrefix is the prefix Incus gives the ZFS snapshots backing its
// own instance snapshots (#1390).
//
// Established on the Incus lane rather than read from documentation: an
// `incus snapshot create <c> sync0` produces `<dataset>@snapshot-sync0`. See
// TestIntegrationIncus_TenantSnapshotAPISeesIncusOwnSnapshots, which is what
// catches this if a future Incus changes the convention — it is an
// implementation detail of Incus, not a contract it publishes.
//
// The daemon snapshots two ways on one dataset: `incus snapshot`, which
// MoveContainer uses for its migration sync points, and `zfs snapshot`, this
// API. ZFS lists both, so without this prefix the tenant surface reports
// Incus's snapshots as though a tenant took them, and lets a tenant destroy
// one — during a migration, that is a live sync point, and Incus's database is
// left referencing a snapshot that no longer exists.
const incusSnapshotPrefix = "snapshot-"

// incusManaged reports whether a snapshot name belongs to Incus.
//
// A PREFIX test, deliberately not a substring one: "pre-snapshot-upgrade" is a
// perfectly ordinary name a tenant might choose, and refusing it would be a
// usability regression nobody would connect back to this.
func incusManaged(snapshotName string) bool {
	return strings.HasPrefix(snapshotName, incusSnapshotPrefix)
}

// refuseIncusManaged rejects an operation aimed at one of Incus's snapshots.
//
// Shared by delete and rollback so the two cannot drift: both rewrite or
// remove state Incus believes it owns, and a guard on only one of them is the
// same bug with a smaller blast radius.
func refuseIncusManaged(verb, name string) error {
	if !incusManaged(name) {
		return nil
	}
	return status.Errorf(codes.InvalidArgument,
		"%q is an Incus-managed snapshot, not one of yours — refusing to %s it. Incus records "+
			"these in its own database (migrations use them as sync points), so removing one "+
			"through the storage layer leaves Incus referencing a snapshot that no longer exists. "+
			"Snapshots you created do not carry the %q prefix",
		name, verb, incusSnapshotPrefix)
}

// snapshotOps is the daemon's container-snapshot surface: a zfscrypt manager
// plus the two lookups needed to name the right dataset.
//
// A nil *snapshotOps is a valid receiver meaning "this daemon has no ZFS
// snapshot support", so the handlers answer FailedPrecondition rather than
// panicking on a backend that is not ZFS.
type snapshotOps struct {
	zfs *zfscrypt.Manager

	// datasetFor resolves a container's own dataset on a given pool; "" pool
	// means the daemon's configured one. Bound to incus.Client.ContainerDataset,
	// which reads the pool's source from Incus rather than rebuilding the
	// layout string — that rebuild is what #1336 got wrong.
	datasetFor func(containerName, pool string) (string, error)

	// poolFor reports the storage pool a container was placed on, or "" when
	// it is on the default one. nil when encryption is not configured, in
	// which case every container is on the default pool.
	poolFor func(containerName string) (string, error)
}

// SetSnapshotStorage wires the snapshot surface.
//
// The pool lookup goes through the ENCRYPTION record, not the tenant naming
// convention: an encrypted container lives under its tenant's pool, whose
// source is the tenant encryptionroot (#1335), and the pool it was actually
// placed on is recorded at create time. Recomputing the name instead would
// mean that the day the convention changes, every existing container resolves
// to a dataset that is not theirs — the same reasoning as encryptionRootFor.
func (s *ContainerServer) SetSnapshotStorage(zfs *zfscrypt.Manager, datasetFor func(containerName, pool string) (string, error)) {
	if zfs == nil || datasetFor == nil {
		return
	}
	ops := &snapshotOps{zfs: zfs, datasetFor: datasetFor}
	if h := s.encryption; h.enabled() {
		ops.poolFor = h.refs.GetPool
	}
	s.snapshots = ops
}

// datasetOf resolves the dataset backing a container, honouring the pool it
// was placed on.
func (o *snapshotOps) datasetOf(containerName string) (string, error) {
	pool := ""
	if o.poolFor != nil {
		var err error
		if pool, err = o.poolFor(containerName); err != nil {
			// Never fall back to the default pool here. The container may well
			// be encrypted and living elsewhere, and the default pool's
			// dataset of the same name is another tenant's storage — reading
			// or destroying it would be both wrong and a tenancy violation.
			return "", fmt.Errorf(
				"cannot determine which storage pool %s is on, so its dataset cannot be named "+
					"safely: %w", containerName, err)
		}
	}
	return o.datasetFor(containerName, pool)
}

// snapshotDatasetFor is the shared preamble: authorize the caller for this
// container and resolve the dataset to operate on.
func (s *ContainerServer) snapshotDatasetFor(ctx context.Context, username, scope string) (*snapshotOps, string, error) {
	if username == "" {
		return nil, "", status.Error(codes.InvalidArgument, "username is required")
	}
	if err := auth.RequireScope(ctx, scope); err != nil {
		return nil, "", err
	}
	if err := auth.AuthorizeTenant(ctx, username); err != nil {
		return nil, "", err
	}
	if s.snapshots == nil {
		return nil, "", status.Error(codes.FailedPrecondition,
			"container snapshots need a ZFS storage backend, which this daemon is not configured with")
	}

	containerName := username + "-container"
	dataset, err := s.snapshots.datasetOf(containerName)
	if err != nil {
		return nil, "", status.Errorf(codes.FailedPrecondition, "%v", err)
	}
	return s.snapshots, dataset, nil
}

// CreateContainerSnapshot takes a point-in-time snapshot of a container's
// dataset. Instant and space-efficient — it shares blocks with the live
// dataset until they diverge — and safe to take while the container runs.
func (s *ContainerServer) CreateContainerSnapshot(ctx context.Context, req *pb.CreateContainerSnapshotRequest) (*pb.CreateContainerSnapshotResponse, error) {
	ops, dataset, err := s.snapshotDatasetFor(ctx, req.GetUsername(), auth.ScopeContainersWrite)
	if err != nil {
		return nil, err
	}

	// Incus's namespace is reserved (#1390). Without this, a tenant snapshot
	// called "snapshot-foo" lands on the same ZFS name as Incus's snapshot
	// "foo" — and at best is created and then hidden by the listing filter,
	// which is worse than refusing it: the caller is told it exists and can
	// never see it again.
	if incusManaged(req.GetName()) {
		return nil, status.Errorf(codes.InvalidArgument,
			"snapshot names beginning with %q are reserved for Incus's own snapshots (#1390); "+
				"choose another name", incusSnapshotPrefix)
	}

	// The rest of name validation lives in zfscrypt, which rejects anything
	// containing '@', '/' or whitespace. Routing through it rather than
	// concatenating here is the point: a name like "../other" would otherwise
	// address a different dataset entirely.
	full, err := ops.zfs.Snapshot(ctx, dataset, req.GetName())
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
	}

	snap := &pb.ContainerSnapshot{Name: req.GetName()}
	// Usage right after creation is ~0 (everything is still shared with the
	// live dataset), but reading it costs one cheap call and makes the
	// response the same shape as a list entry.
	if used, referenced, err := ops.zfs.SnapshotUsage(ctx, full); err == nil {
		snap.UsedBytes, snap.ReferencedBytes = used, referenced
	}

	return &pb.CreateContainerSnapshotResponse{
		Snapshot: snap,
		Message: fmt.Sprintf("created snapshot %s. It is not a backup until it is copied off this "+
			"host — it shares blocks with the live dataset and dies with the pool", full),
	}, nil
}

// ListContainerSnapshots lists a container's snapshots with their space usage.
//
// The usage is the reason this is not a bare name list: a forgotten snapshot
// pins disk that nothing else in the API accounts for, and the first sign is
// usually a full pool.
func (s *ContainerServer) ListContainerSnapshots(ctx context.Context, req *pb.ListContainerSnapshotsRequest) (*pb.ListContainerSnapshotsResponse, error) {
	ops, dataset, err := s.snapshotDatasetFor(ctx, req.GetUsername(), auth.ScopeContainersRead)
	if err != nil {
		return nil, err
	}

	names, err := ops.zfs.ListSnapshots(ctx, dataset)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
	}

	out := make([]*pb.ContainerSnapshot, 0, len(names))
	for _, full := range names {
		short := snapshotShortName(full)
		// Incus's own snapshots are not the tenant's to see (#1390). They are
		// listed by ZFS because both mechanisms write to one dataset, but a
		// migration's sync points are not something a tenant took, and a row
		// they do not recognise is a row they may delete.
		if incusManaged(short) {
			continue
		}
		snap := &pb.ContainerSnapshot{Name: short}
		// Usage is decoration. A snapshot whose properties cannot be read is
		// still listed with zeroes: dropping the row would hide a snapshot
		// that exists, and an unreadable property is most likely on a pool
		// that is already in trouble.
		if used, referenced, err := ops.zfs.SnapshotUsage(ctx, full); err == nil {
			snap.UsedBytes, snap.ReferencedBytes = used, referenced
		}
		out = append(out, snap)
	}
	return &pb.ListContainerSnapshotsResponse{Snapshots: out}, nil
}

// DeleteContainerSnapshot removes a snapshot and reports what it freed.
func (s *ContainerServer) DeleteContainerSnapshot(ctx context.Context, req *pb.DeleteContainerSnapshotRequest) (*pb.DeleteContainerSnapshotResponse, error) {
	ops, dataset, err := s.snapshotDatasetFor(ctx, req.GetUsername(), auth.ScopeContainersWrite)
	if err != nil {
		return nil, err
	}
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "snapshot name is required")
	}
	if err := refuseIncusManaged("delete", req.GetName()); err != nil {
		return nil, err
	}
	full := dataset + "@" + req.GetName()

	// Read the usage BEFORE destroying: afterwards there is nothing left to
	// read it from, and "how much did that free?" is the question an operator
	// deleting a snapshot is actually asking. Best-effort — an unreadable
	// property is not a reason to refuse a deletion, particularly since the
	// most likely cause is a pool short on space.
	freed, _, usageErr := ops.zfs.SnapshotUsage(ctx, full)
	if usageErr != nil {
		freed = 0
	}

	if err := ops.zfs.DestroySnapshot(ctx, full); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
	}

	msg := fmt.Sprintf("destroyed snapshot %s, freeing %d bytes", full, freed)
	if usageErr != nil {
		msg = fmt.Sprintf("destroyed snapshot %s; how much it freed could not be read beforehand", full)
	}
	return &pb.DeleteContainerSnapshotResponse{Message: msg, FreedBytes: freed}, nil
}

// snapshotShortName reduces "<dataset>@<name>" to "<name>".
//
// Callers asked about a container, so they get back the name they passed in
// rather than a dataset path they would have to parse — and the dataset half
// is a detail of the storage layout that no client should start depending on.
func snapshotShortName(full string) string {
	if _, name, ok := strings.Cut(full, "@"); ok {
		return name
	}
	return full
}
