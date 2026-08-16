package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/box"
	"github.com/footprintai/containarium/pkg/core/zfscrypt"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Container snapshot rollback (#1160b).
//
// `zfscrypt.RollbackToSnapshot` has existed since #1200 and is verified
// against a real pool. What this adds is the three refusals that make a
// destructive operation safe to expose over an API — and each of them is
// checked BEFORE anything is destroyed, because a guard that reports an
// error after rolling back is not a guard.
//
//  1. A running container. ZFS would refuse the busy dataset anyway, but
//     "dataset is busy" sends an operator looking for a mount problem
//     instead of telling them the one thing to do. With force, the daemon
//     stops it first and leaves it stopped.
//  2. Newer snapshots. Rolling back past them destroys them, which widens
//     the blast radius from "lose writes since the snapshot" to "lose other
//     restore points too". Opt-in, and the response names what went.
//  3. An unavailable encryption key. A rollback whose result cannot be read
//     is not a restore — the operator would believe they recovered data they
//     cannot open. This is #1202's second acceptance criterion.

// RollbackContainerSnapshot returns a container's dataset to the state
// captured by a snapshot. Destructive: everything written since is discarded.
func (s *ContainerServer) RollbackContainerSnapshot(ctx context.Context, req *pb.RollbackContainerSnapshotRequest) (*pb.RollbackContainerSnapshotResponse, error) {
	ops, dataset, err := s.snapshotDatasetFor(ctx, req.GetUsername(), auth.ScopeContainersWrite)
	if err != nil {
		return nil, err
	}
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument,
			"snapshot name is required; without one the reference would be a bare '@'")
	}
	snapshot := dataset + "@" + req.GetName()

	// Guard 3 first, because it is the cheapest and the only one whose remedy
	// lies outside this daemon: if key custody is down, stopping the container
	// to satisfy guard 1 would be work spent on an operation that cannot
	// succeed usefully anyway.
	if err := ops.zfs.EnsureInspectable(ctx, snapshot); err != nil {
		if errors.Is(err, zfscrypt.ErrKeyUnavailableForInspection) {
			return nil, status.Errorf(codes.FailedPrecondition,
				"refusing to roll %s back to %s: %v. The rollback itself would succeed, but the "+
					"result would be ciphertext this daemon cannot open — restore key custody and "+
					"retry, and the snapshot is unharmed in the meantime",
				req.GetUsername(), req.GetName(), err)
		}
		return nil, status.Errorf(codes.FailedPrecondition,
			"cannot determine whether %s can be read back, so refusing to roll it back: %v",
			snapshot, err)
	}

	// Guard 1.
	stopped, err := s.stopForRollback(ctx, req.GetUsername(), req.GetForce())
	if err != nil {
		return nil, err
	}

	// Read the snapshots that a -r rollback would take with it, BEFORE doing
	// it — afterwards they are gone and nothing records which they were.
	var doomed []string
	if req.GetDestroyNewer() {
		doomed = snapshotsAfter(ctx, ops, dataset, req.GetName())
	}

	// Guard 2 is ZFS's own refusal, translated. Its message does not say the
	// fix is an explicit flag rather than a retry.
	if err := ops.zfs.RollbackToSnapshot(ctx, snapshot, req.GetDestroyNewer()); err != nil {
		if errors.Is(err, zfscrypt.ErrNewerSnapshotsExist) {
			return nil, status.Errorf(codes.FailedPrecondition,
				"refusing to roll %s back to %s: snapshots taken after it would have to be "+
					"destroyed. Re-run with --destroy-newer to accept losing them. %v",
				req.GetUsername(), req.GetName(), err)
		}
		return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
	}

	msg := fmt.Sprintf("rolled %s back to snapshot %s; everything written since is gone",
		req.GetUsername(), req.GetName())
	if stopped {
		// Left stopped deliberately: the data underneath just changed, and
		// whether to bring the container up on it is the operator's call.
		msg += ". The container was stopped to do this and has been left stopped"
	}
	if len(doomed) > 0 {
		msg += fmt.Sprintf(". Destroyed %d newer snapshot(s): %s", len(doomed), strings.Join(doomed, ", "))
	}
	log.Printf("[snapshot] rollback %s -> %s (stopped=%v destroyed=%v)",
		req.GetUsername(), snapshot, stopped, doomed)

	return &pb.RollbackContainerSnapshotResponse{
		Message:            msg,
		ContainerStopped:   stopped,
		DestroyedSnapshots: doomed,
	}, nil
}

// stopForRollback enforces guard 1, reporting whether it stopped the
// container.
func (s *ContainerServer) stopForRollback(ctx context.Context, username string, force bool) (bool, error) {
	ref := box.BoxRef{Tenant: username}
	st, err := s.boxes().Get(ctx, ref)
	if err != nil {
		// "I could not tell" is not "it is safe". Rolling back a dataset that
		// might be live is the one outcome this guard exists to prevent.
		return false, status.Errorf(codes.FailedPrecondition,
			"cannot determine whether %s is running, so refusing to roll it back: %v", username, err)
	}
	if st.State != pb.ContainerState_CONTAINER_STATE_RUNNING {
		return false, nil
	}

	if !force {
		return false, status.Errorf(codes.FailedPrecondition,
			"container %s is running; roll back a stopped container, or pass --force to have the "+
				"daemon stop it first. A rollback discards everything written since the snapshot, "+
				"including whatever the running container has in flight", username)
	}

	// Before, not after: ZFS refuses a busy dataset, so a stop that came
	// afterwards would fail on exactly the containers force exists for.
	if err := s.boxes().Stop(ctx, ref, true); err != nil {
		return false, status.Errorf(codes.FailedPrecondition,
			"could not stop %s for the rollback, so nothing was rolled back: %v", username, err)
	}
	return true, nil
}

// snapshotsAfter lists the snapshots that come after target, which a -r
// rollback destroys.
//
// Best-effort: this is for the record an operator reads afterwards, and
// failing to build it is not a reason to refuse a rollback they explicitly
// opted into. ListSnapshots returns oldest-first (`-s creation`), so
// "after" is positional.
func snapshotsAfter(ctx context.Context, ops *snapshotOps, dataset, target string) []string {
	all, err := ops.zfs.ListSnapshots(ctx, dataset)
	if err != nil {
		return nil
	}
	var out []string
	seen := false
	for _, full := range all {
		name := snapshotShortName(full)
		if seen {
			out = append(out, name)
			continue
		}
		if name == target {
			seen = true
		}
	}
	return out
}
