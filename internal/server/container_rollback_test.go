package server

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/box"
	"github.com/footprintai/containarium/pkg/core/zfscrypt"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Container snapshot rollback (#1160b).
//
// Rollback is destructive twice over: everything written since the snapshot
// is discarded, and any snapshot taken after it has to be destroyed too. So
// nearly all of this file is about what the RPC REFUSES, and each refusal is
// asserted to have also not run the destructive command — a guard that
// returns an error after already rolling back is not a guard.
//
// The third refusal is #1202's second acceptance criterion: rolling back a
// container whose encryption key is unavailable produces a dataset nobody can
// read. `zfscrypt.EnsureInspectable` gives that a specific error instead of
// whatever ZFS says when a read hits an unkeyed dataset, which reads like
// corruption and sends an operator hunting the wrong problem.

// stubBoxes reports a fixed state and records whether Stop was called, so the
// running-container guard can be tested without a container runtime.
type stubBoxes struct {
	box.BoxBackend
	state    pb.ContainerState
	getErr   error
	stopped  []string
	stopErr  error
	stopSeen func()
}

func (s *stubBoxes) Get(_ context.Context, ref box.BoxRef) (*box.BoxStatus, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	return &box.BoxStatus{Ref: ref, State: s.state}, nil
}

func (s *stubBoxes) Stop(_ context.Context, ref box.BoxRef, _ bool) error {
	if s.stopSeen != nil {
		s.stopSeen()
	}
	if s.stopErr != nil {
		return s.stopErr
	}
	s.stopped = append(s.stopped, ref.Tenant)
	return nil
}

// rollbackFixture wires a server whose snapshots run against a fake `zfs` and
// whose box backend reports the given state.
func rollbackFixture(t *testing.T, z *zfsFake, boxes *stubBoxes) *ContainerServer {
	t.Helper()
	return &ContainerServer{
		boxBackend: boxes,
		snapshots: &snapshotOps{
			zfs: zfscrypt.NewManager(z),
			datasetFor: func(containerName, pool string) (string, error) {
				if pool == "" {
					pool = "default"
				}
				return "tank/" + pool + "/containers/" + containerName, nil
			},
		},
	}
}

// keyed makes the fake report a loaded key, so tests about the OTHER guards
// are not silently passing because the key guard fired first.
func keyed(z *zfsFake) *zfsFake {
	z.stdout["get"] = string(zfscrypt.KeyAvailable)
	return z
}

func stoppedBoxes() *stubBoxes {
	return &stubBoxes{state: pb.ContainerState_CONTAINER_STATE_STOPPED}
}

func TestRollbackContainerSnapshot_RollsBackAStoppedContainer(t *testing.T) {
	z := keyed(newZFSFake())
	s := rollbackFixture(t, z, stoppedBoxes())

	resp, err := s.RollbackContainerSnapshot(writeCtx("bob"),
		&pb.RollbackContainerSnapshotRequest{Username: "bob", Name: "nightly"})
	if err != nil {
		t.Fatalf("RollbackContainerSnapshot: %v", err)
	}
	if !z.ran("rollback tank/default/containers/bob-container@nightly") {
		t.Fatalf("zfs calls = %v, want a rollback of the container's dataset", z.calls)
	}
	if resp.GetContainerStopped() {
		t.Error("reported stopping a container that was already stopped")
	}
}

// Guard 1: a running container. ZFS would refuse the busy dataset anyway, but
// "dataset is busy" sends an operator looking for a mount problem instead of
// telling them the one thing they need to do.
func TestRollbackContainerSnapshot_RefusesARunningContainerUnlessForced(t *testing.T) {
	z := keyed(newZFSFake())
	boxes := &stubBoxes{state: pb.ContainerState_CONTAINER_STATE_RUNNING}
	s := rollbackFixture(t, z, boxes)

	_, err := s.RollbackContainerSnapshot(writeCtx("bob"),
		&pb.RollbackContainerSnapshotRequest{Username: "bob", Name: "nightly"})
	if err == nil {
		t.Fatal("rolled back a running container without --force")
	}
	if !strings.Contains(err.Error(), "running") || !strings.Contains(err.Error(), "force") {
		t.Errorf("the refusal does not say what is wrong or how to proceed: %v", err)
	}
	if z.ran("rollback") {
		t.Fatalf("the dataset was rolled back anyway — the guard returned an error AFTER "+
			"destroying data; calls=%v", z.calls)
	}
	if len(boxes.stopped) != 0 {
		t.Errorf("the container was stopped despite the refusal: %v", boxes.stopped)
	}
}

// With force, the daemon stops it first — and must stop it BEFORE rolling
// back, or ZFS refuses the busy dataset and force achieves nothing.
func TestRollbackContainerSnapshot_ForceStopsBeforeRollingBack(t *testing.T) {
	z := keyed(newZFSFake())
	rolledBackFirst := false
	boxes := &stubBoxes{state: pb.ContainerState_CONTAINER_STATE_RUNNING}
	boxes.stopSeen = func() { rolledBackFirst = z.ran("rollback") }
	s := rollbackFixture(t, z, boxes)

	resp, err := s.RollbackContainerSnapshot(writeCtx("bob"),
		&pb.RollbackContainerSnapshotRequest{Username: "bob", Name: "nightly", Force: true})
	if err != nil {
		t.Fatalf("forced rollback: %v", err)
	}
	if len(boxes.stopped) != 1 {
		t.Fatalf("the container was not stopped: %v", boxes.stopped)
	}
	if rolledBackFirst {
		t.Error("the rollback ran BEFORE the stop — ZFS refuses a busy dataset, so force would " +
			"fail on exactly the containers it exists for")
	}
	if !z.ran("rollback") {
		t.Fatalf("nothing was rolled back; calls=%v", z.calls)
	}
	// The caller has to know the container is down: its data just changed
	// underneath, and restarting is their decision, not the daemon's.
	if !resp.GetContainerStopped() {
		t.Error("the response does not report that the container was stopped and left stopped")
	}
}

// A container that cannot be inspected must not be rolled back on the
// assumption that it is stopped. "I could not tell" is not "it is safe".
func TestRollbackContainerSnapshot_RefusesWhenTheStateIsUnknown(t *testing.T) {
	z := keyed(newZFSFake())
	s := rollbackFixture(t, z, &stubBoxes{getErr: errors.New("incus unreachable")})

	if _, err := s.RollbackContainerSnapshot(writeCtx("bob"),
		&pb.RollbackContainerSnapshotRequest{Username: "bob", Name: "nightly"}); err == nil {
		t.Fatal("rolled back a container whose state could not be read")
	}
	if z.ran("rollback") {
		t.Errorf("the dataset was rolled back anyway; calls=%v", z.calls)
	}
}

// Guard 2: newer snapshots. ZFS refuses, and the refusal has to be translated
// — its own message does not say which restore points are at stake or that
// the fix is an explicit flag rather than a retry.
func TestRollbackContainerSnapshot_RefusesToDestroyNewerSnapshots(t *testing.T) {
	z := keyed(newZFSFake())
	z.errs["rollback"] = errors.New("exit status 1")
	z.stderr["rollback"] = "cannot rollback to 'tank/x@nightly': more recent snapshots or bookmarks exist\nuse '-r' to force deletion of the following snapshots and bookmarks:\ntank/x@weekly"
	s := rollbackFixture(t, z, stoppedBoxes())

	_, err := s.RollbackContainerSnapshot(writeCtx("bob"),
		&pb.RollbackContainerSnapshotRequest{Username: "bob", Name: "nightly"})
	if err == nil {
		t.Fatal("a refused rollback was reported as success")
	}
	// The operator needs to know what they would lose and how to say yes.
	for _, want := range []string{"destroy-newer", "weekly"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error is missing %q, so the operator can neither see the cost nor act "+
				"on it: %v", want, err)
		}
	}
	if !strings.Contains(z.calls[len(z.calls)-1], "rollback") || z.ran("rollback -r") {
		t.Errorf("the refused attempt should not have passed -r; calls=%v", z.calls)
	}
}

func TestRollbackContainerSnapshot_DestroyNewerPassesTheFlag(t *testing.T) {
	z := keyed(newZFSFake())
	// The snapshots that will be destroyed, so the response can name them.
	delete(z.errs, "list")
	z.stdout["list"] = "tank/default/containers/bob-container@nightly\n" +
		"tank/default/containers/bob-container@weekly"
	s := rollbackFixture(t, z, stoppedBoxes())

	// The list has to be read BEFORE the rollback: afterwards those snapshots
	// are gone and nothing records which they were. The fake replays a static
	// listing, so only the ORDER can expose a read that came too late.
	listedAfterRollback := false
	z.onCall = func(sub string) {
		if sub == "list" && z.ran("rollback") {
			listedAfterRollback = true
		}
	}

	resp, err := s.RollbackContainerSnapshot(writeCtx("bob"),
		&pb.RollbackContainerSnapshotRequest{Username: "bob", Name: "nightly", DestroyNewer: true})
	if err != nil {
		t.Fatalf("rollback with destroy_newer: %v", err)
	}
	if listedAfterRollback {
		t.Error("the snapshots about to be destroyed were listed AFTER the rollback destroyed " +
			"them — on a real pool that list comes back empty and the operator is told nothing " +
			"about the restore points they just lost")
	}
	if !z.ran("rollback -r tank/default/containers/bob-container@nightly") {
		t.Fatalf("zfs calls = %v, want -r passed", z.calls)
	}
	// Naming them is the point: the operator has just lost restore points and
	// nothing else records which.
	if len(resp.GetDestroyedSnapshots()) != 1 || resp.GetDestroyedSnapshots()[0] != "weekly" {
		t.Errorf("destroyed_snapshots = %v, want [weekly] — the restore points that no longer "+
			"exist are otherwise unrecorded", resp.GetDestroyedSnapshots())
	}
}

// Guard 3 — #1202's second acceptance criterion.
//
// Rolling back a dataset whose key is unavailable leaves the container's data
// as ciphertext nobody can open. ZFS's own error for a read against an unkeyed
// dataset reads like corruption; this one names key custody.
func TestRollbackContainerSnapshot_RefusesWhenTheKeyIsUnavailable(t *testing.T) {
	z := newZFSFake()
	z.stdout["get"] = string(zfscrypt.KeyUnavailable)
	s := rollbackFixture(t, z, stoppedBoxes())

	_, err := s.RollbackContainerSnapshot(writeCtx("alice"),
		&pb.RollbackContainerSnapshotRequest{Username: "alice", Name: "nightly"})
	if err == nil {
		t.Fatal("rolled back to a snapshot whose contents cannot be read — the operator would " +
			"believe they restored data they cannot open")
	}
	if !errors.Is(err, zfscrypt.ErrKeyUnavailableForInspection) &&
		!strings.Contains(err.Error(), "key") {
		t.Errorf("the error does not name key custody, so it reads like corruption and sends the "+
			"operator after the wrong problem: %v", err)
	}
	if got := status.Code(err); got != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition — this is a fixable precondition, not a "+
			"malformed request", got)
	}
	if z.ran("rollback") {
		t.Fatalf("the dataset was rolled back anyway; calls=%v", z.calls)
	}
}

// The key guard must not fire on an UNENCRYPTED container: keystatus is "-"
// for a dataset with no encryption, and treating that as "unavailable" would
// block rollback for essentially every container on the platform.
func TestRollbackContainerSnapshot_AllowsAnUnencryptedContainer(t *testing.T) {
	z := newZFSFake()
	z.stdout["get"] = "-"
	s := rollbackFixture(t, z, stoppedBoxes())

	if _, err := s.RollbackContainerSnapshot(writeCtx("bob"),
		&pb.RollbackContainerSnapshotRequest{Username: "bob", Name: "nightly"}); err != nil {
		t.Fatalf("an unencrypted container was refused: %v — keystatus is \"-\" when there is no "+
			"encryption, and that is not an unavailable key", err)
	}
	if !z.ran("rollback") {
		t.Errorf("nothing was rolled back; calls=%v", z.calls)
	}
}

// --- authorization and validation ---------------------------------------

func TestRollbackContainerSnapshot_RefusesAnotherTenant(t *testing.T) {
	z := keyed(newZFSFake())
	s := rollbackFixture(t, z, stoppedBoxes())

	if _, err := s.RollbackContainerSnapshot(writeCtx("mallory"),
		&pb.RollbackContainerSnapshotRequest{Username: "alice", Name: "x"}); err == nil {
		t.Fatal("mallory rolled back alice's container")
	}
	if z.ran("rollback") {
		t.Errorf("zfs was reached anyway; calls=%v", z.calls)
	}
}

func TestRollbackContainerSnapshot_RequiresTheWriteScope(t *testing.T) {
	z := keyed(newZFSFake())
	s := rollbackFixture(t, z, stoppedBoxes())

	if _, err := s.RollbackContainerSnapshot(
		tenantWithScopes("bob", auth.ScopeContainersRead),
		&pb.RollbackContainerSnapshotRequest{Username: "bob", Name: "x"}); err == nil {
		t.Fatal("a containers:read token performed a destructive rollback")
	}
}

func TestRollbackContainerSnapshot_RequiresASnapshotName(t *testing.T) {
	z := keyed(newZFSFake())
	s := rollbackFixture(t, z, stoppedBoxes())

	_, err := s.RollbackContainerSnapshot(writeCtx("bob"),
		&pb.RollbackContainerSnapshotRequest{Username: "bob"})
	if err == nil {
		t.Fatal("an empty snapshot name was accepted — the reference would be a bare '@'")
	}
	if got := status.Code(err); got != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", got)
	}
}

func TestRollbackContainerSnapshot_UnconfiguredSaysSo(t *testing.T) {
	s := &ContainerServer{}
	_, err := s.RollbackContainerSnapshot(writeCtx("bob"),
		&pb.RollbackContainerSnapshotRequest{Username: "bob", Name: "x"})
	if err == nil {
		t.Fatal("a daemon with no snapshot support claimed to have rolled back")
	}
	if got := status.Code(err); got != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition", got)
	}
}
