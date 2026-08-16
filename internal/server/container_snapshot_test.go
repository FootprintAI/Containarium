package server

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/zfscrypt"
	"github.com/footprintai/containarium/pkg/core/zfskey"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Container snapshot lifecycle (#1160, slice a).
//
// The mechanism already exists in pkg/core/zfscrypt and is verified against a
// real pool. What did not exist is any way to REACH it: no RPC, no CLI, so a
// snapshot could only be taken by an operator with a shell on the host. These
// tests pin the daemon-side half — which dataset gets snapshotted, who is
// allowed to ask, and what the caller is told.
//
// The dataset resolution is the part worth testing hardest. An encrypted
// container does not live under the default pool: it lives under its TENANT's
// pool, whose source is the tenant encryptionroot (#1335). Snapshotting the
// name the default pool would produce means snapshotting nothing, or worse,
// another pool's identically-named dataset. See
// docs/architecture/container-snapshots.md.

// snapshotFixture builds a server whose snapshot surface runs against a fake
// `zfs`, with a recorded pool per container so dataset resolution is
// exercised rather than stubbed.
func snapshotFixture(t *testing.T, z *zfsFake, poolOf map[string]string) *ContainerServer {
	t.Helper()
	return &ContainerServer{snapshots: &snapshotOps{
		zfs: zfscrypt.NewManager(z),
		// Stands in for incus.Client.ContainerDataset: the real one reads the
		// pool's source from Incus and appends /containers/<name>. The shape
		// here is that same layout, so a handler that passes the wrong pool
		// produces a visibly wrong dataset instead of the right one.
		datasetFor: func(containerName, pool string) (string, error) {
			if pool == "" {
				pool = "default"
			}
			return "tank/" + pool + "/containers/" + containerName, nil
		},
		poolFor: func(containerName string) (string, error) {
			return poolOf[containerName], nil
		},
	}}
}

func writeCtx(tenant string) context.Context {
	return tenantWithScopes(tenant, auth.ScopeContainersRead, auth.ScopeContainersWrite)
}

// The core of the slice: an encrypted container is snapshotted on ITS pool's
// dataset, not the default pool's.
func TestCreateContainerSnapshot_SnapshotsTheTenantPoolDataset(t *testing.T) {
	z := newZFSFake()
	s := snapshotFixture(t, z, map[string]string{
		"alice-container": "containarium-tenant-alice",
	})

	resp, err := s.CreateContainerSnapshot(writeCtx("alice"),
		&pb.CreateContainerSnapshotRequest{Username: "alice", Name: "nightly"})
	if err != nil {
		t.Fatalf("CreateContainerSnapshot: %v", err)
	}

	const want = "snapshot tank/containarium-tenant-alice/containers/alice-container@nightly"
	if !z.ran(want) {
		t.Fatalf("zfs calls = %v, want %q — an encrypted container lives under its TENANT's pool, "+
			"so resolving through the default pool snapshots a dataset that is not theirs (or "+
			"nothing at all)", z.calls, want)
	}
	if resp.GetSnapshot().GetName() != "nightly" {
		t.Errorf("response names snapshot %q, want nightly", resp.GetSnapshot().GetName())
	}
}

// An unencrypted container has no recorded pool and must still work — the
// overwhelming majority of containers today are in exactly that state.
func TestCreateContainerSnapshot_WorksForAnUnencryptedContainer(t *testing.T) {
	z := newZFSFake()
	s := snapshotFixture(t, z, map[string]string{})

	if _, err := s.CreateContainerSnapshot(writeCtx("bob"),
		&pb.CreateContainerSnapshotRequest{Username: "bob", Name: "before-upgrade"}); err != nil {
		t.Fatalf("CreateContainerSnapshot: %v", err)
	}
	if !z.ran("snapshot tank/default/containers/bob-container@before-upgrade") {
		t.Errorf("zfs calls = %v, want the default pool's dataset", z.calls)
	}
}

// The deliberate one (encryption design, resolved decision #3): a snapshot is
// takeable while the key is unloaded. Blocking on key custody would let a KMS
// outage silently suppress the backup window — the opposite of what a backup
// is for.
//
// The fake reports `zfs get keystatus` as "unavailable" by default, so if the
// handler ever grew a key precondition this test would fail.
func TestCreateContainerSnapshot_SucceedsWithTheKeyUnloaded(t *testing.T) {
	z := newZFSFake()
	z.stdout["get"] = "unavailable"
	s := snapshotFixture(t, z, map[string]string{"alice-container": "containarium-tenant-alice"})

	if _, err := s.CreateContainerSnapshot(writeCtx("alice"),
		&pb.CreateContainerSnapshotRequest{Username: "alice", Name: "nightly"}); err != nil {
		t.Fatalf("a snapshot was refused because the key was unloaded: %v — a key-custody outage "+
			"would then silently stop backups, which is when they matter most", err)
	}
}

func TestCreateContainerSnapshot_ReportsWhatZFSRefused(t *testing.T) {
	z := newZFSFake()
	z.errs["snapshot"] = errors.New("exit status 1")
	z.stderr["snapshot"] = "cannot create snapshot: dataset already exists"
	s := snapshotFixture(t, z, map[string]string{})

	_, err := s.CreateContainerSnapshot(writeCtx("bob"),
		&pb.CreateContainerSnapshotRequest{Username: "bob", Name: "nightly"})
	if err == nil {
		t.Fatal("a failed `zfs snapshot` was reported as success")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("the error drops what ZFS said, so a caller cannot tell a name clash from a "+
			"broken pool: %v", err)
	}
}

// --- listing -------------------------------------------------------------

// Usage is the reason this RPC exists rather than a bare name list: a
// forgotten snapshot pins disk and nothing else in the API reports it.
func TestListContainerSnapshots_CarriesSpaceUsage(t *testing.T) {
	z := newZFSFake()
	delete(z.errs, "list")
	z.stdout["list"] = "tank/containarium-tenant-alice/containers/alice-container@nightly\n" +
		"tank/containarium-tenant-alice/containers/alice-container@weekly"
	z.stdout["get"] = "1024\t65536"
	s := snapshotFixture(t, z, map[string]string{"alice-container": "containarium-tenant-alice"})

	resp, err := s.ListContainerSnapshots(tenantWithScopes("alice", auth.ScopeContainersRead),
		&pb.ListContainerSnapshotsRequest{Username: "alice"})
	if err != nil {
		t.Fatalf("ListContainerSnapshots: %v", err)
	}
	if len(resp.GetSnapshots()) != 2 {
		t.Fatalf("got %d snapshots, want 2", len(resp.GetSnapshots()))
	}

	// Names come back short, not as full dataset@snap references: the caller
	// asked about a container and should not have to parse a dataset path to
	// find the name they passed in.
	if got := resp.Snapshots[0].GetName(); got != "nightly" {
		t.Errorf("name = %q, want the bare snapshot name %q", got, "nightly")
	}
	if resp.Snapshots[0].GetUsedBytes() != 1024 {
		t.Errorf("used_bytes = %d, want 1024 — this is the number that says what deleting the "+
			"snapshot would free, and it is the whole reason to list usage",
			resp.Snapshots[0].GetUsedBytes())
	}
	if resp.Snapshots[0].GetReferencedBytes() != 65536 {
		t.Errorf("referenced_bytes = %d, want 65536", resp.Snapshots[0].GetReferencedBytes())
	}
}

// A container with no snapshots is an empty list, not an error: `zfs list -t
// snapshot` on a dataset with none exits 0 with no output, and a caller
// polling this should not have to distinguish "none yet" from "broken".
func TestListContainerSnapshots_EmptyIsNotAnError(t *testing.T) {
	z := newZFSFake()
	delete(z.errs, "list")
	z.stdout["list"] = ""
	s := snapshotFixture(t, z, map[string]string{})

	resp, err := s.ListContainerSnapshots(tenantWithScopes("bob", auth.ScopeContainersRead),
		&pb.ListContainerSnapshotsRequest{Username: "bob"})
	if err != nil {
		t.Fatalf("listing a container with no snapshots failed: %v", err)
	}
	if len(resp.GetSnapshots()) != 0 {
		t.Errorf("got %d snapshots, want none", len(resp.GetSnapshots()))
	}
}

// A snapshot whose usage cannot be read is still listed. Usage is decoration;
// dropping the row would hide a snapshot that exists, and the operator most
// likely to hit an unreadable property is the one whose pool is already sick.
func TestListContainerSnapshots_ListsASnapshotWhoseUsageIsUnreadable(t *testing.T) {
	z := newZFSFake()
	delete(z.errs, "list")
	z.stdout["list"] = "tank/default/containers/bob-container@nightly"
	z.errs["get"] = errors.New("exit status 1")
	s := snapshotFixture(t, z, map[string]string{})

	resp, err := s.ListContainerSnapshots(tenantWithScopes("bob", auth.ScopeContainersRead),
		&pb.ListContainerSnapshotsRequest{Username: "bob"})
	if err != nil {
		t.Fatalf("ListContainerSnapshots: %v", err)
	}
	if len(resp.GetSnapshots()) != 1 {
		t.Fatalf("got %d snapshots, want the snapshot listed even with unreadable usage — hiding "+
			"it makes a real backup invisible", len(resp.GetSnapshots()))
	}
	if resp.Snapshots[0].GetUsedBytes() != 0 {
		t.Errorf("used_bytes = %d, want 0 when it could not be read",
			resp.Snapshots[0].GetUsedBytes())
	}
}

// --- deletion ------------------------------------------------------------

func TestDeleteContainerSnapshot_DestroysTheTenantPoolSnapshot(t *testing.T) {
	z := newZFSFake()
	delete(z.errs, "list")
	z.stdout["get"] = "4096\t65536"
	s := snapshotFixture(t, z, map[string]string{"alice-container": "containarium-tenant-alice"})

	resp, err := s.DeleteContainerSnapshot(writeCtx("alice"),
		&pb.DeleteContainerSnapshotRequest{Username: "alice", Name: "nightly"})
	if err != nil {
		t.Fatalf("DeleteContainerSnapshot: %v", err)
	}

	const want = "destroy tank/containarium-tenant-alice/containers/alice-container@nightly"
	if !z.ran(want) {
		t.Fatalf("zfs calls = %v, want %q", z.calls, want)
	}
	// Reported BEFORE the destroy, because afterwards there is nothing left to
	// read it from. A zero here means the number was read too late.
	if resp.GetFreedBytes() != 4096 {
		t.Errorf("freed_bytes = %d, want 4096 — read the usage before destroying, or the answer "+
			"is unavailable by the time anyone asks", resp.GetFreedBytes())
	}
}

// Deleting must not require the key either: retention has to keep working
// through a custody outage, or an unreadable key turns into unbounded growth.
func TestDeleteContainerSnapshot_SucceedsWithTheKeyUnloaded(t *testing.T) {
	z := newZFSFake()
	z.stdout["get"] = "unavailable" // not parseable as usage, and not a blocker
	s := snapshotFixture(t, z, map[string]string{"alice-container": "containarium-tenant-alice"})

	if _, err := s.DeleteContainerSnapshot(writeCtx("alice"),
		&pb.DeleteContainerSnapshotRequest{Username: "alice", Name: "nightly"}); err != nil {
		t.Fatalf("deletion was refused with the key unloaded: %v — retention would then stall "+
			"exactly when custody is down", err)
	}
	if !z.ran("destroy") {
		t.Errorf("nothing was destroyed; calls=%v", z.calls)
	}
}

func TestDeleteContainerSnapshot_ReportsAFailedDestroy(t *testing.T) {
	z := newZFSFake()
	z.errs["destroy"] = errors.New("exit status 1")
	z.stderr["destroy"] = "cannot destroy: snapshot has dependent clones"
	s := snapshotFixture(t, z, map[string]string{})

	_, err := s.DeleteContainerSnapshot(writeCtx("bob"),
		&pb.DeleteContainerSnapshotRequest{Username: "bob", Name: "nightly"})
	if err == nil {
		t.Fatal("a failed destroy was reported as a successful deletion — the operator would " +
			"believe they reclaimed space they still hold")
	}
	if !strings.Contains(err.Error(), "dependent clones") {
		t.Errorf("the error drops what ZFS said: %v", err)
	}
}

// --- authorization and validation ---------------------------------------

// Snapshots are a per-container resource, so they inherit the container's
// tenancy: one tenant must not be able to snapshot, list, or destroy
// another's. Each verb is checked, because the gate is written per handler
// and a missing one is invisible from the others.
func TestContainerSnapshots_RefuseAnotherTenantsContainer(t *testing.T) {
	z := newZFSFake()
	delete(z.errs, "list")
	s := snapshotFixture(t, z, map[string]string{})
	mallory := writeCtx("mallory")

	calls := map[string]func() error{
		"create": func() error {
			_, err := s.CreateContainerSnapshot(mallory,
				&pb.CreateContainerSnapshotRequest{Username: "alice", Name: "x"})
			return err
		},
		"list": func() error {
			_, err := s.ListContainerSnapshots(mallory,
				&pb.ListContainerSnapshotsRequest{Username: "alice"})
			return err
		},
		"delete": func() error {
			_, err := s.DeleteContainerSnapshot(mallory,
				&pb.DeleteContainerSnapshotRequest{Username: "alice", Name: "x"})
			return err
		},
	}
	for verb, call := range calls {
		t.Run(verb, func(t *testing.T) {
			if err := call(); err == nil {
				t.Fatalf("%s let mallory operate on alice's container snapshots", verb)
			}
		})
	}
	if z.ran("snapshot") || z.ran("destroy") {
		t.Errorf("a cross-tenant call reached zfs anyway; calls=%v", z.calls)
	}
}

// Reading is not writing: a read-only token can list snapshots but must not
// create or destroy them.
func TestContainerSnapshots_MutationsRequireTheWriteScope(t *testing.T) {
	z := newZFSFake()
	delete(z.errs, "list")
	s := snapshotFixture(t, z, map[string]string{})
	readOnly := tenantWithScopes("bob", auth.ScopeContainersRead)

	if _, err := s.CreateContainerSnapshot(readOnly,
		&pb.CreateContainerSnapshotRequest{Username: "bob", Name: "x"}); err == nil {
		t.Error("a containers:read token created a snapshot")
	}
	if _, err := s.DeleteContainerSnapshot(readOnly,
		&pb.DeleteContainerSnapshotRequest{Username: "bob", Name: "x"}); err == nil {
		t.Error("a containers:read token destroyed a snapshot")
	}
	if _, err := s.ListContainerSnapshots(readOnly,
		&pb.ListContainerSnapshotsRequest{Username: "bob"}); err != nil {
		t.Errorf("a containers:read token could not list snapshots: %v", err)
	}
}

// A name with a '/' or '@' would address a different dataset entirely. The
// rejection lives in zfscrypt, but the handler has to actually route through
// it rather than build the string itself.
func TestCreateContainerSnapshot_RejectsANameThatEscapesTheDataset(t *testing.T) {
	z := newZFSFake()
	s := snapshotFixture(t, z, map[string]string{})

	for _, name := range []string{"../escape", "a@b", "with space", ""} {
		if _, err := s.CreateContainerSnapshot(writeCtx("bob"),
			&pb.CreateContainerSnapshotRequest{Username: "bob", Name: name}); err == nil {
			t.Errorf("snapshot name %q was accepted — it does not name a snapshot of this "+
				"container's dataset", name)
		}
	}
	if z.ran("snapshot") {
		t.Errorf("a rejected name still reached zfs; calls=%v", z.calls)
	}
}

func TestContainerSnapshots_RequireAUsername(t *testing.T) {
	s := snapshotFixture(t, newZFSFake(), map[string]string{})
	if _, err := s.CreateContainerSnapshot(adminCtx(),
		&pb.CreateContainerSnapshotRequest{Name: "x"}); err == nil {
		t.Error("an empty username was accepted for create")
	}
	if _, err := s.ListContainerSnapshots(adminCtx(),
		&pb.ListContainerSnapshotsRequest{}); err == nil {
		t.Error("an empty username was accepted for list")
	}
}

// A daemon whose storage backend is not ZFS has no snapshots to offer, and
// must say so rather than panic on a nil surface.
func TestContainerSnapshots_UnconfiguredSaysSoInsteadOfPanicking(t *testing.T) {
	s := &ContainerServer{}
	_, err := s.CreateContainerSnapshot(writeCtx("bob"),
		&pb.CreateContainerSnapshotRequest{Username: "bob", Name: "x"})
	if err == nil {
		t.Fatal("a daemon with no snapshot support claimed to have taken a snapshot")
	}
	if got := status.Code(err); got != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition", got)
	}
	if _, err := s.ListContainerSnapshots(tenantWithScopes("bob", auth.ScopeContainersRead),
		&pb.ListContainerSnapshotsRequest{Username: "bob"}); err == nil {
		t.Error("listing on an unconfigured daemon claimed success")
	}
}

// The pool a container is recorded on comes from the same store the
// encryption hooks write at create time. If that record is unreadable the
// snapshot must not silently fall back to the default pool — that dataset
// belongs to someone else.
func TestContainerSnapshots_RefuseWhenThePoolRecordIsUnreadable(t *testing.T) {
	z := newZFSFake()
	s := &ContainerServer{snapshots: &snapshotOps{
		zfs: zfscrypt.NewManager(z),
		datasetFor: func(containerName, pool string) (string, error) {
			return "tank/" + pool + "/containers/" + containerName, nil
		},
		poolFor: func(string) (string, error) { return "", errors.New("incus unreachable") },
	}}

	_, err := s.CreateContainerSnapshot(writeCtx("alice"),
		&pb.CreateContainerSnapshotRequest{Username: "alice", Name: "nightly"})
	if err == nil {
		t.Fatal("an unreadable pool record fell through to the default pool — that dataset is " +
			"another tenant's, and snapshotting it is both wrong and a cross-tenant read")
	}
	if z.ran("snapshot") {
		t.Errorf("zfs was called anyway; calls=%v", z.calls)
	}
}

// The wiring: SetSnapshotStorage must reuse the encryption hooks' pool record
// when encryption is configured, or every encrypted container resolves to the
// wrong dataset in production while the unit tests above stay green.
func TestSetSnapshotStorage_ResolvesThePoolThroughTheEncryptionRecord(t *testing.T) {
	z := newZFSFake()
	refs := &fakeRefStore{
		refs:  map[string]zfskey.KeyRef{"alice-container": {Scheme: zfskey.SchemeFile, URI: "/k"}},
		pools: map[string]string{"alice-container": "containarium-tenant-alice"},
	}
	s := &ContainerServer{encryption: testHooksWith(t, newZFSFake(), &fakeKeyProvider{key: aKey(t)}, refs, newFakePools())}
	s.SetSnapshotStorage(zfscrypt.NewManager(z), func(containerName, pool string) (string, error) {
		if pool == "" {
			pool = "default"
		}
		return "tank/" + pool + "/containers/" + containerName, nil
	})

	if _, err := s.CreateContainerSnapshot(writeCtx("alice"),
		&pb.CreateContainerSnapshotRequest{Username: "alice", Name: "nightly"}); err != nil {
		t.Fatalf("CreateContainerSnapshot: %v", err)
	}
	if !z.ran("snapshot tank/containarium-tenant-alice/containers/alice-container@nightly") {
		t.Errorf("zfs calls = %v — the wiring did not consult the encryption record, so every "+
			"encrypted container would be snapshotted on the wrong pool in production", z.calls)
	}
}

// A daemon with encryption unwired must still snapshot, on the default pool.
func TestSetSnapshotStorage_WorksWithoutEncryptionConfigured(t *testing.T) {
	z := newZFSFake()
	s := &ContainerServer{}
	s.SetSnapshotStorage(zfscrypt.NewManager(z), func(containerName, pool string) (string, error) {
		if pool == "" {
			pool = "default"
		}
		return "tank/" + pool + "/containers/" + containerName, nil
	})

	if _, err := s.CreateContainerSnapshot(writeCtx("bob"),
		&pb.CreateContainerSnapshotRequest{Username: "bob", Name: "x"}); err != nil {
		t.Fatalf("CreateContainerSnapshot: %v", err)
	}
	if !z.ran("snapshot tank/default/containers/bob-container@x") {
		t.Errorf("zfs calls = %v, want the default pool's dataset", z.calls)
	}
}
