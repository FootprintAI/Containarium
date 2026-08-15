package server

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/footprintai/containarium/pkg/core/zfskey"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Placement for a migrated encrypted container (#1203b, the half #1360 left).
//
// #1360 made the destination provision the tenant's pool and hand back its
// name. Nothing consumed it: `incus copy` still ran with no `--storage`, so
// the container landed on the destination's DEFAULT pool — outside the
// tenant's encryptionroot, unencrypted — while the pre-flight had just said
// the migration was safe. That combination is worse than no pre-flight at
// all, because the reassuring signal is the false one.
//
// These tests pin the copy going where the pre-flight said, and the
// destination recording enough to unlock it again afterwards.

// preflightOK installs a destination that accepts and names a pool.
func preflightOK(t *testing.T, pool string) {
	t.Helper()
	prev := overridePrepareForTest(func(*PeerClient, string, *pb.PrepareEncryptedMigrationRequest) (*pb.PrepareEncryptedMigrationResponse, error) {
		return &pb.PrepareEncryptedMigrationResponse{CanResolve: true, StoragePool: pool}, nil
	})
	t.Cleanup(prev)
}

// Every copy in the migration must target the tenant pool — not just the
// first. The final cutover copy is the one that carries the last delta, so a
// copy that forgot the pool there would leave the container's freshest state
// on the wrong dataset.
func TestMoveContainer_EveryCopyTargetsTheTenantPool(t *testing.T) {
	runner := &fakeRunner{hasRemote: true}
	cs := encryptedServer(t, runner)
	preflightOK(t, "containarium-tenant-alice")

	var adopted *pb.AdoptMigratedContainerRequest
	prev := overrideAdoptForTest(func(_ *PeerClient, _ string, req *pb.AdoptMigratedContainerRequest) (*pb.AdoptMigratedContainerResponse, error) {
		adopted = req
		return &pb.AdoptMigratedContainerResponse{NewIpAddress: "10.0.7.42"}, nil
	})
	defer prev()

	if _, err := cs.MoveContainer(adminCtx(), &pb.MoveContainerRequest{
		Username: "alice", TargetBackendId: "vm2",
	}); err != nil {
		t.Fatalf("MoveContainer: %v", err)
	}

	copies := 0
	for _, call := range runner.calls {
		if !strings.HasPrefix(call, "copyinit ") && !strings.HasPrefix(call, "refresh ") {
			continue
		}
		copies++
		if !strings.Contains(call, "storage=containarium-tenant-alice") {
			t.Errorf("copy %q did not target the tenant pool — the container lands on the "+
				"destination's default pool, outside its encryptionroot, and arrives unencrypted "+
				"while the pre-flight said the migration was safe", call)
		}
	}
	if copies == 0 {
		t.Fatal("no copies happened at all")
	}

	// And the destination must be told what it received, or it cannot
	// unlock the container on any later start.
	if adopted == nil {
		t.Fatal("adopt was never called")
	}
	if adopted.ZfsPool != "containarium-tenant-alice" {
		t.Errorf("adopt request pool = %q, want the tenant pool", adopted.ZfsPool)
	}
	var ref zfskey.KeyRef
	if err := json.Unmarshal([]byte(adopted.ZfsKeyRef), &ref); err != nil {
		t.Fatalf("adopt request carries no decodable key ref: %v", err)
	}
	if ref.URI != "/keys/alice.key" {
		t.Errorf("adopt ref = %+v, want alice's", ref)
	}
}

// The unencrypted path must be byte-identical: no --storage, no placement
// fields. Every container today takes this path.
func TestMoveContainer_UnencryptedCopiesCarryNoStorageOverride(t *testing.T) {
	runner := &fakeRunner{hasRemote: true}
	cs := newTestContainerServer(t, runner, "vm2")

	var adopted *pb.AdoptMigratedContainerRequest
	prev := overrideAdoptForTest(func(_ *PeerClient, _ string, req *pb.AdoptMigratedContainerRequest) (*pb.AdoptMigratedContainerResponse, error) {
		adopted = req
		return &pb.AdoptMigratedContainerResponse{NewIpAddress: "10.0.7.42"}, nil
	})
	defer prev()

	if _, err := cs.MoveContainer(adminCtx(), &pb.MoveContainerRequest{
		Username: "bob", TargetBackendId: "vm2",
	}); err != nil {
		t.Fatalf("MoveContainer: %v", err)
	}

	for _, call := range runner.calls {
		if strings.Contains(call, "storage=") {
			t.Errorf("an unencrypted migration passed a storage override (%q) — it would be "+
				"pinned to a pool it never asked for", call)
		}
	}
	if adopted == nil {
		t.Fatal("adopt was never called")
	}
	if adopted.ZfsKeyRef != "" || adopted.ZfsPool != "" {
		t.Errorf("an unencrypted adopt carried placement fields: ref=%q pool=%q",
			adopted.ZfsKeyRef, adopted.ZfsPool)
	}
}

// --- destination side --------------------------------------------------

// The destination records what it was told, so a restarted daemon — or any
// later start — can find the encryptionroot. Without this the container is
// running but unopenable the moment it stops.
func TestAdoptMigratedContainer_RecordsThePlacementItWasGiven(t *testing.T) {
	z, p := newZFSFake(), &fakeKeyProvider{key: aKey(t)}
	refs := &fakeRefStore{refs: map[string]zfskey.KeyRef{}, pools: map[string]string{}}
	s := &ContainerServer{encryption: testHooksWith(t, z, p, refs, newFakePools())}

	err := s.recordAdoptedPlacement(&pb.AdoptMigratedContainerRequest{
		Username:  "alice",
		ZfsKeyRef: refJSON(t, "/keys/alice.key"),
		ZfsPool:   "containarium-tenant-alice",
	})
	if err != nil {
		t.Fatalf("recordAdoptedPlacement: %v", err)
	}

	if got := refs.refs["alice-container"]; got.URI != "/keys/alice.key" {
		t.Errorf("stored ref = %+v, want alice's", got)
	}
	if got := refs.pools["alice-container"]; got != "containarium-tenant-alice" {
		t.Errorf("stored pool = %q, want the tenant pool", got)
	}
}

// An unencrypted adoption must not touch encryption state at all.
func TestAdoptMigratedContainer_UnencryptedRecordsNothing(t *testing.T) {
	z, p := newZFSFake(), &fakeKeyProvider{key: aKey(t)}
	refs := &fakeRefStore{refs: map[string]zfskey.KeyRef{}, pools: map[string]string{}}
	s := &ContainerServer{encryption: testHooksWith(t, z, p, refs, newFakePools())}

	if err := s.recordAdoptedPlacement(&pb.AdoptMigratedContainerRequest{Username: "bob"}); err != nil {
		t.Fatalf("recordAdoptedPlacement: %v", err)
	}
	if len(refs.refs) != 0 || len(refs.pools) != 0 {
		t.Errorf("an unencrypted adoption recorded encryption state: refs=%v pools=%v",
			refs.refs, refs.pools)
	}
}

// A ref that arrives without a pool (or the reverse) is a half-message. It
// must fail rather than be recorded, because a container with a ref and no
// pool refuses to start — and one with a pool and no ref reads as
// unencrypted, which is the dangerous direction.
//
// NOTE, so this is not mistaken for a unit test of the explicit check in
// recordAdoptedPlacement: it is not. Deleting that check leaves this test
// passing, because both halves are refused anyway — a missing pool by
// RecordPlacement (#1340), a missing ref by the JSON decode. What is asserted
// here is the GUARANTEE, which is upheld by three independent mechanisms. The
// explicit check earns its place only by naming which half is missing, which
// the other two cannot.
func TestAdoptMigratedContainer_RejectsAHalfMessage(t *testing.T) {
	for _, tc := range []struct{ name, ref, pool string }{
		{"ref without pool", `{"scheme":"file","uri":"/k"}`, ""},
		{"pool without ref", "", "containarium-tenant-alice"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			z, p := newZFSFake(), &fakeKeyProvider{key: aKey(t)}
			refs := &fakeRefStore{refs: map[string]zfskey.KeyRef{}, pools: map[string]string{}}
			s := &ContainerServer{encryption: testHooksWith(t, z, p, refs, newFakePools())}

			err := s.recordAdoptedPlacement(&pb.AdoptMigratedContainerRequest{
				Username: "alice", ZfsKeyRef: tc.ref, ZfsPool: tc.pool,
			})
			if err == nil {
				t.Fatal("a half-specified placement was accepted")
			}
			if len(refs.refs) != 0 || len(refs.pools) != 0 {
				t.Errorf("state was recorded anyway: refs=%v pools=%v", refs.refs, refs.pools)
			}
		})
	}
}

// A destination with no encryption wired that is handed an encrypted
// container must refuse loudly. The pre-flight should have stopped this, so
// reaching here means the source skipped it or the daemon changed underneath
// — either way, recording nothing and reporting success would leave a
// container nobody can unlock.
func TestAdoptMigratedContainer_RefusesEncryptedWithoutEncryptionWired(t *testing.T) {
	s := &ContainerServer{} // no hooks

	err := s.recordAdoptedPlacement(&pb.AdoptMigratedContainerRequest{
		Username:  "alice",
		ZfsKeyRef: refJSON(t, "/keys/alice.key"),
		ZfsPool:   "containarium-tenant-alice",
	})
	if err == nil {
		t.Fatal("a daemon with no key custody accepted an encrypted container — it would run " +
			"until its first stop and then never start again, with nothing recording why")
	}
}
