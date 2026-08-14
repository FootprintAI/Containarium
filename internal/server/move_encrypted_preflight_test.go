package server

import (
	"encoding/json"
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

// Migration pre-flight for encrypted containers (#1360, from #1203).
//
// The check exists because the alternative is discovering at the END of a
// migration that the destination cannot unlock what it just received: a full
// data copy spent, and an unstartable container shell left on the far side.
//
// It also provisions the destination's tenant storage, because the copy has
// to land inside that tenant's encryptionroot and only the destination can
// create it. One call, two answers, both needed at the same moment.

// --- source side -------------------------------------------------------

// prepareRecorder captures what the source sent to the destination.
type prepareRecorder struct {
	calls []*pb.PrepareEncryptedMigrationRequest
	resp  *pb.PrepareEncryptedMigrationResponse
	err   error
}

func (p *prepareRecorder) install(t *testing.T) {
	t.Helper()
	prev := overridePrepareForTest(func(_ *PeerClient, _ string, req *pb.PrepareEncryptedMigrationRequest) (*pb.PrepareEncryptedMigrationResponse, error) {
		p.calls = append(p.calls, req)
		if p.err != nil {
			return nil, p.err
		}
		return p.resp, nil
	})
	t.Cleanup(prev)
}

// encryptedServer wires a move-capable server whose container is recorded as
// encrypted, the way a create through #1341's path leaves it.
func encryptedServer(t *testing.T, runner *fakeRunner) *ContainerServer {
	t.Helper()
	cs := newTestContainerServer(t, runner, "vm2")
	cs.encryption = &encryptionHooks{
		provider: &fakeKeyProvider{key: aKey(t)},
		// A real manager over a fake runner. The source only READS the stored
		// ref, so nothing here is invoked — but enabled() requires it, and a
		// nil would make every container read as unencrypted, which is
		// exactly the silent failure this whole feature guards against.
		zfs: zfscrypt.NewManager(newZFSFake()),
		refs: &fakeRefStore{
			refs: map[string]zfskey.KeyRef{
				"alice-container": {Scheme: zfskey.SchemeFile, URI: "/keys/alice.key",
					Metadata: map[string]string{"tenant": "alice"}},
			},
			pools: map[string]string{"alice-container": "containarium-tenant-alice"},
		},
		pools:      newFakePools(),
		tenantRoot: "tank/tenants",
	}
	return cs
}

// The acceptance criterion: a destination that cannot resolve the ref fails
// the pre-flight BEFORE any data is copied. "Before" is the whole value —
// a check that runs after the copy is just a nicer error message on a
// migration that already cost the transfer.
func TestMoveContainer_AbortsBeforeCopyingWhenTheDestinationCannotResolveTheKey(t *testing.T) {
	runner := &fakeRunner{hasRemote: true}
	cs := encryptedServer(t, runner)
	rec := &prepareRecorder{resp: &pb.PrepareEncryptedMigrationResponse{
		CanResolve: false,
		Reason:     "no key custody configured on this daemon",
	}}
	rec.install(t)

	_, err := cs.MoveContainer(adminCtx(), &pb.MoveContainerRequest{
		Username: "alice", TargetBackendId: "vm2",
	})
	if err == nil {
		t.Fatal("the migration proceeded although the destination cannot unlock the container — " +
			"it would arrive as an unstartable shell after a full data copy")
	}
	if got := status.Code(err); got != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition", got)
	}
	// The operator has to learn WHY from the destination, not just "it failed".
	if !strings.Contains(err.Error(), "no key custody configured") {
		t.Errorf("the destination's reason did not survive to the caller: %v", err)
	}

	// Nothing may have been touched. This is the assertion that makes the
	// check worth having.
	for _, call := range runner.calls {
		t.Errorf("the runner was invoked (%q) despite a failed pre-flight — the point of the "+
			"check is that a doomed migration costs nothing", call)
	}
}

func TestMoveContainer_PreflightRunsBeforeTheFirstSnapshot(t *testing.T) {
	runner := &fakeRunner{hasRemote: true}
	cs := encryptedServer(t, runner)
	rec := &prepareRecorder{resp: &pb.PrepareEncryptedMigrationResponse{
		CanResolve: true, StoragePool: "containarium-tenant-alice",
	}}
	rec.install(t)

	prev := overrideAdoptForTest(func(*PeerClient, string, *pb.AdoptMigratedContainerRequest) (*pb.AdoptMigratedContainerResponse, error) {
		return &pb.AdoptMigratedContainerResponse{NewIpAddress: "10.0.7.42"}, nil
	})
	defer prev()

	if _, err := cs.MoveContainer(adminCtx(), &pb.MoveContainerRequest{
		Username: "alice", TargetBackendId: "vm2",
	}); err != nil {
		t.Fatalf("MoveContainer: %v", err)
	}

	if len(rec.calls) != 1 {
		t.Fatalf("pre-flight called %d times, want exactly 1", len(rec.calls))
	}
	if len(runner.calls) == 0 {
		t.Fatal("the migration did no work at all")
	}
	// The recorder appends on call; the runner appends on each incus
	// operation. The pre-flight having happened at all, with the runner's
	// first call being a snapshot, is the ordering under test.
	if first := runner.calls[0]; !strings.HasPrefix(first, "snapshot ") {
		t.Errorf("first runner call = %q, want a snapshot — the pre-flight should precede it", first)
	}
}

// #1203 AC3: only the reference crosses the wire.
//
// A KeyRef is scheme + URI + metadata. If key BYTES ever reached this
// message, they would travel between daemons and sit in whatever logs the
// transport keeps — the one thing the design forbids outright.
func TestMoveContainer_PreflightSendsTheRefAndNeverKeyMaterial(t *testing.T) {
	runner := &fakeRunner{hasRemote: true}
	cs := encryptedServer(t, runner)
	rec := &prepareRecorder{resp: &pb.PrepareEncryptedMigrationResponse{
		CanResolve: true, StoragePool: "containarium-tenant-alice",
	}}
	rec.install(t)

	prev := overrideAdoptForTest(func(*PeerClient, string, *pb.AdoptMigratedContainerRequest) (*pb.AdoptMigratedContainerResponse, error) {
		return &pb.AdoptMigratedContainerResponse{NewIpAddress: "10.0.7.42"}, nil
	})
	defer prev()

	if _, err := cs.MoveContainer(adminCtx(), &pb.MoveContainerRequest{
		Username: "alice", TargetBackendId: "vm2",
	}); err != nil {
		t.Fatalf("MoveContainer: %v", err)
	}
	if len(rec.calls) != 1 {
		t.Fatalf("pre-flight called %d times, want 1", len(rec.calls))
	}
	sent := rec.calls[0]

	if sent.Tenant != "alice" {
		t.Errorf("tenant = %q, want %q — the destination provisions per tenant, not per container",
			sent.Tenant, "alice")
	}

	var ref zfskey.KeyRef
	if err := json.Unmarshal([]byte(sent.KeyRef), &ref); err != nil {
		t.Fatalf("the key_ref field is not a decodable KeyRef: %v", err)
	}
	if ref.URI != "/keys/alice.key" || ref.Scheme != zfskey.SchemeFile {
		t.Errorf("ref did not survive the wire: %+v", ref)
	}

	// The key this tenant actually holds, verbatim, must not appear
	// anywhere in the request — not in the ref, not in a stray field.
	keyBytes := aKey(t).Bytes()
	if strings.Contains(sent.String(), string(keyBytes)) {
		t.Error("key MATERIAL is present in the pre-flight request — only the reference may travel")
	}
}

// An unencrypted migration must be untouched: no extra round trip, no new
// failure mode. Every container today is unencrypted.
func TestMoveContainer_UnencryptedMigrationMakesNoPreflightCall(t *testing.T) {
	runner := &fakeRunner{hasRemote: true}
	cs := newTestContainerServer(t, runner, "vm2") // no encryption hooks at all
	rec := &prepareRecorder{resp: &pb.PrepareEncryptedMigrationResponse{CanResolve: false}}
	rec.install(t)

	prev := overrideAdoptForTest(func(*PeerClient, string, *pb.AdoptMigratedContainerRequest) (*pb.AdoptMigratedContainerResponse, error) {
		return &pb.AdoptMigratedContainerResponse{NewIpAddress: "10.0.7.42"}, nil
	})
	defer prev()

	if _, err := cs.MoveContainer(adminCtx(), &pb.MoveContainerRequest{
		Username: "bob", TargetBackendId: "vm2",
	}); err != nil {
		t.Fatalf("an unencrypted migration failed: %v", err)
	}
	if len(rec.calls) != 0 {
		t.Errorf("an unencrypted migration made %d pre-flight call(s) — the destination would be "+
			"asked to resolve a ref that does not exist, and a `CanResolve:false` answer would "+
			"break a migration that has nothing to do with encryption", len(rec.calls))
	}
}

// --- destination side --------------------------------------------------

func TestPrepareEncryptedMigration_ResolvesTheRefAndProvisionsTheTenantPool(t *testing.T) {
	z, p := newZFSFake(), &fakeKeyProvider{key: aKey(t)}
	pools := newFakePools()
	s := &ContainerServer{encryption: testHooksWith(t, z, p,
		&fakeRefStore{refs: map[string]zfskey.KeyRef{}}, pools)}

	resp, err := s.PrepareEncryptedMigration(adminCtx(), &pb.PrepareEncryptedMigrationRequest{
		Username: "alice", Tenant: "alice", KeyRef: refJSON(t, "/keys/alice.key"),
	})
	if err != nil {
		t.Fatalf("PrepareEncryptedMigration: %v", err)
	}
	if !resp.CanResolve {
		t.Fatalf("a destination with working key custody refused: %s", resp.Reason)
	}
	if resp.StoragePool == "" {
		t.Error("no storage pool returned — the source has nowhere correct to copy into, and the " +
			"container would land on the destination's default pool, unencrypted")
	}
	if len(pools.created) != 1 {
		t.Errorf("the tenant pool was created %d times, want 1", len(pools.created))
	}
}

// A destination with no key custody must answer plainly, not error. The
// source needs the REASON to put in front of an operator.
func TestPrepareEncryptedMigration_RefusesWithoutKeyCustody(t *testing.T) {
	s := &ContainerServer{} // no encryption wired

	resp, err := s.PrepareEncryptedMigration(adminCtx(), &pb.PrepareEncryptedMigrationRequest{
		Username: "alice", Tenant: "alice", KeyRef: refJSON(t, "/keys/alice.key"),
	})
	if err != nil {
		t.Fatalf("a destination without custody returned a transport error rather than an "+
			"answer: %v", err)
	}
	if resp.CanResolve {
		t.Fatal("a destination with no key custody claimed it could resolve the ref — the " +
			"migration would proceed and the container would arrive unopenable")
	}
	if resp.Reason == "" {
		t.Error("refused with no reason; the operator cannot tell this from any other failure")
	}
}

// Custody configured but this particular ref unresolvable — a tenant the
// destination has never heard of, or a key it cannot reach.
func TestPrepareEncryptedMigration_RefusesAnUnresolvableRef(t *testing.T) {
	z := newZFSFake()
	p := &fakeKeyProvider{key: aKey(t), loadErr: errors.New("no such key for tenant")}
	pools := newFakePools()
	s := &ContainerServer{encryption: testHooksWith(t, z, p,
		&fakeRefStore{refs: map[string]zfskey.KeyRef{}}, pools)}

	resp, err := s.PrepareEncryptedMigration(adminCtx(), &pb.PrepareEncryptedMigrationRequest{
		Username: "alice", Tenant: "alice", KeyRef: refJSON(t, "/keys/alice.key"),
	})
	if err != nil {
		t.Fatalf("PrepareEncryptedMigration: %v", err)
	}
	if resp.CanResolve {
		t.Fatal("claimed it could resolve a ref its own provider rejected")
	}
	if !strings.Contains(resp.Reason, "no such key") {
		t.Errorf("the provider's reason did not reach the response: %q", resp.Reason)
	}
	// And nothing may have been provisioned for a tenant we cannot serve.
	if len(pools.created) != 0 {
		t.Errorf("a tenant pool was created for an unresolvable ref: %v", pools.created)
	}
}

func TestPrepareEncryptedMigration_RejectsAMalformedRef(t *testing.T) {
	z, p := newZFSFake(), &fakeKeyProvider{key: aKey(t)}
	s := &ContainerServer{encryption: testHooksWith(t, z, p,
		&fakeRefStore{refs: map[string]zfskey.KeyRef{}}, newFakePools())}

	_, err := s.PrepareEncryptedMigration(adminCtx(), &pb.PrepareEncryptedMigrationRequest{
		Username: "alice", Tenant: "alice", KeyRef: "{not json",
	})
	if err == nil {
		t.Fatal("a malformed key ref was accepted")
	}
	if got := status.Code(err); got != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument — the request is wrong, not the daemon", got)
	}
}

// Peer-to-peer only, like AdoptMigratedContainer: a user token must not be
// able to make a daemon provision tenant storage or probe key custody.
func TestPrepareEncryptedMigration_RequiresAdmin(t *testing.T) {
	s := &ContainerServer{}

	_, err := s.PrepareEncryptedMigration(
		tenantWithScopes("alice", auth.ScopeContainersWrite),
		&pb.PrepareEncryptedMigrationRequest{Username: "alice", Tenant: "alice", KeyRef: refJSON(t, "/k")})
	if err == nil {
		t.Fatal("a non-admin caller was allowed to drive the migration pre-flight")
	}
	if got := status.Code(err); got != codes.PermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", got)
	}
}

// --- helpers -----------------------------------------------------------

func refJSON(t *testing.T, uri string) string {
	t.Helper()
	b, err := json.Marshal(zfskey.KeyRef{Scheme: zfskey.SchemeFile, URI: uri})
	if err != nil {
		t.Fatalf("marshal ref: %v", err)
	}
	return string(b)
}
