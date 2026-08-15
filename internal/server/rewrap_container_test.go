package server

import (
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/zfskey"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Control-plane-driven key rotation (#1204).
//
// Rewrapping changes only the wrapping key: ZFS re-encrypts the dataset's
// master key, never the data, so the cost is independent of dataset size.
// The daemon exposes the primitive and holds no schedule — cadence is tenant
// policy owned by the control plane (design resolved decision #5).
//
// The property these tests exist to protect is #1204's second criterion: an
// interrupted rotation must leave the container startable on exactly one of
// the two keys, never on neither. That is why the new ref is recorded only
// AFTER `zfs change-key` reports success — a ref recorded first would name a
// key the dataset is not yet wrapped by, and the container would refuse to
// start on either.

func rewrapServer(t *testing.T, z *zfsFake, p *fakeKeyProvider) (*ContainerServer, *fakeRefStore, *fakePools) {
	t.Helper()
	refs := &fakeRefStore{
		refs: map[string]zfskey.KeyRef{
			"alice-container": {Scheme: zfskey.SchemeFile, URI: "/keys/alice.key",
				Metadata: map[string]string{"tenant": "alice"}},
		},
		pools: map[string]string{"alice-container": "containarium-tenant-alice"},
	}
	pools := newFakePools()
	pools.sources["containarium-tenant-alice"] = "tank/tenants/alice"
	return &ContainerServer{encryption: testHooksWith(t, z, p, refs, pools)}, refs, pools
}

func TestRewrapContainer_RotatesTheTenantEncryptionrootAndRecordsTheNewRef(t *testing.T) {
	z, p := newZFSFake(), &fakeKeyProvider{key: aKey(t)}
	s, refs, _ := rewrapServer(t, z, p)

	resp, err := s.RewrapContainer(adminCtx(), &pb.RewrapContainerRequest{
		Username:  "alice",
		NewKeyRef: refJSON(t, "/keys/alice-v2.key"),
	})
	if err != nil {
		t.Fatalf("RewrapContainer: %v", err)
	}

	if !z.ran("change-key") {
		t.Fatalf("no rewrap happened; calls=%v", z.calls)
	}
	// On the tenant's encryptionroot — the pool's source — not the
	// container's own dataset, which has no key of its own to change.
	if !z.ran("tank/tenants/alice") {
		t.Errorf("rewrapped the wrong dataset; calls=%v", z.calls)
	}
	if got := refs.refs["alice-container"].URI; got != "/keys/alice-v2.key" {
		t.Errorf("stored ref = %q, want the NEW key — every later start resolves the key from "+
			"this, so a stale ref means the container opens with a key the dataset no longer has", got)
	}
	if len(resp.RewrappedContainers) == 0 {
		t.Error("the response does not say which containers were affected; rotation hits the " +
			"whole tenant and a caller must not have to discover that themselves")
	}
}

// #1204 AC2, the ordering that makes an interrupted rotation survivable.
//
// If the ref were recorded before the rewrap, a failure between the two
// would leave the dataset wrapped by the OLD key while the daemon believed
// the NEW one — so neither key would start the container. Recording after
// means a failure leaves the old key both wrapped and recorded: still
// exactly one working key.
func TestRewrapContainer_AFailedRewrapLeavesTheOldKeyRecorded(t *testing.T) {
	z, p := newZFSFake(), &fakeKeyProvider{key: aKey(t)}
	z.errs["change-key"] = errors.New("exit status 1")
	z.stderr["change-key"] = "Key must be loaded"
	s, refs, _ := rewrapServer(t, z, p)

	_, err := s.RewrapContainer(adminCtx(), &pb.RewrapContainerRequest{
		Username:  "alice",
		NewKeyRef: refJSON(t, "/keys/alice-v2.key"),
	})
	if err == nil {
		t.Fatal("a failed rewrap was reported as success — the control plane would retire a key " +
			"that is still the only one that works")
	}
	if got := refs.refs["alice-container"].URI; got != "/keys/alice.key" {
		t.Errorf("stored ref = %q, want the OLD key still — the dataset is wrapped by it, and a "+
			"ref naming the new key would leave the container startable on neither", got)
	}
}

// The new key must be resolvable BEFORE anything is rotated. Rewrapping onto
// a key the daemon cannot fetch again would destroy access to the data on
// the next start.
func TestRewrapContainer_RefusesAKeyItCannotResolve(t *testing.T) {
	z := newZFSFake()
	p := &fakeKeyProvider{key: aKey(t), loadErr: errors.New("no such key")}
	s, refs, _ := rewrapServer(t, z, p)

	_, err := s.RewrapContainer(adminCtx(), &pb.RewrapContainerRequest{
		Username:  "alice",
		NewKeyRef: refJSON(t, "/keys/missing.key"),
	})
	if err == nil {
		t.Fatal("rotated onto a key the daemon cannot resolve — the data becomes unreachable at " +
			"the next start, which is indistinguishable from losing it")
	}
	if z.ran("change-key") {
		t.Errorf("the dataset was rewrapped anyway; calls=%v", z.calls)
	}
	if got := refs.refs["alice-container"].URI; got != "/keys/alice.key" {
		t.Errorf("the recorded ref changed to %q despite the failure", got)
	}
}

func TestRewrapContainer_RefusesAnUnencryptedContainer(t *testing.T) {
	z, p := newZFSFake(), &fakeKeyProvider{key: aKey(t)}
	s := &ContainerServer{encryption: testHooksWith(t, z, p,
		&fakeRefStore{refs: map[string]zfskey.KeyRef{}}, newFakePools())}

	_, err := s.RewrapContainer(adminCtx(), &pb.RewrapContainerRequest{
		Username: "bob", NewKeyRef: refJSON(t, "/keys/bob.key"),
	})
	if err == nil {
		t.Fatal("rotated a key for a container that has none")
	}
	if got := status.Code(err); got != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition", got)
	}
}

func TestRewrapContainer_RejectsAMalformedRef(t *testing.T) {
	z, p := newZFSFake(), &fakeKeyProvider{key: aKey(t)}
	s, _, _ := rewrapServer(t, z, p)

	_, err := s.RewrapContainer(adminCtx(), &pb.RewrapContainerRequest{
		Username: "alice", NewKeyRef: "{not json",
	})
	if err == nil {
		t.Fatal("a malformed key ref was accepted")
	}
	if got := status.Code(err); got != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", got)
	}
}

// Rotation is an infrastructure operation on a tenant's key custody, not a
// tenant operation — same gate as MoveContainer.
func TestRewrapContainer_RequiresAdmin(t *testing.T) {
	z, p := newZFSFake(), &fakeKeyProvider{key: aKey(t)}
	s, _, _ := rewrapServer(t, z, p)

	_, err := s.RewrapContainer(
		tenantWithScopes("alice", auth.ScopeContainersWrite),
		&pb.RewrapContainerRequest{Username: "alice", NewKeyRef: refJSON(t, "/k")})
	if err == nil {
		t.Fatal("a non-admin rotated a tenant's encryption key")
	}
	if got := status.Code(err); got != codes.PermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", got)
	}
}

// The response has to name the blast radius. A caller who thinks they
// rotated one container's key, when they rotated their whole tenant's, will
// schedule the next maintenance window wrongly.
func TestRewrapContainer_SaysRotationCoversTheWholeTenant(t *testing.T) {
	z, p := newZFSFake(), &fakeKeyProvider{key: aKey(t)}
	s, refs, _ := rewrapServer(t, z, p)
	// A second container for the same tenant, on the same pool.
	refs.refs["alice-two"] = zfskey.KeyRef{Scheme: zfskey.SchemeFile, URI: "/keys/alice.key",
		Metadata: map[string]string{"tenant": "alice"}}
	refs.pools["alice-two"] = "containarium-tenant-alice"

	resp, err := s.RewrapContainer(adminCtx(), &pb.RewrapContainerRequest{
		Username: "alice", NewKeyRef: refJSON(t, "/keys/alice-v2.key"),
	})
	if err != nil {
		t.Fatalf("RewrapContainer: %v", err)
	}

	if len(resp.RewrappedContainers) < 2 {
		t.Errorf("reported %v — the tenant's other container shares this encryptionroot and is "+
			"equally affected; a caller reading this list decides their maintenance window from it",
			resp.RewrappedContainers)
	}
	if !strings.Contains(resp.Message, "tenant") {
		t.Errorf("the message does not say rotation is tenant-wide: %q", resp.Message)
	}
	// And every one of them must now resolve the new key.
	for _, name := range []string{"alice-container", "alice-two"} {
		if got := refs.refs[name].URI; got != "/keys/alice-v2.key" {
			t.Errorf("%s still records %q — it would try the retired key on its next start", name, got)
		}
	}
}
