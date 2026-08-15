package server

import (
	"context"
	"errors"
	"testing"

	"github.com/footprintai/containarium/pkg/core/zfskey"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// KEY_UNAVAILABLE on container status (#1202, first acceptance criterion).
//
// ZFS lets a snapshot be TAKEN while the key is unloaded — which is
// deliberate, because blocking on key-custody reachability would let a
// transient outage suppress the backup window (design resolved decision #3).
// What it will not let you do is read one back. So the condition has to be
// visible on status, before someone trips over it at restore time.
//
// The distinction the enum exists to preserve: "not encrypted" and "encrypted
// but currently unopenable" are different situations with different operator
// responses, and "we could not determine it" is a third.

func TestEncryptionStateFor(t *testing.T) {
	aRef := map[string]zfskey.KeyRef{
		"alice-container": {Scheme: zfskey.SchemeFile, URI: "/keys/alice.key",
			Metadata: map[string]string{"tenant": "alice"}},
	}

	t.Run("an unencrypted container reports NONE", func(t *testing.T) {
		z, p := newZFSFake(), &fakeKeyProvider{key: aKey(t)}
		h := testHooksWith(t, z, p, &fakeRefStore{refs: map[string]zfskey.KeyRef{}}, newFakePools())

		if got := h.encryptionStateFor(context.Background(), "bob-container"); got != pb.EncryptionState_ENCRYPTION_STATE_NONE {
			t.Errorf("state = %v, want NONE", got)
		}
	})

	t.Run("a loaded key reports UNLOCKED", func(t *testing.T) {
		z, p := newZFSFake(), &fakeKeyProvider{key: aKey(t)}
		z.stdout["get"] = "available"
		refs := &fakeRefStore{refs: aRef, pools: map[string]string{"alice-container": "containarium-tenant-alice"}}
		pools := newFakePools()
		pools.sources["containarium-tenant-alice"] = "tank/tenants/alice"
		h := testHooksWith(t, z, p, refs, pools)

		if got := h.encryptionStateFor(context.Background(), "alice-container"); got != pb.EncryptionState_ENCRYPTION_STATE_UNLOCKED {
			t.Errorf("state = %v, want UNLOCKED", got)
		}
	})

	// The one an operator has to act on.
	t.Run("an unloaded key reports KEY_UNAVAILABLE", func(t *testing.T) {
		z, p := newZFSFake(), &fakeKeyProvider{key: aKey(t)}
		z.stdout["get"] = "unavailable"
		refs := &fakeRefStore{refs: aRef, pools: map[string]string{"alice-container": "containarium-tenant-alice"}}
		pools := newFakePools()
		pools.sources["containarium-tenant-alice"] = "tank/tenants/alice"
		h := testHooksWith(t, z, p, refs, pools)

		got := h.encryptionStateFor(context.Background(), "alice-container")
		if got != pb.EncryptionState_ENCRYPTION_STATE_KEY_UNAVAILABLE {
			t.Errorf("state = %v, want KEY_UNAVAILABLE — the container cannot start and its "+
				"snapshots cannot be inspected, and nothing else on status says so", got)
		}
	})

	// "We could not check" must never be reported as "there is nothing to
	// check": an operator reading NONE would conclude the container is
	// unencrypted and stop looking.
	t.Run("an unreadable state reports UNSPECIFIED, not NONE", func(t *testing.T) {
		z, p := newZFSFake(), &fakeKeyProvider{key: aKey(t)}
		refs := &fakeRefStore{
			refs:  aRef,
			pools: map[string]string{"alice-container": "containarium-tenant-alice"},
		}
		pools := newFakePools()
		pools.sourceErr = errors.New("incus unreachable")
		h := testHooksWith(t, z, p, refs, pools)

		got := h.encryptionStateFor(context.Background(), "alice-container")
		if got == pb.EncryptionState_ENCRYPTION_STATE_NONE {
			t.Fatal("an unreadable encryption state was reported as NONE — an operator would " +
				"read that as 'not encrypted' and stop investigating")
		}
		if got != pb.EncryptionState_ENCRYPTION_STATE_UNSPECIFIED {
			t.Errorf("state = %v, want UNSPECIFIED", got)
		}
	})

	// A daemon with no encryption wired: every container is genuinely
	// unencrypted, which is an answer rather than an unknown.
	t.Run("a daemon without encryption reports NONE", func(t *testing.T) {
		var h *encryptionHooks
		if got := h.encryptionStateFor(context.Background(), "alice-container"); got != pb.EncryptionState_ENCRYPTION_STATE_NONE {
			t.Errorf("state = %v, want NONE", got)
		}
	})
}

// The state has to reach the wire, or it is a field nobody sees.
func TestContainerStatus_CarriesTheEncryptionState(t *testing.T) {
	z, p := newZFSFake(), &fakeKeyProvider{key: aKey(t)}
	z.stdout["get"] = "unavailable"
	refs := &fakeRefStore{
		refs: map[string]zfskey.KeyRef{
			"alice-container": {Scheme: zfskey.SchemeFile, URI: "/keys/alice.key"},
		},
		pools: map[string]string{"alice-container": "containarium-tenant-alice"},
	}
	pools := newFakePools()
	pools.sources["containarium-tenant-alice"] = "tank/tenants/alice"

	s := &ContainerServer{encryption: testHooksWith(t, z, p, refs, pools)}
	out := s.withEncryptionState(context.Background(), &pb.Container{Name: "alice-container"})

	if out.EncryptionState != pb.EncryptionState_ENCRYPTION_STATE_KEY_UNAVAILABLE {
		t.Errorf("container status carries %v, want KEY_UNAVAILABLE", out.EncryptionState)
	}
}

// A nil container must not panic the status path — it is decoration on a
// response, and decoration must never be the thing that breaks a list.
func TestContainerStatus_ToleratesANilContainer(t *testing.T) {
	s := &ContainerServer{}
	if got := s.withEncryptionState(context.Background(), nil); got != nil {
		t.Errorf("got %v, want nil", got)
	}
}
