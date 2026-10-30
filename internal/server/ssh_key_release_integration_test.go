//go:build integration

// Shared-key ownership through the RPCs (#3217), over the real registry:
// an owner's drop of a key another account still holds releases the row, so
// the remaining holder's own drop revokes it; no other tenant can cut the
// remaining holder off; and ownership compares user_id for an owner account.
//
//	CONTAINARIUM_TEST_DSN=postgres://... go test -tags=integration ./internal/server/ -run SharedKey
package server

import (
	"context"
	"slices"
	"testing"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/sshauthz"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// aliceFirstShared has alice add bob's public key before bob does, so alice
// owns the row, and bob then adds it to his own box.
func aliceFirstShared(t *testing.T) (*ContainerServer, *sshauthz.PGKeyStore, *fakeAuthorizedKeys, string) {
	t.Helper()
	s, keys, fs := crossTenantServer(t)
	bobKey := newTestPubKey(t)
	for _, u := range []string{"alice", "bob"} {
		if _, err := s.AddSSHKey(tenantWithScopes(u, auth.ScopeSSHWrite), &pb.AddSSHKeyRequest{Username: u, SshPublicKey: bobKey}); err != nil {
			t.Fatalf("%s AddSSHKey: %v", u, err)
		}
	}
	if owner, active := keyState(t, keys, bobKey); owner != "alice" || !active {
		t.Fatalf("precondition: row = owner %q active %v, want alice, active", owner, active)
	}
	return s, keys, fs, bobKey
}

func removeKey(t *testing.T, s *ContainerServer, user, pub string) {
	t.Helper()
	if _, err := s.RemoveSSHKey(tenantWithScopes(user, auth.ScopeSSHWrite), &pb.RemoveSSHKeyRequest{Username: user, SshPublicKey: pub}); err != nil {
		t.Fatalf("%s RemoveSSHKey: %v", user, err)
	}
}

// The residual gap #3226 left: alice's drop is skipped for the registry
// because bob holds the key, and bob's own later drop must then revoke it
// rather than leave an active row nobody holds.
func TestSSHKeys_SharedKeyHolderDropRevokesAfterOwnerDrop(t *testing.T) {
	for _, tc := range []struct {
		name      string
		aliceDrop func(t *testing.T, s *ContainerServer, pub string)
	}{
		{"RemoveSSHKey", func(t *testing.T, s *ContainerServer, pub string) { removeKey(t, s, "alice", pub) }},
		{"SetSSHKeys allow_empty", func(t *testing.T, s *ContainerServer, _ string) {
			if _, err := s.SetSSHKeys(tenantWithScopes("alice", auth.ScopeSSHWrite), &pb.SetSSHKeysRequest{Username: "alice", AllowEmpty: true}); err != nil {
				t.Fatalf("alice SetSSHKeys: %v", err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, keys, fs, bobKey := aliceFirstShared(t)
			tc.aliceDrop(t, s, bobKey)
			if _, active := keyState(t, keys, bobKey); !active {
				t.Fatal("alice's drop revoked a key bob holds")
			}

			removeKey(t, s, "bob", bobKey)
			if slices.Contains(fs.files["bob"], bobKey) {
				t.Fatal("bob's authorized_keys still holds the key")
			}
			if _, active := keyState(t, keys, bobKey); active {
				t.Fatal("bob dropped the key as its sole holder and the registry row stayed active")
			}
		})
	}
}

// Cross-tenant, must fail closed: once alice has dropped the key, neither
// alice (adding and dropping it again) nor an unrelated tenant can revoke the
// access bob still holds; bob's re-add takes the row over.
func TestSSHKeys_SharedKeyReleasedRowCannotCutHolderOff(t *testing.T) {
	s, keys, fs, bobKey := aliceFirstShared(t)
	removeKey(t, s, "alice", bobKey)

	// An unrelated tenant drops a key it never held.
	removeKey(t, s, "carol", bobKey)
	if _, active := keyState(t, keys, bobKey); !active {
		t.Fatal("carol revoked a key bob holds")
	}

	// Alice registers it again (taking the released row), then drops it.
	aliceCtx := tenantWithScopes("alice", auth.ScopeSSHWrite)
	if _, err := s.AddSSHKey(aliceCtx, &pb.AddSSHKeyRequest{Username: "alice", SshPublicKey: bobKey}); err != nil {
		t.Fatalf("alice AddSSHKey: %v", err)
	}
	if _, err := s.SetSSHKeys(aliceCtx, &pb.SetSSHKeysRequest{Username: "alice", AllowEmpty: true}); err != nil {
		t.Fatalf("alice SetSSHKeys: %v", err)
	}
	if _, active := keyState(t, keys, bobKey); !active {
		t.Fatal("alice cut bob off by re-registering and dropping his key")
	}
	if !slices.Contains(fs.files["bob"], bobKey) {
		t.Fatal("bob's authorized_keys lost his key")
	}

	// Bob's re-add takes the released row over.
	if _, err := s.AddSSHKey(tenantWithScopes("bob", auth.ScopeSSHWrite), &pb.AddSSHKeyRequest{Username: "bob", SshPublicKey: bobKey}); err != nil {
		t.Fatalf("bob AddSSHKey: %v", err)
	}
	if owner, active := keyState(t, keys, bobKey); owner != "bob" || !active {
		t.Fatalf("after bob's re-add: owner %q active %v, want bob, active", owner, active)
	}
}

// Ownership compares user_id for an owner account: a key first registered
// through bob's collaborator account on alice's box is bob's, so bob's drop
// from his own box revokes it once the collaborator account no longer holds
// it, and not while it does.
func TestSSHKeys_SharedKeyOwnerAccountMatchesCollaboratorUserID(t *testing.T) {
	const collab = "alice-container-bob"
	for _, tc := range []struct {
		name        string
		collabHolds bool
		wantActive  bool
	}{
		{"collaborator account no longer holds it", false, false},
		{"collaborator account still holds it", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, keys, fs := crossTenantServer(t)
			bobKey := newTestPubKey(t)
			if err := s.registerSSHKey(context.Background(), collab, bobKey, sshauthz.SourceCollaborator); err != nil {
				t.Fatal(err)
			}
			if tc.collabHolds {
				fs.files[collab] = []string{bobKey}
			}
			if _, err := s.AddSSHKey(tenantWithScopes("bob", auth.ScopeSSHWrite), &pb.AddSSHKeyRequest{Username: "bob", SshPublicKey: bobKey}); err != nil {
				t.Fatalf("bob AddSSHKey: %v", err)
			}
			if owner, _ := keyState(t, keys, bobKey); owner != collab {
				t.Fatalf("precondition: owner %q, want %s", owner, collab)
			}

			removeKey(t, s, "bob", bobKey)
			if _, active := keyState(t, keys, bobKey); active != tc.wantActive {
				t.Fatalf("after bob's drop: active = %v, want %v", active, tc.wantActive)
			}
		})
	}
}
