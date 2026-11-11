//go:build integration

// Ownership of a shared key's ssh_keys row (#3217): an owner's drop while
// another account still holds the key releases the row instead of leaving the
// dropper as owner of a key it no longer holds, a later holder can take a
// released row over, and ownership compares user_id for an owner account.
//
//	CONTAINARIUM_TEST_DSN=postgres://... go test -tags=integration ./internal/sshauthz/ -run Ownership
package sshauthz

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// heldKeys is the store with the holder lookup reading homeRoot.
func heldKeys(t *testing.T, homeRoot string) *PGKeyStore {
	t.Helper()
	return pgKeysHeld(t, homeRoot)
}

func dropHeld(t *testing.T, homeRoot, user string) {
	t.Helper()
	if err := os.Remove(filepath.Join(homeRoot, user, ".ssh", "authorized_keys")); err != nil {
		t.Fatal(err)
	}
}

// aliceFirst registers pub to alice and then to bob, both holding it, so
// first registration leaves alice as owner. It returns the fingerprint.
func aliceFirst(t *testing.T, s *PGKeyStore, home, pub string) string {
	t.Helper()
	ctx := context.Background()
	rec := mustRecord(t, pub, "alice", SourceAPI, caseNow)
	for _, r := range []KeyRecord{rec, mustRecord(t, pub, "bob", SourceAPI, caseNow.Add(time.Minute))} {
		if err := s.Register(ctx, r); err != nil {
			t.Fatal(err)
		}
		holdKey(t, home, r.Username, pub)
	}
	if got := lookup(t, s, rec.Fingerprint); got.Username != "alice" || !got.RevokedAt.IsZero() {
		t.Fatalf("precondition: row = %+v, want active and owned by alice", got)
	}
	return rec.Fingerprint
}

// The residual gap #3226 left: alice (owner) drops a key bob still holds, so
// her revoke is refused. She must not stay owner of a key she no longer
// holds, or bob's later drop is a non-owner no-op and the row stays active
// with no holder at all. Her drop releases the row, and bob's drop as the
// sole holder then revokes it.
func TestPGKeyStoreOwnership_OwnerDropReleasesSharedRow(t *testing.T) {
	home := t.TempDir()
	s := heldKeys(t, home)
	ctx := context.Background()
	pub := testKey(t)
	fp := aliceFirst(t, s, home, pub)

	at := caseNow.Add(time.Hour)
	if err := s.Revoke(ctx, mustRecord(t, pub, "alice", SourceAPI, at), at); !errors.Is(err, ErrKeyHeldByOtherAccount) {
		t.Fatalf("alice's revoke = %v, want ErrKeyHeldByOtherAccount", err)
	}
	dropHeld(t, home, "alice")
	if got := lookup(t, s, fp); !got.RevokedAt.IsZero() {
		t.Fatalf("alice's drop revoked a key bob holds: %+v", got)
	}

	if err := s.Revoke(ctx, mustRecord(t, pub, "bob", SourceAPI, at), at); err != nil {
		t.Fatalf("bob's revoke as the sole holder: %v", err)
	}
	if got := lookup(t, s, fp); got.RevokedAt.IsZero() {
		t.Fatalf("bob dropped the key as its sole holder and the row stayed active: %+v", got)
	}
}

// A released row is taken over by the next registration: the holder that
// re-adds the key becomes the owner. Once owned again, a non-owner's revoke
// changes nothing.
func TestPGKeyStoreOwnership_RegisterTakesOverReleasedRow(t *testing.T) {
	home := t.TempDir()
	s := heldKeys(t, home)
	ctx := context.Background()
	pub := testKey(t)
	fp := aliceFirst(t, s, home, pub)

	at := caseNow.Add(time.Hour)
	if err := s.Revoke(ctx, mustRecord(t, pub, "alice", SourceAPI, at), at); !errors.Is(err, ErrKeyHeldByOtherAccount) {
		t.Fatalf("alice's revoke = %v, want ErrKeyHeldByOtherAccount", err)
	}
	dropHeld(t, home, "alice")

	if err := s.Register(ctx, mustRecord(t, pub, "bob", SourceAPI, at.Add(time.Minute))); err != nil {
		t.Fatal(err)
	}
	got := lookup(t, s, fp)
	if got.Username != "bob" || got.UserID != "bob" || !got.RevokedAt.IsZero() {
		t.Fatalf("bob's registration did not take the released row over: %+v", got)
	}
	if !got.CreatedAt.Equal(caseNow) {
		t.Fatalf("takeover moved created_at (the key was never revoked, so its age stands): %+v", got)
	}

	// Owned by bob again: carol, who does not hold it, changes nothing.
	if err := s.Revoke(ctx, mustRecord(t, pub, "carol", SourceAPI, at), at); err != nil {
		t.Fatal(err)
	}
	if got := lookup(t, s, fp); got.Username != "bob" || !got.RevokedAt.IsZero() {
		t.Fatalf("carol changed bob's row: %+v", got)
	}
}

// Cross-tenant, fail closed: a released row a holder still has in its file
// cannot be revoked by anyone else, whether the account that released it or
// an unrelated one, and re-registering it first does not change that.
func TestPGKeyStoreOwnership_ReleasedRowNotRevokedWhileHeld(t *testing.T) {
	home := t.TempDir()
	s := heldKeys(t, home)
	ctx := context.Background()
	pub := testKey(t)
	fp := aliceFirst(t, s, home, pub)

	at := caseNow.Add(time.Hour)
	if err := s.Revoke(ctx, mustRecord(t, pub, "alice", SourceAPI, at), at); !errors.Is(err, ErrKeyHeldByOtherAccount) {
		t.Fatalf("alice's revoke = %v, want ErrKeyHeldByOtherAccount", err)
	}
	dropHeld(t, home, "alice")

	for _, who := range []string{"alice", "carol", "alice-container-bob"} {
		err := s.Revoke(ctx, mustRecord(t, pub, who, SourceAPI, at), at)
		if err != nil && !errors.Is(err, ErrKeyHeldByOtherAccount) {
			t.Fatalf("%s's revoke: %v", who, err)
		}
		if got := lookup(t, s, fp); !got.RevokedAt.IsZero() {
			t.Fatalf("%s revoked a released key bob still holds: %+v", who, got)
		}
	}

	// Carol registers it first, then drops it: still bob's access.
	if err := s.Register(ctx, mustRecord(t, pub, "carol", SourceAPI, at)); err != nil {
		t.Fatal(err)
	}
	holdKey(t, home, "carol", pub)
	if err := s.Revoke(ctx, mustRecord(t, pub, "carol", SourceAPI, at), at); !errors.Is(err, ErrKeyHeldByOtherAccount) {
		t.Fatalf("carol's revoke = %v, want ErrKeyHeldByOtherAccount", err)
	}
	if got := lookup(t, s, fp); !got.RevokedAt.IsZero() {
		t.Fatalf("carol revoked a key bob still holds: %+v", got)
	}
}

// Ownership compares user_id for an owner account (#3217): a key registered
// first through bob's collaborator account on alice's box
// ("alice-container-bob", user_id "bob") is bob's, so bob's drop from his own
// box revokes it once no other account holds it. The user_id match is only
// granted to a revoking login whose user_id is its own name: a login of the
// collaborator form names a user_id it does not authenticate, so it matches
// by username alone.
func TestPGKeyStoreOwnership_ComparesUserID(t *testing.T) {
	at := caseNow.Add(time.Hour)
	for _, tc := range []struct {
		name    string
		owner   string // registers first
		revoker string
		revokes bool
	}{
		{"owner account revokes its collaborator account's row", "alice-container-bob", "bob", true},
		{"same username", "alice-container-bob", "alice-container-bob", true},
		{"another person", "alice-container-bob", "carol", false},
		{"collaborator login naming bob does not match bob's row", "bob", "alice-container-bob", false},
		{"collaborator login naming bob does not match another collaborator row", "carol-container-bob", "alice-container-bob", false},
		{"box owner is not its collaborator", "alice-container-bob", "alice", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := heldKeys(t, t.TempDir()) // nobody holds the key in a file
			ctx := context.Background()
			pub := testKey(t)
			rec := mustRecord(t, pub, tc.owner, SourceCollaborator, caseNow)
			if err := s.Register(ctx, rec); err != nil {
				t.Fatal(err)
			}
			if err := s.Revoke(ctx, mustRecord(t, pub, tc.revoker, SourceAPI, at), at); err != nil {
				t.Fatal(err)
			}
			got := lookup(t, s, rec.Fingerprint)
			if revoked := !got.RevokedAt.IsZero(); revoked != tc.revokes {
				t.Fatalf("%s revoking %s's row: revoked = %v, want %v (%+v)", tc.revoker, tc.owner, revoked, tc.revokes, got)
			}
		})
	}
}

// The user_id match still respects the holder check: bob's drop does not
// revoke the row while his collaborator account still holds the key.
func TestPGKeyStoreOwnership_UserIDMatchStillRefusedWhileHeld(t *testing.T) {
	home := t.TempDir()
	s := heldKeys(t, home)
	ctx := context.Background()
	pub := testKey(t)
	rec := mustRecord(t, pub, "alice-container-bob", SourceCollaborator, caseNow)
	if err := s.Register(ctx, rec); err != nil {
		t.Fatal(err)
	}
	holdKey(t, home, "alice-container-bob", pub)
	at := caseNow.Add(time.Hour)
	if err := s.Revoke(ctx, mustRecord(t, pub, "bob", SourceAPI, at), at); !errors.Is(err, ErrKeyHeldByOtherAccount) {
		t.Fatalf("bob's revoke = %v, want ErrKeyHeldByOtherAccount", err)
	}
	if got := lookup(t, s, rec.Fingerprint); !got.RevokedAt.IsZero() {
		t.Fatalf("bob revoked a key his collaborator account still holds: %+v", got)
	}
}

// The released_at column is added to a table created by an earlier release
// (additive migration): its rows keep their owner and stay active.
func TestPGKeyStoreOwnership_MigratesExistingTable(t *testing.T) {
	s := pgKeys(t)
	ctx := context.Background()
	pub := testKey(t)
	rec := mustRecord(t, pub, "alice", SourceAPI, caseNow)
	if err := s.Register(ctx, rec); err != nil {
		t.Fatal(err)
	}
	// Back to the earlier schema, as a rollback would leave it.
	if _, err := s.pool.Exec(ctx, `ALTER TABLE ssh_keys DROP COLUMN IF EXISTS released_at`); err != nil {
		t.Fatal(err)
	}
	s2, err := NewPGKeyStore(ctx, s.pool, s.holders)
	if err != nil {
		t.Fatalf("NewPGKeyStore over the earlier schema: %v", err)
	}
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns
		WHERE table_name = 'ssh_keys' AND column_name = 'released_at'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("released_at columns = %d, want 1", n)
	}
	if got := lookup(t, s2, rec.Fingerprint); got.Username != "alice" || !got.RevokedAt.IsZero() {
		t.Fatalf("existing row after migration: %+v", got)
	}
}
