//go:build integration

// Integration coverage for the ssh_keys registry (#2517). This table is the
// self-host authorization source: a wrong ON CONFLICT clause re-activates a
// revoked key, which is exactly the bug a skipped test hides.
//
//	CONTAINARIUM_TEST_DSN=postgres://... go test -tags=integration ./internal/sshauthz/
package sshauthz

import (
	"bytes"
	"context"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func pgKeys(t *testing.T) *PGKeyStore {
	t.Helper()
	return pgKeysHeld(t, t.TempDir())
}

// pgKeysHeld is pgKeys with the holder lookup reading homeRoot.
func pgKeysHeld(t *testing.T, homeRoot string) *PGKeyStore {
	t.Helper()
	dsn := os.Getenv("CONTAINARIUM_TEST_DSN")
	if dsn == "" {
		t.Fatal("CONTAINARIUM_TEST_DSN is unset. Failing rather than skipping — this is access " +
			"control, and a skipped test looks exactly like a passing one.")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, `DROP TABLE IF EXISTS ssh_keys`); err != nil {
		t.Fatalf("reset: %v", err)
	}
	s, err := NewPGKeyStore(ctx, pool, FileHolders{HomeRoot: homeRoot})
	if err != nil {
		t.Fatalf("NewPGKeyStore: %v", err)
	}
	return s
}

func TestPGKeyStore_DeciderTable(t *testing.T) {
	runDeciderCases(t, func(t *testing.T) keySeeder { return pgKeys(t) })
}

func mustRecord(t *testing.T, pub, username string, src KeySource, at time.Time) KeyRecord {
	t.Helper()
	rec, err := NewKeyRecord(pub, username, src, at)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func lookup(t *testing.T, s *PGKeyStore, fp string) KeyRecord {
	t.Helper()
	rec, err := s.Lookup(context.Background(), fp)
	if err != nil {
		t.Fatalf("Lookup(%s): %v", fp, err)
	}
	return rec
}

func TestPGKeyStore_RegisterRoundTrip(t *testing.T) {
	s := pgKeys(t)
	ctx := context.Background()
	rec := mustRecord(t, testKey(t), "alice", SourceAPI, caseNow)
	if err := s.Register(ctx, rec); err != nil {
		t.Fatal(err)
	}
	got := lookup(t, s, rec.Fingerprint)
	if got.Username != "alice" || got.UserID != "alice" || got.PublicKey != rec.PublicKey || got.KeyType != rec.KeyType ||
		got.Source != SourceAPI || !got.CreatedAt.Equal(caseNow) || !got.RevokedAt.IsZero() {
		t.Fatalf("round trip: got %+v, want %+v", got, rec)
	}
	if _, err := s.Lookup(ctx, "SHA256:nope"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("unknown fingerprint: got %v, want ErrKeyNotFound", err)
	}
}

// Decision (#2517): first registration wins while the row is active.
func TestPGKeyStore_FirstRegistrationWins(t *testing.T) {
	s := pgKeys(t)
	ctx := context.Background()
	pub := testKey(t)
	first := mustRecord(t, pub, "bob", SourceBoxCreate, caseNow)
	if err := s.Register(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := s.Register(ctx, mustRecord(t, pub, "alice-container-bob", SourceCollaborator, caseNow.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	got := lookup(t, s, first.Fingerprint)
	if got.Username != "bob" || got.Source != SourceBoxCreate || !got.CreatedAt.Equal(caseNow) {
		t.Fatalf("second registration overwrote the active row: %+v", got)
	}
}

// Decision (#3187, replacing #2517's "every account"): a revocation applies
// only to the row the revoking account owns. Another account holding the
// same public key cannot revoke the owner's entry.
func TestPGKeyStore_RevokeByNonOwnerLeavesRowActive(t *testing.T) {
	s := pgKeys(t)
	ctx := context.Background()
	pub := testKey(t)
	rec := mustRecord(t, pub, "bob", SourceAPI, caseNow)
	if err := s.Register(ctx, rec); err != nil {
		t.Fatal(err)
	}
	revokeAt := caseNow.Add(time.Hour)
	for _, other := range []string{"carol", "bob-container-carol"} {
		if err := s.Revoke(ctx, mustRecord(t, pub, other, SourceAPI, revokeAt), revokeAt); err != nil {
			t.Fatal(err)
		}
	}
	got := lookup(t, s, rec.Fingerprint)
	if !got.RevokedAt.IsZero() || got.Username != "bob" || !got.CreatedAt.Equal(caseNow) {
		t.Fatalf("a non-owner revoked or rewrote bob's row: %+v", got)
	}
}

// A non-owner's revoke changes nothing and returns nil, so it is logged once
// (naming the revoking account and the fingerprint) for an operator to see
// that the registry entry was left to its owner. The owner's revoke, an
// owner's repeat revoke and a revoke of an unknown key change a row and log
// nothing.
func TestPGKeyStore_RevokeByNonOwnerIsLogged(t *testing.T) {
	s := pgKeys(t)
	ctx := context.Background()
	var buf bytes.Buffer
	orig, flags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(orig); log.SetFlags(flags) })

	pub := testKey(t)
	rec := mustRecord(t, pub, "bob", SourceAPI, caseNow)
	if err := s.Register(ctx, rec); err != nil {
		t.Fatal(err)
	}
	revokeAt := caseNow.Add(time.Hour)
	if err := s.Revoke(ctx, mustRecord(t, pub, "carol", SourceAPI, revokeAt), revokeAt); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if n := strings.Count(out, "\n"); n != 1 || !strings.Contains(out, "carol") || !strings.Contains(out, rec.Fingerprint) {
		t.Fatalf("non-owner revoke: want one log line naming carol and %s, got %q", rec.Fingerprint, out)
	}

	buf.Reset()
	for i := 0; i < 2; i++ { // owner's revoke, then the owner's repeat revoke
		if err := s.Revoke(ctx, mustRecord(t, pub, "bob", SourceAPI, revokeAt), revokeAt); err != nil {
			t.Fatal(err)
		}
	}
	unknown := testKey(t)
	if err := s.Revoke(ctx, mustRecord(t, unknown, "dave", SourceAPI, revokeAt), revokeAt); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Fatalf("owner or unknown-key revoke logged: %q", buf.String())
	}
	if got := lookup(t, s, rec.Fingerprint); got.RevokedAt.IsZero() {
		t.Fatalf("owner's revoke did not revoke: %+v", got)
	}
}

// The owner's revocation revokes the row, and a re-add is a fresh
// registration (new owner, new created_at, active).
func TestPGKeyStore_RevokeThenReAdd(t *testing.T) {
	s := pgKeys(t)
	ctx := context.Background()
	pub := testKey(t)
	rec := mustRecord(t, pub, "bob", SourceAPI, caseNow)
	if err := s.Register(ctx, rec); err != nil {
		t.Fatal(err)
	}
	revokeAt := caseNow.Add(time.Hour)
	if err := s.Revoke(ctx, mustRecord(t, pub, "bob", SourceAPI, revokeAt), revokeAt); err != nil {
		t.Fatal(err)
	}
	got := lookup(t, s, rec.Fingerprint)
	if !got.RevokedAt.Equal(revokeAt) || got.Username != "bob" {
		t.Fatalf("the owner's revoke must revoke its row and keep its owner: %+v", got)
	}
	// A second revoke keeps the original revocation time.
	if err := s.Revoke(ctx, mustRecord(t, pub, "bob", SourceAPI, revokeAt.Add(time.Hour)), revokeAt.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got := lookup(t, s, rec.Fingerprint); !got.RevokedAt.Equal(revokeAt) {
		t.Fatalf("second revoke moved revoked_at: %+v", got)
	}

	reAddAt := caseNow.Add(48 * time.Hour)
	if err := s.Register(ctx, mustRecord(t, pub, "alice-container-bob", SourceCollaborator, reAddAt)); err != nil {
		t.Fatal(err)
	}
	got = lookup(t, s, rec.Fingerprint)
	if !got.RevokedAt.IsZero() || got.Username != "alice-container-bob" || got.UserID != "bob" ||
		got.Source != SourceCollaborator || !got.CreatedAt.Equal(reAddAt) {
		t.Fatalf("re-add is not a fresh registration: %+v", got)
	}
}

// Revoking a key the registry has never seen leaves a revoked row, so a
// later backfill of the same key from another account cannot make it live.
func TestPGKeyStore_RevokeUnknownKeyBlocksBackfill(t *testing.T) {
	s := pgKeys(t)
	ctx := context.Background()
	root := t.TempDir()
	pub := testKey(t)
	writeHome(t, root, "alice", pub)

	if err := s.Revoke(ctx, mustRecord(t, pub, "bob", SourceAPI, caseNow), caseNow); err != nil {
		t.Fatal(err)
	}
	if n, err := Backfill(ctx, s, root, caseNow.Add(time.Hour)); err != nil || n != 0 {
		t.Fatalf("backfill = %d, %v; want 0 (key is revoked)", n, err)
	}
	fp := mustRecord(t, pub, "alice", SourceBackfill, caseNow).Fingerprint
	if got := lookup(t, s, fp); got.RevokedAt.IsZero() {
		t.Fatalf("backfill re-activated a revoked key: %+v", got)
	}
}

// Done-when 2: a fixture /home tree → expected rows; running it twice adds
// nothing.
func TestPGKeyStore_BackfillTwiceAddsNothing(t *testing.T) {
	s := pgKeys(t)
	ctx := context.Background()
	root, want := fixtureHome(t)

	n, err := Backfill(ctx, s, root, caseNow)
	if err != nil || n != len(want) {
		t.Fatalf("first backfill = %d, %v; want %d", n, err, len(want))
	}
	for pub, username := range want {
		got := lookup(t, s, mustRecord(t, pub, username, SourceBackfill, caseNow).Fingerprint)
		if got.Username != username || got.Source != SourceBackfill || !got.CreatedAt.Equal(caseNow) {
			t.Fatalf("backfilled row %+v, want username %s source backfill", got, username)
		}
	}
	n, err = Backfill(ctx, s, root, caseNow.Add(time.Hour))
	if err != nil || n != 0 {
		t.Fatalf("second backfill = %d, %v; want 0", n, err)
	}
	var count int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM ssh_keys WHERE source = 'backfill'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != len(want) {
		t.Fatalf("rows = %d, want %d", count, len(want))
	}
}

// holdKey writes pub into homeRoot/<user>/.ssh/authorized_keys.
func holdKey(t *testing.T, homeRoot, user, pub string) {
	t.Helper()
	dir := filepath.Join(homeRoot, user, ".ssh")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(dir, "authorized_keys"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(pub + "\n"); err != nil {
		t.Fatal(err)
	}
}

// #3222, Alice-first order: alice registers bob's public key before bob does,
// so first-registration-wins leaves her as the row's owner. Bob then holds
// the same key in his own authorized_keys. Alice's revoke must be refused and
// the row must stay active; it used to revoke bob's access.
func TestPGKeyStore_RevokeRefusedWhileAnotherAccountHoldsKey(t *testing.T) {
	home := t.TempDir()
	s := pgKeysHeld(t, home)
	ctx := context.Background()
	pub := testKey(t)

	aliceRec := mustRecord(t, pub, "alice", SourceAPI, caseNow)
	if err := s.Register(ctx, aliceRec); err != nil {
		t.Fatal(err)
	}
	if err := s.Register(ctx, mustRecord(t, pub, "bob", SourceAPI, caseNow.Add(time.Minute))); err != nil {
		t.Fatal(err)
	}
	holdKey(t, home, "alice", pub)
	holdKey(t, home, "bob", pub)
	if got := lookup(t, s, aliceRec.Fingerprint); got.Username != "alice" || !got.RevokedAt.IsZero() {
		t.Fatalf("precondition: row = %+v, want active and owned by alice", got)
	}

	revokeAt := caseNow.Add(time.Hour)
	err := s.Revoke(ctx, mustRecord(t, pub, "alice", SourceAPI, revokeAt), revokeAt)
	if !errors.Is(err, ErrKeyHeldByOtherAccount) {
		t.Fatalf("Revoke = %v, want ErrKeyHeldByOtherAccount", err)
	}
	if strings.Contains(err.Error(), "bob") {
		t.Fatalf("the error names the other holder: %v", err)
	}
	if got := lookup(t, s, aliceRec.Fingerprint); !got.RevokedAt.IsZero() {
		t.Fatalf("alice revoked a key bob still holds: %+v", got)
	}

	// Once bob no longer holds it, alice is the sole holder and can revoke.
	if err := os.Remove(filepath.Join(home, "bob", ".ssh", "authorized_keys")); err != nil {
		t.Fatal(err)
	}
	if err := s.Revoke(ctx, mustRecord(t, pub, "alice", SourceAPI, revokeAt), revokeAt); err != nil {
		t.Fatalf("sole holder's revoke: %v", err)
	}
	if got := lookup(t, s, aliceRec.Fingerprint); got.RevokedAt.IsZero() {
		t.Fatal("the sole holder's revoke did not revoke the key")
	}
}

// A key with no row is the same: Revoke would insert a revoked row, which
// would lock out whoever holds the key, so it is refused while another
// account holds it. With no other holder the revoked row is inserted (so a
// later backfill cannot register the key as live).
func TestPGKeyStore_RevokeOfKeyWithNoRow(t *testing.T) {
	home := t.TempDir()
	s := pgKeysHeld(t, home)
	ctx := context.Background()
	held, free := testKey(t), testKey(t)
	holdKey(t, home, "bob", held)
	revokeAt := caseNow.Add(time.Hour)

	heldRec := mustRecord(t, held, "alice", SourceAPI, revokeAt)
	if err := s.Revoke(ctx, heldRec, revokeAt); !errors.Is(err, ErrKeyHeldByOtherAccount) {
		t.Fatalf("revoke of a no-row key bob holds = %v, want ErrKeyHeldByOtherAccount", err)
	}
	if _, err := s.Lookup(ctx, heldRec.Fingerprint); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("refused revoke left a row behind: %v", err)
	}

	freeRec := mustRecord(t, free, "alice", SourceAPI, revokeAt)
	if err := s.Revoke(ctx, freeRec, revokeAt); err != nil {
		t.Fatal(err)
	}
	if got := lookup(t, s, freeRec.Fingerprint); got.RevokedAt.IsZero() || got.Username != "alice" {
		t.Fatalf("no-row revoke = %+v, want a revoked row owned by alice", got)
	}
}

// A non-owner's revoke never takes effect, so it is not refused for a held
// key: bob's drop of a copy of alice's key changes nothing in the registry.
func TestPGKeyStore_NonOwnerRevokeNotRefusedWhenOwnerHoldsKey(t *testing.T) {
	home := t.TempDir()
	s := pgKeysHeld(t, home)
	ctx := context.Background()
	pub := testKey(t)
	rec := mustRecord(t, pub, "alice", SourceAPI, caseNow)
	if err := s.Register(ctx, rec); err != nil {
		t.Fatal(err)
	}
	holdKey(t, home, "alice", pub)
	revokeAt := caseNow.Add(time.Hour)
	if err := s.Revoke(ctx, mustRecord(t, pub, "bob", SourceAPI, revokeAt), revokeAt); err != nil {
		t.Fatalf("non-owner revoke: %v", err)
	}
	if got := lookup(t, s, rec.Fingerprint); !got.RevokedAt.IsZero() || got.Username != "alice" {
		t.Fatalf("row changed: %+v", got)
	}
}

// An unreadable HomeRoot makes the holder check unanswerable: Revoke must
// error and leave the row as it was, for an owned row and for a key with no
// row (#3241).
func TestPGKeyStore_RevokeFailsClosedOnUnreadableHomeRoot(t *testing.T) {
	s := pgKeysHeld(t, filepath.Join(t.TempDir(), "does-not-exist"))
	ctx := context.Background()
	pub, fresh := testKey(t), testKey(t)
	rec := mustRecord(t, pub, "alice", SourceAPI, caseNow)
	if err := s.Register(ctx, rec); err != nil {
		t.Fatal(err)
	}
	revokeAt := caseNow.Add(time.Hour)

	if err := s.Revoke(ctx, mustRecord(t, pub, "alice", SourceAPI, revokeAt), revokeAt); err == nil {
		t.Fatal("Revoke succeeded with an unreadable HomeRoot")
	}
	if got := lookup(t, s, rec.Fingerprint); !got.RevokedAt.IsZero() || got.Username != "alice" {
		t.Fatalf("row changed: %+v", got)
	}

	freshRec := mustRecord(t, fresh, "alice", SourceAPI, revokeAt)
	if err := s.Revoke(ctx, freshRec, revokeAt); err == nil {
		t.Fatal("no-row Revoke succeeded with an unreadable HomeRoot")
	}
	if _, err := s.Lookup(ctx, freshRec.Fingerprint); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("failed revoke left a row behind: %v", err)
	}
}

// A home the scan cannot read might hold the key: Revoke must error and leave
// the row as it was, rather than read the unreadable account as "no holder"
// (#3241). The sole readable holder's key is held by nobody else we can see.
func TestPGKeyStore_RevokeFailsClosedOnUnreadableAccount(t *testing.T) {
	home := t.TempDir()
	s := pgKeysHeld(t, home)
	ctx := context.Background()
	pub := testKey(t)
	holdKey(t, home, "alice", pub)
	rec := mustRecord(t, pub, "alice", SourceAPI, caseNow)
	if err := s.Register(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(home, "mallory")); err != nil {
		t.Fatal(err)
	}
	revokeAt := caseNow.Add(time.Hour)
	if err := s.Revoke(ctx, mustRecord(t, pub, "alice", SourceAPI, revokeAt), revokeAt); err == nil {
		t.Fatal("Revoke succeeded while an account's authorized_keys could not be read")
	}
	if got := lookup(t, s, rec.Fingerprint); !got.RevokedAt.IsZero() {
		t.Fatalf("row revoked: %+v", got)
	}
}
