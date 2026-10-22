//go:build integration

// Integration coverage for the ssh_keys registry (#2517). This table is the
// self-host authorization source: a wrong ON CONFLICT clause re-activates a
// revoked key, which is exactly the bug a skipped test hides.
//
//	CONTAINARIUM_TEST_DSN=postgres://... go test -tags=integration ./internal/sshauthz/
package sshauthz

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func pgKeys(t *testing.T) *PGKeyStore {
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
	s, err := NewPGKeyStore(ctx, pool)
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

// Decision (#2517): RemoveSSHKey revokes the key for every account, and a
// re-add is a fresh registration (new owner, new created_at, active).
func TestPGKeyStore_RevokeThenReAdd(t *testing.T) {
	s := pgKeys(t)
	ctx := context.Background()
	pub := testKey(t)
	rec := mustRecord(t, pub, "bob", SourceAPI, caseNow)
	if err := s.Register(ctx, rec); err != nil {
		t.Fatal(err)
	}
	revokeAt := caseNow.Add(time.Hour)
	if err := s.Revoke(ctx, mustRecord(t, pub, "carol", SourceAPI, revokeAt), revokeAt); err != nil {
		t.Fatal(err)
	}
	got := lookup(t, s, rec.Fingerprint)
	if !got.RevokedAt.Equal(revokeAt) || got.Username != "bob" {
		t.Fatalf("revoke by another account must revoke the shared row and keep its owner: %+v", got)
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
