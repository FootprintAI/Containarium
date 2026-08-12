//go:build integration

// Integration coverage for the JWT revocation store (#1300).
//
// This is a security control with a simple failure mode: if a revoked token
// does not read as revoked, it stays valid until it expires on its own. The
// SQL had no test — the store is one of the pgxpool users this repo could not
// exercise until the store-integration lane existed.
//
//	CONTAINARIUM_TEST_DSN=postgres://... go test -tags=integration ./internal/auth/
package auth

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func revocationStore(t *testing.T) *PgRevocationStore {
	t.Helper()
	dsn := os.Getenv("CONTAINARIUM_TEST_DSN")
	if dsn == "" {
		t.Fatal("CONTAINARIUM_TEST_DSN is unset. Failing rather than skipping — a skipped test " +
			"and a passing one look identical, which is how this store went untested.")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(context.Background(), `DROP TABLE IF EXISTS jwt_revocations`); err != nil {
		t.Fatalf("reset: %v", err)
	}
	s, err := NewPgRevocationStore(context.Background(), pool)
	if err != nil {
		t.Fatalf("NewPgRevocationStore: %v", err)
	}
	return s
}

// The whole point of the store: a revoked token reads as revoked, and an
// unrelated one does not.
func TestRevocationStore_RevokedTokenReadsAsRevoked(t *testing.T) {
	ctx := context.Background()
	s := revocationStore(t)

	if err := s.Revoke(ctx, "jti-1", time.Now().Add(time.Hour), "operator_revoke"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	revoked, err := s.IsRevoked(ctx, "jti-1")
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if !revoked {
		t.Error("a revoked token did not read as revoked — it would stay valid until it expired " +
			"on its own, which is the entire failure this store exists to prevent")
	}

	other, err := s.IsRevoked(ctx, "jti-2")
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if other {
		t.Error("an unrevoked token read as revoked — every session would be rejected")
	}
}

// Revoking twice must not rewrite the first record. The reason and time are
// audit history: a later call describing the same revocation differently
// would overwrite why it happened.
func TestRevocationStore_SecondRevokeDoesNotOverwriteTheFirst(t *testing.T) {
	ctx := context.Background()
	s := revocationStore(t)
	exp := time.Now().Add(time.Hour)

	if err := s.Revoke(ctx, "jti-1", exp, "operator_revoke"); err != nil {
		t.Fatalf("first revoke: %v", err)
	}
	if err := s.Revoke(ctx, "jti-1", exp, "refresh_rotation"); err != nil {
		t.Fatalf("second revoke: %v", err)
	}

	rows, err := s.List(ctx, ListRevocationsParams{Limit: 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("revoking the same jti twice produced %d rows, want 1", len(rows))
	}
	if rows[0].Reason != "operator_revoke" {
		t.Errorf("reason = %q, want the first one — a later revoke overwrote the audit record of "+
			"why the token was revoked", rows[0].Reason)
	}
}

// Cleanup must drop only entries whose token has already expired. Removing a
// live revocation makes the token valid again — a revoked credential coming
// back is worse than an oversized table.
func TestRevocationStore_CleanupKeepsRevocationsForLiveTokens(t *testing.T) {
	ctx := context.Background()
	s := revocationStore(t)
	now := time.Now()

	if err := s.Revoke(ctx, "expired", now.Add(-time.Hour), "operator_revoke"); err != nil {
		t.Fatalf("revoke expired: %v", err)
	}
	if err := s.Revoke(ctx, "live", now.Add(time.Hour), "operator_revoke"); err != nil {
		t.Fatalf("revoke live: %v", err)
	}

	n, err := s.CleanupExpired(ctx, now)
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if n != 1 {
		t.Errorf("cleanup removed %d rows, want 1", n)
	}

	stillRevoked, err := s.IsRevoked(ctx, "live")
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if !stillRevoked {
		t.Error("cleanup dropped the revocation of a token that has not expired — that token is " +
			"accepted again, so a revoked credential came back to life")
	}

	// The expired one is gone, which is the point of the cleanup.
	if gone, _ := s.IsRevoked(ctx, "expired"); gone {
		t.Error("cleanup left an entry for an already-expired token")
	}
}

// Revocation has to survive the process that wrote it, or a daemon restart
// un-revokes every token — the reason this is in Postgres rather than memory.
func TestRevocationStore_SurvivesAReconnect(t *testing.T) {
	ctx := context.Background()
	s := revocationStore(t)

	if err := s.Revoke(ctx, "jti-durable", time.Now().Add(time.Hour), "operator_revoke"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// A new pool and store over the same database: a restarted daemon.
	pool2, err := pgxpool.New(ctx, os.Getenv("CONTAINARIUM_TEST_DSN"))
	if err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	defer pool2.Close()
	s2, err := NewPgRevocationStore(ctx, pool2)
	if err != nil {
		t.Fatalf("store after reconnect: %v", err)
	}

	revoked, err := s2.IsRevoked(ctx, "jti-durable")
	if err != nil {
		t.Fatalf("IsRevoked after reconnect: %v", err)
	}
	if !revoked {
		t.Error("a revocation did not survive a reconnect — a daemon restart would un-revoke " +
			"every token, which is what this store is for")
	}
}
