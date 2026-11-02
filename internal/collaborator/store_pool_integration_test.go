//go:build integration

package collaborator

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// #3330: after a degraded start the collaborator store is opened over the
// daemon's shared late-install pool. NewStoreOnPool creates the schema on
// that pool, the store works over it, and Close leaves the pool open,
// because the store does not own it; opening it again on the same pool (a
// retried install) is harmless.
func TestCollaboratorStore_OnSharedPool(t *testing.T) {
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
	if _, err := pool.Exec(ctx, `DROP TABLE IF EXISTS collaborators`); err != nil {
		t.Fatalf("reset: %v", err)
	}

	s, err := NewStoreOnPool(ctx, pool)
	if err != nil {
		t.Fatalf("NewStoreOnPool: %v", err)
	}
	if s.Pool() != pool {
		t.Error("store does not use the shared pool")
	}
	if _, err := NewStoreOnPool(ctx, pool); err != nil {
		t.Fatalf("second NewStoreOnPool on the same pool: %v", err)
	}
	add(t, s, "alice-container", "alice", "bob", false)
	if _, err := s.Get(ctx, "alice-container", "bob"); err != nil {
		t.Fatalf("Get after Add over the shared pool: %v", err)
	}

	s.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Errorf("shared pool closed by the store's Close: %v", err)
	}
}
