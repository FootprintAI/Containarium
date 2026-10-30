package sshauthz

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// A store with no HolderLookup must not revoke: skipping the holder check
// silently would bring back #3222 at any construction site that forgot it.
func TestPGKeyStore_RevokeWithoutHolderLookupErrors(t *testing.T) {
	var s PGKeyStore // zero value: no pool, no holders; must fail before touching the pool
	pub := testKey(t)
	at := time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)
	rec, err := NewKeyRecord(pub, "alice", SourceAPI, at)
	if err != nil {
		t.Fatal(err)
	}
	err = s.Revoke(context.Background(), rec, at)
	if !errors.Is(err, ErrNoHolderLookup) {
		t.Fatalf("Revoke without a HolderLookup = %v, want ErrNoHolderLookup", err)
	}
}

// The constructor refuses a nil HolderLookup, so the unsafe store cannot be built.
func TestNewPGKeyStore_RequiresHolderLookup(t *testing.T) {
	// pgxpool.New connects lazily, so this needs no database.
	pool, err := pgxpool.New(context.Background(), "postgres://unused@127.0.0.1:1/unused")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	s, err := NewPGKeyStore(context.Background(), pool, nil)
	if !errors.Is(err, ErrNoHolderLookup) || s != nil {
		t.Fatalf("NewPGKeyStore(nil holders) = (%v, %v), want (nil, ErrNoHolderLookup)", s, err)
	}
}
