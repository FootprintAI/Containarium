//go:build integration

// #3365 against a real Postgres: owner cutoffs recorded in memory while the
// revocation list was pending are in the durable table after the late
// install, the latest cutoff per owner wins, and they survive a restart.
//
//	CONTAINARIUM_TEST_DSN=postgres://... go test -tags=integration ./internal/server/
package server

import (
	"context"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/auth"
)

func TestGatewayRevocationRecovery_PostgresCarryOverKeepsLatestPerOwner(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	if _, err := pool.Exec(ctx, `DROP TABLE IF EXISTS gateway_owner_revocations`); err != nil {
		t.Fatalf("reset: %v", err)
	}
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

	// Before the outage: bob's key was removed at t0+1h, carol's at t0.
	before, err := auth.NewPgOwnerRevocationStore(ctx, pool)
	if err != nil {
		t.Fatalf("NewPgOwnerRevocationStore: %v", err)
	}
	for owner, at := range map[string]time.Time{"user:bob": t0.Add(time.Hour), "user:carol": t0} {
		if err := before.RevokeOwner(ctx, owner, at, "before the outage"); err != nil {
			t.Fatalf("seed %s: %v", owner, err)
		}
	}

	// The window: cutoffs land in memory only.
	gr := newGatewayRevocations(openOwnerRevocationStore)
	for owner, at := range map[string]time.Time{
		"user:alice": t0.Add(2 * time.Hour), // new owner
		"user:bob":   t0,                    // earlier than Postgres: must not narrow
		"user:carol": t0.Add(3 * time.Hour), // later than Postgres: wins
	} {
		if err := gr.owners.RevokeOwner(ctx, owner, at, "during the window"); err != nil {
			t.Fatalf("RevokeOwner(%s) during the window: %v", owner, err)
		}
	}

	jti, err := openRevocationStore(ctx, pool)
	if err != nil {
		t.Fatalf("openRevocationStore: %v", err)
	}
	n, err := gr.install(ctx, pool, jti)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if n != 3 {
		t.Errorf("carried %d cutoffs, want 3", n)
	}

	// A restart: a fresh store on the same table sees the merged result.
	after, err := auth.NewPgOwnerRevocationStore(ctx, pool)
	if err != nil {
		t.Fatalf("NewPgOwnerRevocationStore after install: %v", err)
	}
	want := map[string]time.Time{
		"user:alice": t0.Add(2 * time.Hour),
		"user:bob":   t0.Add(time.Hour),
		"user:carol": t0.Add(3 * time.Hour),
	}
	for owner, w := range want {
		got, err := after.RevokedBefore(ctx, owner)
		if err != nil || !got.Equal(w) {
			t.Errorf("durable cutoff for %s = %v, %v; want %v", owner, got, err, w)
		}
		live, err := gr.owners.RevokedBefore(ctx, owner)
		if err != nil || !live.Equal(w) {
			t.Errorf("gateway cutoff for %s after install = %v, %v; want %v", owner, live, err, w)
		}
	}
}
