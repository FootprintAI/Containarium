//go:build integration

// Postgres coverage for the retention store (#2875). The in-memory store runs
// the same contract in the unit suite; this file adds what only a database
// shows: the policy and holds survive a restart (a second bootstrap over the
// same tables), and concurrent sets get distinct revisions.
//
//	CONTAINARIUM_TEST_DSN=postgres://... go test -tags=integration ./internal/retention/pgstore/
package pgstore

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/footprintai/containarium/internal/retention"
	"github.com/footprintai/containarium/internal/retention/storetest"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func retentionPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("CONTAINARIUM_TEST_DSN")
	if dsn == "" {
		t.Fatal("CONTAINARIUM_TEST_DSN is unset. Failing rather than skipping, so a lane that " +
			"loses its database reports it instead of going quietly green.")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(context.Background(), `DROP TABLE IF EXISTS retention_policy, retention_windows, retention_legal_holds`); err != nil {
		t.Fatalf("reset: %v", err)
	}
	return pool
}

func pgStore(t *testing.T, pool *pgxpool.Pool) *Store {
	t.Helper()
	s, err := New(context.Background(), pool)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func TestRetentionPGStore_Contract(t *testing.T) {
	storetest.RunStoreContract(t, func(t *testing.T) retention.Store { return pgStore(t, retentionPool(t)) })
}

func TestRetentionPGStore_SurvivesRestart(t *testing.T) {
	ctx := context.Background()
	pool := retentionPool(t)
	first := pgStore(t, pool)
	if _, err := first.SetPolicy(ctx, []*pb.RetentionWindow{{Class: pb.RetentionClass_RETENTION_CLASS_PROMPTS, Days: 7}}, "admin-a", nil); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}
	if _, err := first.SetHold(ctx, "org-a", "case 1", "admin-a", nil); err != nil {
		t.Fatalf("SetHold: %v", err)
	}
	restarted := pgStore(t, pool)
	p, err := restarted.GetPolicy(ctx)
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if p.GetRevision() != 1 || p.GetWindows()[0].GetDays() != 7 || p.GetWindows()[0].GetIsDefault() {
		t.Fatalf("policy after restart = %v, want revision 1 with prompts 7", p)
	}
	hs, err := restarted.ListHolds(ctx)
	if err != nil || len(hs) != 1 || hs[0].GetOrgId() != "org-a" {
		t.Fatalf("holds after restart = (%v, %v), want org-a", hs, err)
	}
}

// TestRetentionPGStore_DaysCapIsADatabaseCheck: the cap holds even for a
// write that bypasses the store's validation, including on a table created
// before the cap existed (the bootstrap adds the constraint to it).
func TestRetentionPGStore_DaysCapIsADatabaseCheck(t *testing.T) {
	ctx := context.Background()
	pool := retentionPool(t)
	// The schema exactly as the store merged in #2917 created it (no upper
	// bound), with a policy already stored, as on a deployed daemon.
	if _, err := pool.Exec(ctx, `
		CREATE TABLE retention_policy (
			id         SMALLINT PRIMARY KEY CHECK (id = 1),
			revision   BIGINT NOT NULL DEFAULT 0,
			updated_at TIMESTAMPTZ,
			updated_by TEXT NOT NULL DEFAULT ''
		);
		INSERT INTO retention_policy (id, revision, updated_at, updated_by) VALUES (1, 1, NOW(), 'admin-a');
		CREATE TABLE retention_windows (
			class INTEGER PRIMARY KEY,
			days  INTEGER NOT NULL CHECK (days > 0)
		);
		INSERT INTO retention_windows (class, days) VALUES (2, 45);
		CREATE TABLE retention_legal_holds (
			org_id TEXT PRIMARY KEY,
			reason TEXT NOT NULL,
			set_by TEXT NOT NULL,
			set_at TIMESTAMPTZ NOT NULL
		);
		INSERT INTO retention_legal_holds VALUES ('org-a', 'case 1', 'admin-a', NOW());
	`); err != nil {
		t.Fatalf("create the merged schema: %v", err)
	}
	pgStore(t, pool)
	s := pgStore(t, pool) // a second bootstrap is a no-op, not a duplicate-constraint error
	p, err := s.GetPolicy(ctx)
	if err != nil {
		t.Fatalf("GetPolicy after the migration: %v", err)
	}
	if p.GetRevision() != 1 || p.GetWindows()[1].GetDays() != 45 || p.GetWindows()[1].GetIsDefault() {
		t.Fatalf("policy after the migration = %v, want revision 1 with responses 45 kept", p)
	}
	if hs, err := s.ListHolds(ctx); err != nil || len(hs) != 1 || hs[0].GetOrgId() != "org-a" {
		t.Fatalf("holds after the migration = (%v, %v), want org-a kept", hs, err)
	}
	insert := func(days int32) error {
		_, err := pool.Exec(ctx, `INSERT INTO retention_windows (class, days) VALUES (1, $1)
			ON CONFLICT (class) DO UPDATE SET days = EXCLUDED.days`, days)
		return err
	}
	if err := insert(retention.MaxDays); err != nil {
		t.Fatalf("insert %d days: %v", retention.MaxDays, err)
	}
	if err := insert(retention.MaxDays + 1); err == nil {
		t.Fatalf("insert %d days succeeded; the CHECK is missing", retention.MaxDays+1)
	}
}

func TestRetentionPGStore_ConcurrentSetsGetDistinctRevisions(t *testing.T) {
	ctx := context.Background()
	s := pgStore(t, retentionPool(t))
	const n = 8
	revs := make(chan int64, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res, err := s.SetPolicy(ctx, []*pb.RetentionWindow{{Class: pb.RetentionClass_RETENTION_CLASS_RESPONSES, Days: int32(10 + i)}}, "admin-a", nil)
			if err != nil {
				t.Errorf("SetPolicy: %v", err)
				return
			}
			revs <- res.Current.GetRevision()
		}(i)
	}
	wg.Wait()
	close(revs)
	seen := map[int64]bool{}
	for r := range revs {
		if seen[r] {
			t.Fatalf("revision %d issued twice", r)
		}
		seen[r] = true
	}
	if p, _ := s.GetPolicy(ctx); p.GetRevision() != n {
		t.Fatalf("final revision = %d, want %d", p.GetRevision(), n)
	}
}
