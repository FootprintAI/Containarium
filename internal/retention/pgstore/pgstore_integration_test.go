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
