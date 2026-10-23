//go:build integration

// Real-Postgres coverage for enforcement (#2877): rows are seeded on both
// sides of a cutoff, the whole path the daemon runs (Postgres store, Postgres
// sources, sweeper) is driven in each mode, and the rows left in the tables
// are what must match.
//
//	CONTAINARIUM_TEST_DSN=postgres://... go test -tags=integration ./internal/retention/pgstore/
package pgstore_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/footprintai/containarium/internal/retention"
	"github.com/footprintai/containarium/internal/retention/pgstore"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// enforcePath is the daemon's retention path over a seeded database, with the
// three classes the swept tables use set to the test window.
func enforcePath(t *testing.T) (context.Context, *pgxpool.Pool, *pgstore.Store, *retention.Sweeper) {
	t.Helper()
	ctx := context.Background()
	pool := sourcesPool(t)
	seed(t, pool)
	store, err := pgstore.New(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetPolicy(ctx, []*pb.RetentionWindow{
		{Class: pb.RetentionClass_RETENTION_CLASS_PROMPTS, Days: sourceWindowDays},
		{Class: pb.RetentionClass_RETENTION_CLASS_RESPONSES, Days: sourceWindowDays},
		{Class: pb.RetentionClass_RETENTION_CLASS_GATEWAY_LOGS, Days: sourceWindowDays},
	}, "admin", nil); err != nil {
		t.Fatal(err)
	}
	return ctx, pool, store, retention.NewSweeper(store, pgstore.NewSources(pool), nil)
}

func setMode(t *testing.T, ctx context.Context, s *pgstore.Store, m pb.RetentionMode) {
	t.Helper()
	if _, err := s.SetMode(ctx, m, "admin", nil); err != nil {
		t.Fatalf("SetMode %v: %v", m, err)
	}
}

func wantRows(t *testing.T, pool *pgxpool.Pool, want int, why string) {
	t.Helper()
	for tbl, n := range rowCounts(t, pool) {
		if n != want {
			t.Errorf("%s has %d rows, want %d (%s)", tbl, n, want, why)
		}
	}
}

func TestEnforce_RemovesOlderRecordsKeepsNewerAndDryRunRemovesNothing(t *testing.T) {
	ctx, pool, store, sw := enforcePath(t)

	// DRY_RUN is the default: a full sweep removes nothing.
	rep, err := sw.Sweep(ctx)
	if err != nil {
		t.Fatalf("dry-run Sweep: %v", err)
	}
	if rep.GetEnforced() || rep.GetMode() != pb.RetentionMode_RETENTION_MODE_DRY_RUN {
		t.Errorf("default report = mode %v enforced %v, want DRY_RUN and not enforced", rep.GetMode(), rep.GetEnforced())
	}
	wantRows(t, pool, 3, "DRY_RUN must remove nothing")

	setMode(t, ctx, store, pb.RetentionMode_RETENTION_MODE_ENFORCE)
	rep, err = sw.Sweep(ctx)
	if err != nil {
		t.Fatalf("enforced Sweep: %v", err)
	}
	if !rep.GetEnforced() {
		t.Error("report of an ENFORCE sweep is not marked enforced")
	}
	wantRows(t, pool, 1, "the two rows past the window are gone, the newer one is kept")
	var kept int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_tasks WHERE id = 't-c'`).Scan(&kept); err != nil || kept != 1 {
		t.Errorf("the newer agent_tasks row t-c: count %d, err %v; want it kept", kept, err)
	}
	var removed int64
	for _, s := range rep.GetStores() {
		removed += s.GetRemoved()
	}
	if removed != 10 { // 2 each in 5 tables; crew_runs is removed once, not once per class
		t.Errorf("report removed %d records in all, want 10 (crew_runs once)", removed)
	}
}

func TestEnforce_AHeldOrgsRecordsSurviveAndGoOnTheNextSweepAfterRelease(t *testing.T) {
	ctx, pool, store, sw := enforcePath(t)
	setMode(t, ctx, store, pb.RetentionMode_RETENTION_MODE_ENFORCE)
	if _, err := store.SetHold(ctx, "org-a", "case 1", "admin", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := sw.Sweep(ctx); err != nil {
		t.Fatalf("held Sweep: %v", err)
	}
	wantRows(t, pool, 3, "while a hold is active no org-less record is removed (Q21 on #2727)")

	if _, err := store.ReleaseHold(ctx, "org-a", "admin", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := sw.Sweep(ctx); err != nil {
		t.Fatalf("Sweep after release: %v", err)
	}
	wantRows(t, pool, 1, "after the release the expired records go on the next enforced sweep")
}

func TestEnforce_ACrewRunUsesTheLongerOfItsTwoWindows(t *testing.T) {
	ctx := context.Background()
	pool := sourcesPool(t)
	store, err := pgstore.New(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetPolicy(ctx, []*pb.RetentionWindow{
		{Class: pb.RetentionClass_RETENTION_CLASS_PROMPTS, Days: 30},
		{Class: pb.RetentionClass_RETENTION_CLASS_RESPONSES, Days: 90},
	}, "admin", nil); err != nil {
		t.Fatal(err)
	}
	for id, age := range map[string]int{"c-20d": 20, "c-60d": 60, "c-100d": 100} {
		if _, err := pool.Exec(ctx, `INSERT INTO crew_runs (id, run, created_at) VALUES ($1, '{}'::jsonb, $2)`,
			id, time.Now().AddDate(0, 0, -age)); err != nil {
			t.Fatal(err)
		}
	}
	setMode(t, ctx, store, pb.RetentionMode_RETENTION_MODE_ENFORCE)
	if _, err := retention.NewSweeper(store, pgstore.NewSources(pool), nil).Sweep(ctx); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	rows, err := pool.Query(ctx, `SELECT id FROM crew_runs ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var left []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		left = append(left, id)
	}
	if len(left) != 2 || left[0] != "c-20d" || left[1] != "c-60d" {
		t.Errorf("crew_runs left = %v, want [c-20d c-60d]: only the row past the longer 90-day window goes", left)
	}
}

func removers(pool *pgxpool.Pool, table string) retention.Remover {
	for _, s := range pgstore.NewSources(pool) {
		if s.Store() == table {
			return s.(retention.Remover)
		}
	}
	return nil
}

func TestRemove_IsBoundedByMaxRows(t *testing.T) {
	ctx := context.Background()
	pool := sourcesPool(t)
	seed(t, pool)
	if _, err := pgstore.New(ctx, pool); err != nil { // creates the holds table Remove checks
		t.Fatal(err)
	}
	cutoff := time.Now().AddDate(0, 0, -sourceWindowDays)
	rm := removers(pool, "agent_tasks")
	n, err := rm.Remove(ctx, cutoff, nil, 1)
	if err != nil || n != 1 {
		t.Fatalf("Remove(maxRows=1) = (%d, %v), want (1, nil) of the 2 eligible", n, err)
	}
	n, err = rm.Remove(ctx, cutoff, nil, 100)
	if err != nil || n != 1 {
		t.Fatalf("Remove(maxRows=100) = (%d, %v), want the 1 remaining eligible row", n, err)
	}
	var left int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_tasks`).Scan(&left); err != nil || left != 1 {
		t.Errorf("agent_tasks has %d rows left (err %v), want only the newer one", left, err)
	}
}

// A hold placed after the sweeper read the holds must still stop the
// deletion: the hold check is part of the DELETE statement.
func TestRemove_ReChecksHoldsInTheSameStatement(t *testing.T) {
	ctx := context.Background()
	pool := sourcesPool(t)
	seed(t, pool)
	store, err := pgstore.New(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetHold(ctx, "org-a", "case 1", "admin", nil); err != nil {
		t.Fatal(err)
	}
	cutoff := time.Now().AddDate(0, 0, -sourceWindowDays)
	// The caller believes there are no holds (it read them before the hold was placed).
	for _, tbl := range []string{"agent_tasks", "agent_task_results", "crew_runs", "traffic_connections", "traffic_aggregates"} {
		if n, err := removers(pool, tbl).Remove(ctx, cutoff, nil, 100); err != nil || n != 0 {
			t.Errorf("Remove on %s = (%d, %v), want (0, nil) while a hold exists", tbl, n, err)
		}
	}
	wantRows(t, pool, 3, "a hold placed mid-sweep keeps every record")
}

// Without the holds table nothing can prove that no hold exists, so nothing is removed.
func TestRemove_WithoutTheHoldsTableRemovesNothing(t *testing.T) {
	ctx := context.Background()
	pool := sourcesPool(t)
	seed(t, pool)
	n, err := removers(pool, "agent_tasks").Remove(ctx, time.Now().AddDate(0, 0, -sourceWindowDays), nil, 100)
	if err != nil || n != 0 {
		t.Errorf("Remove with no holds table = (%d, %v), want (0, nil)", n, err)
	}
	wantRows(t, pool, 3, "no holds table, no removal")
}

func TestRemove_AMissingTableRemovesNothing(t *testing.T) {
	ctx := context.Background()
	pool := sourcesPool(t)
	if _, err := pool.Exec(ctx, `DROP TABLE traffic_aggregates`); err != nil {
		t.Fatal(err)
	}
	if n, err := removers(pool, "traffic_aggregates").Remove(ctx, time.Now(), nil, 10); err != nil || n != 0 {
		t.Errorf("Remove on a missing table = (%d, %v), want (0, nil)", n, err)
	}
}

func TestModeSurvivesARestart(t *testing.T) {
	ctx := context.Background()
	pool := sourcesPool(t)
	first, err := pgstore.New(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := first.GetMode(ctx); m.GetMode() != pb.RetentionMode_RETENTION_MODE_DRY_RUN {
		t.Fatalf("fresh database mode = %v, want DRY_RUN", m.GetMode())
	}
	setMode(t, ctx, first, pb.RetentionMode_RETENTION_MODE_ENFORCE)
	second, err := pgstore.New(ctx, pool) // a second bootstrap over the same tables
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := second.GetMode(ctx); m.GetMode() != pb.RetentionMode_RETENTION_MODE_ENFORCE || m.GetUpdatedBy() != "admin" {
		t.Errorf("mode after restart = %v, want ENFORCE by admin", m)
	}
}
