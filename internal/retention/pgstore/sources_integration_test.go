//go:build integration

// Real-Postgres coverage for the retention sources (#2876): the stores are
// created by their owning packages' constructors, rows are seeded on both
// sides of a cutoff, and the report must count exactly the older ones and
// leave every row in place.
//
//	CONTAINARIUM_TEST_DSN=postgres://... go test -tags=integration ./internal/retention/pgstore/
package pgstore_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/footprintai/containarium/internal/retention"
	"github.com/footprintai/containarium/internal/retention/pgstore"
	"github.com/footprintai/containarium/internal/server"
	"github.com/footprintai/containarium/internal/traffic"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

const sourceWindowDays = 30

// sourcesPool creates every swept table through its owner's constructor, so a
// schema change there breaks this test instead of drifting from a copy.
func sourcesPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("CONTAINARIUM_TEST_DSN")
	if dsn == "" {
		t.Fatal("CONTAINARIUM_TEST_DSN is unset. Failing rather than skipping, so a lane that " +
			"loses its database reports it instead of going quietly green.")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, `DROP TABLE IF EXISTS agent_tasks, agent_task_results, crew_runs, traffic_connections, traffic_aggregates, retention_policy, retention_windows, retention_legal_holds`); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if _, err := server.NewPostgresAgentTaskQueue(ctx, pool); err != nil {
		t.Fatalf("agent task tables: %v", err)
	}
	if _, err := server.NewPostgresCrewRunStore(ctx, pool); err != nil {
		t.Fatalf("crew_runs table: %v", err)
	}
	ts, err := traffic.NewStore(ctx, dsn)
	if err != nil {
		t.Fatalf("traffic tables: %v", err)
	}
	t.Cleanup(ts.Close)
	return pool
}

// seed puts two rows older than the window and one newer in every swept table.
func seed(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	old1, old2 := time.Now().AddDate(0, 0, -sourceWindowDays-5), time.Now().AddDate(0, 0, -sourceWindowDays-1)
	fresh := time.Now().AddDate(0, 0, -sourceWindowDays+5)
	for i, ts := range []time.Time{old1, old2, fresh} {
		id := string(rune('a' + i))
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO agent_tasks (id, skill_id, input_json, enqueued_at) VALUES ($1, 's', 'PROMPT TEXT', $2)`, []any{"t-" + id, ts}},
			{`INSERT INTO agent_task_results (id, skill_id, artifact_json, completed_at) VALUES ($1, 's', 'RESPONSE TEXT', $2)`, []any{"r-" + id, ts}},
			{`INSERT INTO crew_runs (id, run, created_at) VALUES ($1, '{}'::jsonb, $2)`, []any{"c-" + id, ts}},
			{`INSERT INTO traffic_connections (container_name, protocol, source_ip, dest_ip, direction, started_at, created_at)
			  VALUES ('box', 6, '10.0.0.1', '10.0.0.2', 1, $1, $1)`, []any{ts}},
			{`INSERT INTO traffic_aggregates (container_name, dest_ip, dest_port, interval_start, interval_end)
			  VALUES ('box', '10.0.0.2', 443, $1, $1)`, []any{ts}},
		} {
			if _, err := pool.Exec(ctx, q.sql, q.args...); err != nil {
				t.Fatalf("seed %q: %v", q.sql, err)
			}
		}
	}
}

func rowCounts(t *testing.T, pool *pgxpool.Pool) map[string]int {
	t.Helper()
	out := map[string]int{}
	for _, tbl := range []string{"agent_tasks", "agent_task_results", "crew_runs", "traffic_connections", "traffic_aggregates"} {
		var n int
		if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM `+tbl).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", tbl, err)
		}
		out[tbl] = n
	}
	return out
}

func TestSources_CountExactlyTheOlderRowsAndDeleteNothing(t *testing.T) {
	pool := sourcesPool(t)
	seed(t, pool)
	before := rowCounts(t, pool)
	cutoff := time.Now().AddDate(0, 0, -sourceWindowDays)

	srcs := pgstore.NewSources(pool)
	if len(srcs) != 6 {
		t.Fatalf("NewSources = %d sources, want 6 (agent_tasks, agent_task_results, crew_runs x2, traffic_connections, traffic_aggregates)", len(srcs))
	}
	for _, src := range srcs {
		got, err := src.Count(context.Background(), cutoff, nil)
		if err != nil {
			t.Fatalf("%v/%s: %v", src.Class(), src.Store(), err)
		}
		if got != (retention.Count{Older: 2, Eligible: 2}) {
			t.Errorf("%v/%s = %+v, want 2 older and 2 eligible of 3 rows", src.Class(), src.Store(), got)
		}
	}
	after := rowCounts(t, pool)
	for tbl, n := range before {
		if after[tbl] != n || n != 3 {
			t.Errorf("%s had %d rows before and %d after the sweep; a dry run must delete nothing", tbl, n, after[tbl])
		}
	}
}

func TestSources_AHeldOrgMakesTheUnattributedRowsIneligible(t *testing.T) {
	pool := sourcesPool(t)
	seed(t, pool)
	cutoff := time.Now().AddDate(0, 0, -sourceWindowDays)
	for _, src := range pgstore.NewSources(pool) {
		got, err := src.Count(context.Background(), cutoff, []string{"org-a"})
		if err != nil {
			t.Fatalf("%v/%s: %v", src.Class(), src.Store(), err)
		}
		if got != (retention.Count{Older: 2, Eligible: 0}) {
			t.Errorf("%v/%s with a hold = %+v, want 2 older and none eligible (rows have no org)", src.Class(), src.Store(), got)
		}
	}
}

func TestSources_AMissingTableHoldsNothing(t *testing.T) {
	pool := sourcesPool(t)
	if _, err := pool.Exec(context.Background(), `DROP TABLE traffic_aggregates`); err != nil {
		t.Fatal(err)
	}
	for _, src := range pgstore.NewSources(pool) {
		if src.Store() != "traffic_aggregates" {
			continue
		}
		got, err := src.Count(context.Background(), time.Now(), nil)
		if err != nil || got != (retention.Count{}) {
			t.Errorf("missing table = (%+v, %v), want zero and no error", got, err)
		}
	}
}

// TestSweep_ReportThroughThePostgresStore runs the whole path the daemon runs:
// the Postgres policy and holds store, the Postgres sources, the sweeper.
func TestSweep_ReportThroughThePostgresStore(t *testing.T) {
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
	sw := retention.NewSweeper(store, pgstore.NewSources(pool), nil)

	rep, err := sw.Sweep(ctx)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(rep.GetStores()) != 6 {
		t.Fatalf("report has %d stores, want 6", len(rep.GetStores()))
	}
	for _, s := range rep.GetStores() {
		if s.GetStatus() != pb.RetentionSweepStatus_RETENTION_SWEEP_STATUS_COUNTED || s.GetOlderThanCutoff() != 2 || s.GetEligible() != 2 || s.GetHeld() != 0 {
			t.Errorf("%v/%s = %v, want counted with 2 older, 2 eligible, 0 held", s.GetClass(), s.GetStore(), s)
		}
	}

	if _, err := store.SetHold(ctx, "org-a", "case 1", "admin", nil); err != nil {
		t.Fatal(err)
	}
	held, err := sw.Sweep(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range held.GetStores() {
		if s.GetEligible() != 0 || s.GetHeld() != 2 {
			t.Errorf("%v/%s with a hold = eligible %d, held %d; want 0 and 2", s.GetClass(), s.GetStore(), s.GetEligible(), s.GetHeld())
		}
	}
	for tbl, n := range rowCounts(t, pool) {
		if n != 3 {
			t.Errorf("%s has %d rows after two sweeps, want all 3", tbl, n)
		}
	}
}
