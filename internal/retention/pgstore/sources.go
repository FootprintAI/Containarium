package pgstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/footprintai/containarium/internal/retention"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// pgUndefinedTable is the SQLSTATE of a query on a table that does not exist.
const pgUndefinedTable = "42P01"

// removeBatch is how many rows one DELETE statement removes, so no statement
// holds locks on more than this many rows.
const removeBatch = 1000

// tableSource counts the rows of one table older than its age column, and
// removes them. None of the swept tables carries an org, so every count goes
// through retention.Unattributed and every removal is refused while any legal
// hold exists. Count runs a SELECT and nothing else.
type tableSource struct {
	pool      *pgxpool.Pool
	class     pb.RetentionClass
	table     string
	ageColumn string
}

func (s *tableSource) Class() pb.RetentionClass { return s.class }
func (s *tableSource) Store() string            { return s.table }

func (s *tableSource) Count(ctx context.Context, cutoff time.Time, heldOrgs []string) (retention.Count, error) {
	var older int64
	// table and ageColumn are constants of this file, never request input.
	q := fmt.Sprintf(`SELECT count(*) FROM %s WHERE %s < $1`, s.table, s.ageColumn)
	if err := s.pool.QueryRow(ctx, q, cutoff).Scan(&older); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgUndefinedTable {
			// The owning store was never installed here, so it holds nothing.
			return retention.Count{}, nil
		}
		return retention.Count{}, fmt.Errorf("count %s: %w", s.table, err)
	}
	return retention.Unattributed(older, heldOrgs), nil
}

// sweptTables are the stores outside the hash chain (#2876). A crew run keeps
// a prompt and a response in one row, so crew_runs is listed once per class,
// each against its own window. The age columns of the traffic tables are the
// ones the daily traffic cleanup deletes by.
var sweptTables = []struct {
	class     pb.RetentionClass
	table     string
	ageColumn string
}{
	{pb.RetentionClass_RETENTION_CLASS_PROMPTS, "agent_tasks", "enqueued_at"},
	{pb.RetentionClass_RETENTION_CLASS_RESPONSES, "agent_task_results", "completed_at"},
	{pb.RetentionClass_RETENTION_CLASS_PROMPTS, "crew_runs", "created_at"},
	{pb.RetentionClass_RETENTION_CLASS_RESPONSES, "crew_runs", "created_at"},
	{pb.RetentionClass_RETENTION_CLASS_GATEWAY_LOGS, "traffic_connections", "created_at"},
	{pb.RetentionClass_RETENTION_CLASS_GATEWAY_LOGS, "traffic_aggregates", "interval_start"},
}

// NewSources returns the dry-run sources for the stores outside the hash
// chain.
func NewSources(pool *pgxpool.Pool) []retention.Source {
	out := make([]retention.Source, len(sweptTables))
	for i, t := range sweptTables {
		out[i] = &tableSource{pool: pool, class: t.class, table: t.table, ageColumn: t.ageColumn}
	}
	return out
}

// NoDatabase lists the same stores as not swept, for a daemon with no
// database pool.
func NoDatabase() []retention.Unswept {
	out := make([]retention.Unswept, len(sweptTables))
	for i, t := range sweptTables {
		out[i] = retention.Unswept{Class: t.class, Store: t.table,
			Note: "no database connection on this daemon, so nothing is counted"}
	}
	return out
}

// Remove deletes the rows Count lists as eligible, at most maxRows, in batches
// of removeBatch. The predicate is Count's (age column before the cutoff), and
// the DELETE carries it itself, so no statement can touch a newer row. The
// rows have no org, so while any legal hold exists nothing is removed (Q21 on
// #2727). A caller's list of held orgs is only the fast path: each batch runs
// in its own transaction that first takes a SHARE lock on retention_legal_holds
// and then DELETEs with a NOT EXISTS on that table. SetLegalHold inserts into
// the table, which the SHARE lock excludes, so a hold being placed either
// committed before the batch looked (and stops it) or waits until the batch
// has committed (and then protects what is left). Waiting is bounded by
// lock_timeout; a timeout is an error and removes nothing more.
func (s *tableSource) Remove(ctx context.Context, cutoff time.Time, heldOrgs []string, maxRows int) (retention.Removal, error) {
	if len(heldOrgs) > 0 || maxRows < 1 {
		return retention.Removal{}, nil
	}
	// table and ageColumn are constants of this file, never request input.
	q := fmt.Sprintf(`DELETE FROM %[1]s
		WHERE %[2]s < $1
		  AND NOT EXISTS (SELECT 1 FROM retention_legal_holds)
		  AND ctid = ANY(ARRAY(SELECT ctid FROM %[1]s WHERE %[2]s < $1 LIMIT $2 FOR UPDATE SKIP LOCKED))`,
		s.table, s.ageColumn)
	var total int64
	for total < int64(maxRows) {
		if err := ctx.Err(); err != nil {
			return retention.Removal{Removed: total}, err
		}
		batch := int64(removeBatch)
		if left := int64(maxRows) - total; left < batch {
			batch = left
		}
		n, err := s.removeBatch(ctx, q, cutoff, batch)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == pgUndefinedTable {
				// The swept table, or the holds table, was never installed
				// here: nothing to remove, or no way to prove nothing is held.
				return retention.Removal{Removed: total, Skipped: pgErr.Message}, nil
			}
			return retention.Removal{Removed: total}, fmt.Errorf("remove from %s: %w", s.table, err)
		}
		total += n
		if n < batch {
			break
		}
	}
	return retention.Removal{Removed: total}, nil
}

// removeBatch runs one locked DELETE and returns the rows it removed.
func (s *tableSource) removeBatch(ctx context.Context, q string, cutoff time.Time, batch int64) (int64, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout = '10s'`); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `LOCK TABLE retention_legal_holds IN SHARE MODE`); err != nil {
		return 0, err
	}
	tag, err := tx.Exec(ctx, q, cutoff, batch)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
