package pgstore

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/retention"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Anchor is the newest published anchor a purge must stay below.
type Anchor struct {
	Checkpoint int64
	Root       string
}

// AnchorFunc reads the anchor that bounds a purge. ok is false when nothing is
// anchored yet. audit.SafeAnchor is the daemon's implementation.
type AnchorFunc func(ctx context.Context) (a Anchor, ok bool, err error)

// ChainSource is the retention.PrefixSource of the hash-chained audit_logs
// (#2878, slice D of #2576; also #2420).
//
// audit_logs is one chain for every org and every class, so a purge removes a
// PREFIX only: the ids below one end id. The end is the lowest of
//
//   - the latest published anchor's checkpoint: the anchored row and everything
//     after it stay, so verify-anchor still has the row it compares;
//   - the first row not yet past its own class window (session actions use the
//     session window, every other action the gateway-logs window): rows after
//     an unexpired row cannot go, however old;
//   - the oldest row a legal hold keeps: a row of a held org, or, while any
//     hold is active, a row with no org (Q21 on #2727).
//
// Other audit actions inside the prefix are removed with it, since a prefix
// cannot skip them.
//
// The base (the last purged row's id and hash) is written in the same
// transaction as each batch of deletes, so a verifier never sees rows gone
// without the base that explains them.
type ChainSource struct {
	pool *pgxpool.Pool

	mu     sync.RWMutex
	anchor AnchorFunc
}

// NewChainSource builds the source over the daemon's database pool. Until
// SetAnchor is called it can purge nothing.
func NewChainSource(pool *pgxpool.Pool) *ChainSource { return &ChainSource{pool: pool} }

// SetAnchor wires the anchor that bounds a purge. It may be called while the
// sweeper is running.
func (c *ChainSource) SetAnchor(f AnchorFunc) {
	c.mu.Lock()
	c.anchor = f
	c.mu.Unlock()
}

func (c *ChainSource) Store() string { return "audit_logs" }

func (c *ChainSource) Classes() []pb.RetentionClass {
	return []pb.RetentionClass{
		pb.RetentionClass_RETENTION_CLASS_GATEWAY_LOGS,
		pb.RetentionClass_RETENTION_CLASS_SESSION_TRANSCRIPTS,
	}
}

// removeChainBatch is how many rows one transaction removes.
const removeChainBatch = 1000

// prefixPlan is where a purge ends and why.
type prefixPlan struct {
	// end: rows with an id below it may go. 0 means nothing.
	end int64
	// skipped: why nothing can be purged at all, such as no anchor.
	skipped string
	// note: what bounded the purge, for the report.
	note string
}

// cutoffsOf returns the gateway-logs and session-transcripts cutoffs.
func cutoffsOf(cutoffs map[pb.RetentionClass]time.Time) (gw, sess time.Time, err error) {
	gw, okG := cutoffs[pb.RetentionClass_RETENTION_CLASS_GATEWAY_LOGS]
	sess, okS := cutoffs[pb.RetentionClass_RETENTION_CLASS_SESSION_TRANSCRIPTS]
	if !okG || !okS {
		return gw, sess, errors.New("both chained classes need a cutoff")
	}
	return gw, sess, nil
}

// plan decides where the purge ends. q reads inside the caller's transaction
// when there is one, so the holds it sees are the ones the caller has locked.
func (c *ChainSource) plan(ctx context.Context, q audit.RowQuerier, cutoffs map[pb.RetentionClass]time.Time, heldOrgs []string) (prefixPlan, error) {
	gwCut, sessCut, err := cutoffsOf(cutoffs)
	if err != nil {
		return prefixPlan{}, err
	}

	c.mu.RLock()
	anchorFn := c.anchor
	c.mu.RUnlock()
	if anchorFn == nil {
		return prefixPlan{skipped: "no anchor source is wired on this daemon, so nothing can be purged"}, nil
	}
	a, ok, err := anchorFn(ctx)
	if err != nil {
		return prefixPlan{skipped: fmt.Sprintf("the anchor could not be read (%v), so nothing is purged", err)}, nil
	}
	if !ok {
		return prefixPlan{skipped: "no anchor has been published (or the external copy has none yet), so nothing can be purged"}, nil
	}

	var base int64
	if b, purged, err := audit.ReadChainBase(ctx, q); err != nil {
		return prefixPlan{}, err
	} else if purged {
		base = b.ID
	}
	if a.Checkpoint <= base+1 {
		return prefixPlan{note: fmt.Sprintf("nothing below the latest anchor (id %d) is left to purge", a.Checkpoint)}, nil
	}

	// The anchored row must still match its anchor. If it does not, a rewrite
	// is already suspected and verify-anchor needs the rows a purge would
	// delete as context: refuse.
	var rowHash string
	switch err := q.QueryRow(ctx, `SELECT row_hash FROM audit_logs WHERE id = $1`, a.Checkpoint).Scan(&rowHash); {
	case errors.Is(err, pgx.ErrNoRows):
		return prefixPlan{skipped: fmt.Sprintf("the anchored row (id %d) is not in the database; run 'containarium audit verify-anchor'. Nothing is purged", a.Checkpoint)}, nil
	case err != nil:
		return prefixPlan{}, err
	case rowHash != a.Root:
		return prefixPlan{skipped: fmt.Sprintf("the anchored row (id %d) no longer matches its anchor; run 'containarium audit verify-anchor'. Nothing is purged", a.Checkpoint)}, nil
	}

	end, bound := a.Checkpoint, fmt.Sprintf("the latest anchor (id %d)", a.Checkpoint)

	// First row not yet past its own class window.
	var firstKept *int64
	if err := q.QueryRow(ctx, `
		SELECT min(id) FROM audit_logs
		WHERE (action = ANY($1) AND timestamp >= $2)
		   OR (NOT (action = ANY($1)) AND timestamp >= $3)`,
		audit.SessionTranscriptActions, sessCut, gwCut).Scan(&firstKept); err != nil {
		return prefixPlan{}, err
	}
	if firstKept != nil && *firstKept < end {
		end, bound = *firstKept, fmt.Sprintf("the first row inside its window (id %d)", *firstKept)
	}

	// Oldest row a hold keeps.
	if len(heldOrgs) > 0 {
		var held *int64
		if err := q.QueryRow(ctx, `SELECT min(id) FROM audit_logs WHERE org_id = '' OR org_id = ANY($1)`, heldOrgs).Scan(&held); err != nil {
			return prefixPlan{}, err
		}
		if held != nil && *held < end {
			end, bound = *held, fmt.Sprintf("the oldest row a legal hold keeps (id %d; with a hold active, rows with no org count as held)", *held)
		}
	}
	return prefixPlan{end: end, note: "the purge stops below " + bound + "; other audit actions in the prefix are removed with it"}, nil
}

// CountPrefix counts without removing anything.
func (c *ChainSource) CountPrefix(ctx context.Context, cutoffs map[pb.RetentionClass]time.Time, heldOrgs []string) (retention.PrefixCount, error) {
	gwCut, sessCut, err := cutoffsOf(cutoffs)
	if err != nil {
		return retention.PrefixCount{}, err
	}
	p, err := c.plan(ctx, c.pool, cutoffs, heldOrgs)
	if err != nil {
		return retention.PrefixCount{}, wrapMissingTable("count audit_logs", err)
	}
	end := p.end
	if end == 0 {
		end = math.MinInt64 // id < end matches nothing
	}
	var olderG, olderS, eligG, eligS int64
	if err := c.pool.QueryRow(ctx, `
		SELECT
		  count(*) FILTER (WHERE NOT (action = ANY($1)) AND timestamp < $3),
		  count(*) FILTER (WHERE action = ANY($1) AND timestamp < $2),
		  count(*) FILTER (WHERE NOT (action = ANY($1)) AND id < $4),
		  count(*) FILTER (WHERE action = ANY($1) AND id < $4)
		FROM audit_logs`,
		audit.SessionTranscriptActions, sessCut, gwCut, end).Scan(&olderG, &olderS, &eligG, &eligS); err != nil {
		return retention.PrefixCount{}, wrapMissingTable("count audit_logs", err)
	}
	out := retention.PrefixCount{ByClass: map[pb.RetentionClass]retention.Count{
		pb.RetentionClass_RETENTION_CLASS_GATEWAY_LOGS:        {Older: olderG, Eligible: eligG},
		pb.RetentionClass_RETENTION_CLASS_SESSION_TRANSCRIPTS: {Older: olderS, Eligible: eligS},
	}}
	out.Note = p.note
	if p.skipped != "" {
		out.Note = "not purged: " + p.skipped
	}
	if base, purged, err := audit.ReadChainBase(ctx, c.pool); err != nil {
		return retention.PrefixCount{}, wrapMissingTable("count audit_logs", err)
	} else if purged {
		out.Base = basePB(base)
	}
	return out, nil
}

// RemovePrefix removes the prefix in batches of removeChainBatch, each in its
// own transaction that first takes a SHARE lock on retention_legal_holds, reads
// the holds under it, and re-plans: SetLegalHold inserts into that table, which
// the lock excludes, so a hold being placed either committed before the batch
// looked (and bounds it) or waits until the batch has committed. Each batch
// writes the new base in the same transaction as its deletes. lock_timeout
// bounds the wait; a timeout is an error and removes nothing more.
//
// The sweeper's snapshot of the held orgs is not used: the holds are read again
// under the lock.
func (c *ChainSource) RemovePrefix(ctx context.Context, cutoffs map[pb.RetentionClass]time.Time, _ []string, maxRows int) (retention.PrefixRemoval, error) {
	out := retention.PrefixRemoval{RemovedByClass: map[pb.RetentionClass]int64{}}
	if maxRows < 1 {
		return out, nil
	}
	var total int64
	for total < int64(maxRows) {
		if err := ctx.Err(); err != nil {
			return c.withBase(ctx, out), err
		}
		batch := int64(removeChainBatch)
		if left := int64(maxRows) - total; left < batch {
			batch = left
		}
		res, err := c.removeBatch(ctx, cutoffs, batch)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == pgUndefinedTable {
				// The holds table or the audit tables were never installed
				// here: no way to prove nothing is held, so nothing goes.
				out.Skipped = pgErr.Message
				return c.withBase(ctx, out), nil
			}
			return c.withBase(ctx, out), fmt.Errorf("purge audit_logs: %w", err)
		}
		if res.skipped != "" {
			out.Skipped = res.skipped
			return c.withBase(ctx, out), nil
		}
		out.RemovedByClass[pb.RetentionClass_RETENTION_CLASS_GATEWAY_LOGS] += res.gateway
		out.RemovedByClass[pb.RetentionClass_RETENTION_CLASS_SESSION_TRANSCRIPTS] += res.session
		total += res.gateway + res.session
		if res.gateway+res.session < batch {
			break
		}
	}
	return c.withBase(ctx, out), nil
}

// withBase attaches the current base to a removal.
func (c *ChainSource) withBase(ctx context.Context, out retention.PrefixRemoval) retention.PrefixRemoval {
	if base, purged, err := audit.ReadChainBase(ctx, c.pool); err == nil && purged {
		out.Base = basePB(base)
	}
	return out
}

type batchResult struct {
	gateway, session int64
	skipped          string
}

func (c *ChainSource) removeBatch(ctx context.Context, cutoffs map[pb.RetentionClass]time.Time, batch int64) (batchResult, error) {
	tx, err := c.pool.Begin(ctx)
	if err != nil {
		return batchResult{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout = '10s'`); err != nil {
		return batchResult{}, err
	}
	if _, err := tx.Exec(ctx, `LOCK TABLE retention_legal_holds IN SHARE MODE`); err != nil {
		return batchResult{}, err
	}
	rows, err := tx.Query(ctx, `SELECT org_id FROM retention_legal_holds ORDER BY org_id`)
	if err != nil {
		return batchResult{}, err
	}
	var held []string
	for rows.Next() {
		var org string
		if err := rows.Scan(&org); err != nil {
			rows.Close()
			return batchResult{}, err
		}
		held = append(held, org)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return batchResult{}, err
	}

	p, err := c.plan(ctx, tx, cutoffs, held)
	if err != nil {
		return batchResult{}, err
	}
	if p.skipped != "" {
		return batchResult{skipped: p.skipped}, nil
	}
	if p.end == 0 {
		return batchResult{}, nil
	}

	// The oldest `batch` rows below the end id, deleted and counted by class;
	// the last of them is the new base.
	var baseID *int64
	var baseHash *string
	var gw, sess int64
	if err := tx.QueryRow(ctx, `
		WITH picked AS (
			SELECT id, row_hash, action FROM audit_logs
			WHERE id < $1 ORDER BY id LIMIT $2 FOR UPDATE
		), gone AS (
			DELETE FROM audit_logs a USING picked p WHERE a.id = p.id RETURNING a.id
		)
		SELECT (SELECT id FROM picked ORDER BY id DESC LIMIT 1),
		       (SELECT row_hash FROM picked ORDER BY id DESC LIMIT 1),
		       count(*) FILTER (WHERE NOT (action = ANY($3))),
		       count(*) FILTER (WHERE action = ANY($3))
		FROM picked`,
		p.end, batch, audit.SessionTranscriptActions).Scan(&baseID, &baseHash, &gw, &sess); err != nil {
		return batchResult{}, err
	}
	if baseID == nil {
		return batchResult{}, nil // nothing left below the end
	}
	if err := audit.WriteChainBase(ctx, tx, *baseID, *baseHash, gw+sess); err != nil {
		return batchResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return batchResult{}, err
	}
	return batchResult{gateway: gw, session: sess}, nil
}

func basePB(b audit.ChainBase) *pb.RetentionChainBase {
	return &pb.RetentionChainBase{
		BaseId:     b.ID,
		BaseHash:   b.Hash,
		PurgedAt:   timestamppb.New(b.PurgedAt),
		RowsPurged: b.RowsPurged,
	}
}

// wrapMissingTable adds the likely cause to a missing-table error.
func wrapMissingTable(op string, err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgUndefinedTable {
		return fmt.Errorf("%s: %s (the audit store has not created its tables on this daemon)", op, pgErr.Message)
	}
	return fmt.Errorf("%s: %w", op, err)
}
