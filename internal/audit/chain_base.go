package audit

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Retention of the hash-chained audit_logs (#2878, slice D of #2576; also
// #2420).
//
// audit_logs is one global chain. A row in the middle cannot be removed
// without breaking verification of every later row, and the oldest rows cannot
// be removed without a way to start verification somewhere other than genesis.
// A retention purge therefore removes a PREFIX only, and records where the
// retained chain starts in audit_chain_base, in the same transaction as the
// delete.
//
// The base is (id, hash) of the LAST purged row. The first retained row's
// prev_hash is that hash, so verification starts from it exactly as it starts
// from HashEmpty on an unpurged chain. The base proves where verification
// starts; it does not prove why the rows before it are gone. Each purge writes
// a retention.sweep audit entry (itself in the chain, and anchored by the next
// anchor), which is the record that a purge was an authorised one.

// chainBaseSchema is run by Store.initSchema. A singleton row: only the latest
// purge matters, earlier bases are history in the audit log.
const chainBaseSchema = `
	CREATE TABLE IF NOT EXISTS audit_chain_base (
		id          SMALLINT PRIMARY KEY CHECK (id = 1),
		base_id     BIGINT NOT NULL,
		base_hash   TEXT NOT NULL,
		purged_at   TIMESTAMPTZ NOT NULL,
		rows_purged BIGINT NOT NULL CHECK (rows_purged >= 0)
	);
`

// ChainBase is where verification of the retained chain starts after a purge.
type ChainBase struct {
	// ID is the id of the last purged row; every retained row has a higher id.
	ID int64
	// Hash is that row's row_hash, the prev_hash of the first retained row.
	// It is empty when every purged row predates the chain.
	Hash string
	// PurgedAt is when the latest purge moved the base.
	PurgedAt time.Time
	// RowsPurged is the total number of rows ever purged.
	RowsPurged int64
}

// ChainBaseReader is implemented by a chain that can have been purged. The
// anchor check type-asserts for it so a chain that cannot be purged (a test
// fake, an older store) behaves exactly as before.
type ChainBaseReader interface {
	ChainBase(ctx context.Context) (ChainBase, bool, error)
}

// RowQuerier is the read side shared by *pgxpool.Pool and pgx.Tx.
type RowQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func readChainBase(ctx context.Context, q RowQuerier) (ChainBase, bool, error) {
	var b ChainBase
	err := q.QueryRow(ctx,
		`SELECT base_id, base_hash, purged_at, rows_purged FROM audit_chain_base WHERE id = 1`,
	).Scan(&b.ID, &b.Hash, &b.PurgedAt, &b.RowsPurged)
	if errors.Is(err, pgx.ErrNoRows) {
		return ChainBase{}, false, nil
	}
	if err != nil {
		return ChainBase{}, false, fmt.Errorf("audit: read chain base: %w", err)
	}
	return b, true, nil
}

// ChainBase returns the stored base, and whether a purge has ever happened.
func (s *Store) ChainBase(ctx context.Context) (ChainBase, bool, error) {
	return readChainBase(ctx, s.pool)
}

// ReadChainBase reads the base through q, a pool or the transaction that is
// about to act on it.
func ReadChainBase(ctx context.Context, q RowQuerier) (ChainBase, bool, error) {
	return readChainBase(ctx, q)
}

// WriteChainBase moves the base to (id, hash) inside tx, the transaction that
// deletes the rows before it, and adds purged to the running total. It refuses
// to move the base backwards: a base that goes down would re-trust rows that
// an earlier purge removed.
func WriteChainBase(ctx context.Context, tx pgx.Tx, id int64, hash string, purged int64) error {
	if id < 1 || purged < 1 {
		return fmt.Errorf("audit: chain base needs a row id and a purge count, got id=%d purged=%d", id, purged)
	}
	tag, err := tx.Exec(ctx, `
		INSERT INTO audit_chain_base (id, base_id, base_hash, purged_at, rows_purged)
		VALUES (1, $1, $2, now(), $3)
		ON CONFLICT (id) DO UPDATE SET
			base_id     = EXCLUDED.base_id,
			base_hash   = EXCLUDED.base_hash,
			purged_at   = EXCLUDED.purged_at,
			rows_purged = audit_chain_base.rows_purged + EXCLUDED.rows_purged
		WHERE audit_chain_base.base_id < EXCLUDED.base_id`,
		id, hash, purged)
	if err != nil {
		return fmt.Errorf("audit: write chain base: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("audit: chain base would move backwards to id=%d", id)
	}
	return nil
}

// SessionTranscriptActions are the audit_logs actions that make up the
// session-transcript retention class (SSH logins and the sentinel's session
// records). Every other action in the chain counts as gateway logs (#2878).
var SessionTranscriptActions = []string{"ssh_login", "ssh_session_open", "ssh_session_close"}
