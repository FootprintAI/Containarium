package audit

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AuditEntry represents a single audit log record
type AuditEntry struct {
	ID           int64
	Timestamp    time.Time
	Username     string
	Action       string
	ResourceType string
	ResourceID   string
	Detail       string
	SourceIP     string
	StatusCode   int

	// #1678 — attribution columns. All default to "" (pre-migration rows
	// backfilled by ADD COLUMN, and rows written by a call site that
	// hasn't been updated to populate them).

	// Actor is the root human/service principal at the base of the
	// caller's delegation chain (auth.RootActor), distinct from Username
	// (the token's own subject — an agent's synthetic identity when the
	// call was delegated). Empty for a direct, non-delegated call, where
	// the acting entity IS Username; callers don't need to duplicate it.
	Actor string
	// DelegationChain is the JSON-serialized auth.Actor chain (empty when
	// there was no delegation), kept for full depth reconstruction beyond
	// what the flat Actor column can show.
	DelegationChain string
	// TokenID is the acting token's jti, so "what did this credential do"
	// is one query (QueryParams.TokenID).
	TokenID string
	// OrgID is tenant attribution. Empty on an OSS single-tenant daemon;
	// the cloud control plane's own audit path is out of scope here (see
	// FootprintAI/Containarium-cloud#1428).
	OrgID string
	// RunID groups a session's actions. Empty when the caller didn't
	// supply one.
	RunID string
}

// QueryParams holds parameters for querying audit logs
type QueryParams struct {
	Username     string
	Action       string
	ResourceType string
	// #1678 — attribution filters. Each is an exact-match equality filter,
	// same convention as Username/Action/ResourceType above.
	Actor   string
	TokenID string
	OrgID   string
	From    time.Time
	To      time.Time
	Limit   int
	Offset  int
}

// Store handles persistent storage of audit log entries
type Store struct {
	pool *pgxpool.Pool
}

// NewStore creates a new audit store connected to PostgreSQL
func NewStore(ctx context.Context, pool *pgxpool.Pool) (*Store, error) {
	store := &Store{pool: pool}

	if err := store.initSchema(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize audit schema: %w", err)
	}

	return store, nil
}

// initSchema creates the database schema if it doesn't exist.
//
// Phase 4.5: row_hash + prev_hash columns implement the
// tamper-evidence chain. Added with ADD COLUMN IF NOT EXISTS so
// the upgrade is non-destructive — pre-existing rows have NULL
// hashes and the verifier treats them as "before chain was
// enabled" (skipped from the chain head).
func (s *Store) initSchema(ctx context.Context) error {
	schema := `
		CREATE TABLE IF NOT EXISTS audit_logs (
			id BIGSERIAL PRIMARY KEY,
			timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			username TEXT NOT NULL DEFAULT '',
			action TEXT NOT NULL,
			resource_type TEXT NOT NULL DEFAULT '',
			resource_id TEXT NOT NULL DEFAULT '',
			detail TEXT NOT NULL DEFAULT '',
			source_ip TEXT NOT NULL DEFAULT '',
			status_code INTEGER NOT NULL DEFAULT 0
		);

		ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS row_hash TEXT NOT NULL DEFAULT '';
		ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS prev_hash TEXT NOT NULL DEFAULT '';

		-- #1678: attribution columns. hash_version defaults every
		-- pre-existing row to HashVersion1 (Postgres applies a column
		-- DEFAULT to existing rows in place on ADD COLUMN) — Log() always
		-- writes CurrentHashVersion (HashVersion2) going forward, so
		-- VerifyChain can tell old rows from new ones without a separate
		-- migration script.
		ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS actor TEXT NOT NULL DEFAULT '';
		ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS delegation_chain TEXT NOT NULL DEFAULT '';
		ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS token_id TEXT NOT NULL DEFAULT '';
		ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS org_id TEXT NOT NULL DEFAULT '';
		ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS run_id TEXT NOT NULL DEFAULT '';
		ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS hash_version SMALLINT NOT NULL DEFAULT 1;

		CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp
			ON audit_logs(timestamp DESC);
		CREATE INDEX IF NOT EXISTS idx_audit_logs_username
			ON audit_logs(username);
		CREATE INDEX IF NOT EXISTS idx_audit_logs_action
			ON audit_logs(action);
		CREATE INDEX IF NOT EXISTS idx_audit_logs_resource_type
			ON audit_logs(resource_type);
		CREATE INDEX IF NOT EXISTS idx_audit_logs_actor
			ON audit_logs(actor);
		CREATE INDEX IF NOT EXISTS idx_audit_logs_token_id
			ON audit_logs(token_id);
		CREATE INDEX IF NOT EXISTS idx_audit_logs_org_id
			ON audit_logs(org_id);
	`

	_, err := s.pool.Exec(ctx, schema)
	return err
}

// Log inserts a single audit log entry.
//
// Phase 4.5: each insert reads the latest row's row_hash inside
// a transaction, computes the new row's hash from its content
// plus that prev_hash, and writes both. SELECT FOR UPDATE on
// the tail row serializes concurrent writers so the chain
// stays well-ordered. Without the lock, two concurrent inserts
// could both reference the same prev_hash and produce a fork.
// auditChainLockKey is the advisory-lock key appends serialize on. An
// arbitrary constant; it only has to be unique among this database's advisory
// locks.
const auditChainLockKey int64 = 0x0A0D17C4A1

// defaultVerifyBatch mirrors VerifyChainSinceID's own internal default
// (limit<=0 -> 1000) — used by VerifyChainAgainstAnchor to advance fromID
// across multiple calls the same way the CLI's runAuditVerify loops.
const defaultVerifyBatch = 1000

func (s *Store) Log(ctx context.Context, entry *AuditEntry) error {
	ts := entry.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	// Truncate to what Postgres can store before hashing.
	//
	// computeRowHash feeds Timestamp.UnixNano() into the digest, and the
	// column is `timestamp with time zone` — microsecond precision. So a
	// nanosecond-precision time hashed here comes back truncated, the
	// recomputed hash differs, and VerifyChainSinceID reports the row as
	// modified. Every row, always: the chain could never verify, so the
	// tamper-evidence it exists for could not distinguish a tampered log
	// from an intact one.
	//
	// Truncating first makes the hashed value identical to the stored one.
	ts = ts.Truncate(time.Microsecond)
	entry.Timestamp = ts

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("audit: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // best-effort cleanup; Commit() supersedes

	// Serialize appenders on the chain itself.
	//
	// `SELECT ... ORDER BY id DESC LIMIT 1 FOR UPDATE` does not do this,
	// though it reads as if it should. It locks the row that is the tail
	// *now*; it cannot lock a row that does not exist yet. Two transactions
	// therefore both read tail N, both insert, and both claim N as
	// predecessor — a fork. On an empty table it is worse: there is no row to
	// lock at all, so every concurrent first write claims genesis.
	//
	// An advisory lock has no such gap: it is taken on a constant, not on a
	// row, so it serializes writers regardless of what the table contains.
	// It releases on commit or rollback with the transaction.
	//
	// This serializes all audit appends against each other. That is the point
	// — a hash chain is inherently sequential, and a chain that forks under
	// load is not tamper-evident, only tamper-suggestive.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, auditChainLockKey); err != nil {
		return fmt.Errorf("audit: lock chain: %w", err)
	}

	// Get prev_hash from the chain tail.
	var prevHash string
	err = tx.QueryRow(ctx,
		`SELECT row_hash FROM audit_logs ORDER BY id DESC LIMIT 1`,
	).Scan(&prevHash)
	if err != nil {
		// First row in the table — no predecessor.
		if errors.Is(err, pgx.ErrNoRows) {
			prevHash = HashEmpty
		} else {
			return fmt.Errorf("audit: read chain tail: %w", err)
		}
	}

	// #1678 — every newly-written row uses CurrentHashVersion; a row's
	// hash_version is what VerifyChain later replays it under, so old
	// rows (backfilled to HashVersion1 by initSchema's column default)
	// stay verifiable without this write path ever touching them.
	rowHash, err := computeRowHash(entry, prevHash, CurrentHashVersion)
	if err != nil {
		return fmt.Errorf("audit: compute hash: %w", err)
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO audit_logs (
			timestamp, username, action, resource_type, resource_id,
			detail, source_ip, status_code, actor, delegation_chain,
			token_id, org_id, run_id, row_hash, prev_hash, hash_version
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
	`,
		ts,
		entry.Username,
		entry.Action,
		entry.ResourceType,
		entry.ResourceID,
		entry.Detail,
		entry.SourceIP,
		entry.StatusCode,
		entry.Actor,
		entry.DelegationChain,
		entry.TokenID,
		entry.OrgID,
		entry.RunID,
		rowHash,
		prevHash,
		CurrentHashVersion,
	)
	if err != nil {
		return fmt.Errorf("audit: insert: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("audit: commit: %w", err)
	}
	return nil
}

// MaxRowID returns the highest id currently in
// audit_logs, or 0 if the table is empty. Used by the
// audit-verify CLI to detect "scanned to the end" without
// the Store API needing to surface a per-batch terminator.
//
// Cheap on a B-tree primary key — Postgres reads the last
// page directly.
func (s *Store) MaxRowID(ctx context.Context) (int64, error) {
	var max *int64
	if err := s.pool.QueryRow(ctx, `SELECT MAX(id) FROM audit_logs`).Scan(&max); err != nil {
		return 0, fmt.Errorf("audit: max row id: %w", err)
	}
	if max == nil {
		return 0, nil
	}
	return *max, nil
}

// VerifyChainSinceID walks the hash chain forward from
// `fromID` (exclusive) and returns the ID of the first row that
// fails verification, or 0 if the chain is intact. Pass 0 to
// verify from the chain start.
//
// The function reads up to `limit` rows in one pass — callers
// verifying long ranges should loop, passing the last verified
// ID back in as the next fromID, so memory stays bounded.
func (s *Store) VerifyChainSinceID(ctx context.Context, fromID int64, limit int) (firstBad int64, err error) {
	if limit <= 0 {
		limit = 1000
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, timestamp, username, action, resource_type,
		       resource_id, detail, source_ip, status_code,
		       actor, delegation_chain, token_id, org_id, run_id,
		       row_hash, prev_hash, hash_version
		FROM audit_logs
		WHERE id > $1 AND row_hash <> ''
		ORDER BY id ASC
		LIMIT $2
	`, fromID, limit)
	if err != nil {
		return -1, fmt.Errorf("audit: query chain: %w", err)
	}
	defer rows.Close()

	var entries []ChainEntry
	for rows.Next() {
		var c ChainEntry
		if err := rows.Scan(&c.ID, &c.Timestamp, &c.Username, &c.Action,
			&c.ResourceType, &c.ResourceID, &c.Detail, &c.SourceIP, &c.StatusCode,
			&c.Actor, &c.DelegationChain, &c.TokenID, &c.OrgID, &c.RunID,
			&c.RowHash, &c.PrevHash, &c.HashVersion); err != nil {
			return -1, fmt.Errorf("audit: scan chain row: %w", err)
		}
		entries = append(entries, c)
	}
	if err := rows.Err(); err != nil {
		return -1, fmt.Errorf("audit: iterate chain rows: %w", err)
	}
	if len(entries) == 0 {
		return 0, nil // empty range
	}

	// The expected prev_hash for the first row in this batch is
	// whatever its stored prev_hash claims to be — we can't
	// reach back beyond the WHERE without an extra query. The
	// VerifyChain helper compares prev_hash to the value passed
	// in. For a fromID=0 verification, the first row's
	// prev_hash should be HashEmpty.
	expectedRoot := entries[0].PrevHash
	if fromID == 0 {
		expectedRoot = HashEmpty
	}
	return VerifyChain(entries, expectedRoot)
}

// Query retrieves audit log entries with optional filters and pagination
func (s *Store) Query(ctx context.Context, params QueryParams) ([]AuditEntry, int32, error) {
	baseQuery := `SELECT id, timestamp, username, action, resource_type, resource_id,
		detail, source_ip, status_code, actor, delegation_chain, token_id, org_id, run_id
		FROM audit_logs WHERE 1=1`
	countQuery := `SELECT COUNT(*) FROM audit_logs WHERE 1=1`

	var args []interface{}
	argIdx := 1

	if params.Username != "" {
		baseQuery += fmt.Sprintf(" AND username = $%d", argIdx)
		countQuery += fmt.Sprintf(" AND username = $%d", argIdx)
		args = append(args, params.Username)
		argIdx++
	}

	if params.Action != "" {
		baseQuery += fmt.Sprintf(" AND action = $%d", argIdx)
		countQuery += fmt.Sprintf(" AND action = $%d", argIdx)
		args = append(args, params.Action)
		argIdx++
	}

	if params.ResourceType != "" {
		baseQuery += fmt.Sprintf(" AND resource_type = $%d", argIdx)
		countQuery += fmt.Sprintf(" AND resource_type = $%d", argIdx)
		args = append(args, params.ResourceType)
		argIdx++
	}

	// #1678 — attribution filters, same exact-match convention as above.
	if params.Actor != "" {
		baseQuery += fmt.Sprintf(" AND actor = $%d", argIdx)
		countQuery += fmt.Sprintf(" AND actor = $%d", argIdx)
		args = append(args, params.Actor)
		argIdx++
	}

	if params.TokenID != "" {
		baseQuery += fmt.Sprintf(" AND token_id = $%d", argIdx)
		countQuery += fmt.Sprintf(" AND token_id = $%d", argIdx)
		args = append(args, params.TokenID)
		argIdx++
	}

	if params.OrgID != "" {
		baseQuery += fmt.Sprintf(" AND org_id = $%d", argIdx)
		countQuery += fmt.Sprintf(" AND org_id = $%d", argIdx)
		args = append(args, params.OrgID)
		argIdx++
	}

	if !params.From.IsZero() {
		baseQuery += fmt.Sprintf(" AND timestamp >= $%d", argIdx)
		countQuery += fmt.Sprintf(" AND timestamp >= $%d", argIdx)
		args = append(args, params.From)
		argIdx++
	}

	if !params.To.IsZero() {
		baseQuery += fmt.Sprintf(" AND timestamp <= $%d", argIdx)
		countQuery += fmt.Sprintf(" AND timestamp <= $%d", argIdx)
		args = append(args, params.To)
		argIdx++
	}

	// Get total count
	var totalCount int32
	err := s.pool.QueryRow(ctx, countQuery, args...).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count audit logs: %w", err)
	}

	// Apply pagination
	limit := params.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}

	baseQuery += fmt.Sprintf(" ORDER BY timestamp DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, limit, params.Offset)

	rows, err := s.pool.Query(ctx, baseQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query audit logs: %w", err)
	}
	defer rows.Close()

	var entries []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.Username, &e.Action,
			&e.ResourceType, &e.ResourceID, &e.Detail, &e.SourceIP, &e.StatusCode,
			&e.Actor, &e.DelegationChain, &e.TokenID, &e.OrgID, &e.RunID); err != nil {
			return nil, 0, fmt.Errorf("failed to scan audit row: %w", err)
		}
		entries = append(entries, e)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating audit rows: %w", err)
	}

	return entries, totalCount, nil
}

// Close closes the underlying connection pool
func (s *Store) Close() {
	s.pool.Close()
}

// RowHashAt returns the row_hash stored at audit-log row id, and whether
// that row exists. found=false (rather than an error) is the expected,
// meaningful outcome when the row has been deleted — a fact
// VerifyChainAgainstAnchor treats as evidence of tampering, not a failure
// to report as "unknown."
func (s *Store) RowHashAt(ctx context.Context, id int64) (hash string, found bool, err error) {
	err = s.pool.QueryRow(ctx, `SELECT row_hash FROM audit_logs WHERE id = $1`, id).Scan(&hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("audit: row hash at id=%d: %w", id, err)
	}
	return hash, true, nil
}

// AnchorVerifyResult is VerifyChainAgainstAnchor's outcome. Two independent
// checks, because they catch two different attacks (#1706):
//
//   - AnchorRoot vs CurrentRoot: was the row AT the anchored checkpoint (or
//     anything before it) rewritten since it was anchored? Internal chain
//     consistency alone cannot see this — a rewrite followed by a correct
//     recompute forward preserves internal consistency by construction.
//     Only a hash held outside the database can catch it.
//   - FirstBadAfterCheckpoint: is everything AFTER the checkpoint still
//     internally consistent? A break here means tampering since the last
//     anchor that was NOT (or not yet) followed by a correct recompute —
//     the ordinary hash_chain.go case, just scoped to the post-anchor tail.
type AnchorVerifyResult struct {
	// Checkpoint is the anchored row id this result was checked against.
	Checkpoint int64
	// AnchorRoot is the externally-anchored hash at Checkpoint.
	AnchorRoot string
	// CurrentRoot is what's in the database at Checkpoint right now.
	// Empty means the row no longer exists (deleted) — also a mismatch.
	CurrentRoot string
	// FirstBadAfterCheckpoint is VerifyChainSinceID's result for rows after
	// Checkpoint: 0 if intact, otherwise the first bad row's id.
	FirstBadAfterCheckpoint int64
}

// OK reports whether both halves of the result are clean.
func (r AnchorVerifyResult) OK() bool {
	return r.AnchorRoot == r.CurrentRoot && r.FirstBadAfterCheckpoint == 0
}

// ErrNoAnchor is returned by VerifyChainAgainstAnchor when sink has never
// had a root published to it. Not a chain-integrity failure — there is
// simply nothing yet to check against.
var ErrNoAnchor = errors.New("audit: no anchor has been published yet")

// VerifyChainAgainstAnchor checks the chain against the last root sink
// published, catching a privileged rewrite-and-recompute that internal
// consistency (VerifyChain / VerifyChainSinceID) cannot: see
// AnchorVerifyResult's doc comment for why both checks are needed.
func (s *Store) VerifyChainAgainstAnchor(ctx context.Context, sink RootSink) (AnchorVerifyResult, error) {
	checkpoint, anchorRoot, ok, err := sink.LastPublished(ctx)
	if err != nil {
		return AnchorVerifyResult{}, fmt.Errorf("audit: read last anchor: %w", err)
	}
	if !ok {
		return AnchorVerifyResult{}, ErrNoAnchor
	}
	currentRoot, _, err := s.RowHashAt(ctx, checkpoint)
	if err != nil {
		return AnchorVerifyResult{}, fmt.Errorf("audit: row hash at anchored checkpoint %d: %w", checkpoint, err)
	}

	// VerifyChainSinceID caps a single call at `limit` rows (default 1000)
	// to keep memory bounded — the same reason runAuditVerify (CLI) loops
	// rather than trusting one call to cover an arbitrary range. Mirrored
	// here so a chain with many rows logged since the last anchor is still
	// checked in full, not just its first 1000 post-checkpoint rows.
	maxID, err := s.MaxRowID(ctx)
	if err != nil {
		return AnchorVerifyResult{}, fmt.Errorf("audit: max row id: %w", err)
	}
	var firstBad int64
	for from := checkpoint; from < maxID; {
		firstBad, err = s.VerifyChainSinceID(ctx, from, 0)
		if err != nil {
			return AnchorVerifyResult{}, fmt.Errorf("audit: verify chain since checkpoint %d: %w", checkpoint, err)
		}
		if firstBad != 0 {
			break
		}
		from += defaultVerifyBatch
	}
	return AnchorVerifyResult{
		Checkpoint:              checkpoint,
		AnchorRoot:              anchorRoot,
		CurrentRoot:             currentRoot,
		FirstBadAfterCheckpoint: firstBad,
	}, nil
}
