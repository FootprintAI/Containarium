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
}

// QueryParams holds parameters for querying audit logs
type QueryParams struct {
	Username     string
	Action       string
	ResourceType string
	From         time.Time
	To           time.Time
	Limit        int
	Offset       int
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

		CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp
			ON audit_logs(timestamp DESC);
		CREATE INDEX IF NOT EXISTS idx_audit_logs_username
			ON audit_logs(username);
		CREATE INDEX IF NOT EXISTS idx_audit_logs_action
			ON audit_logs(action);
		CREATE INDEX IF NOT EXISTS idx_audit_logs_resource_type
			ON audit_logs(resource_type);
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
func (s *Store) Log(ctx context.Context, entry *AuditEntry) error {
	ts := entry.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	entry.Timestamp = ts

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("audit: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // best-effort cleanup; Commit() supersedes

	// Get prev_hash from the chain tail. FOR UPDATE serializes
	// concurrent appenders; the lock releases on Commit.
	var prevHash string
	err = tx.QueryRow(ctx,
		`SELECT row_hash FROM audit_logs ORDER BY id DESC LIMIT 1 FOR UPDATE`,
	).Scan(&prevHash)
	if err != nil {
		// First row in the table — no predecessor.
		if errors.Is(err, pgx.ErrNoRows) {
			prevHash = HashEmpty
		} else {
			return fmt.Errorf("audit: read chain tail: %w", err)
		}
	}

	rowHash := computeRowHash(entry, prevHash)

	_, err = tx.Exec(ctx, `
		INSERT INTO audit_logs (
			timestamp, username, action, resource_type, resource_id,
			detail, source_ip, status_code, row_hash, prev_hash
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`,
		ts,
		entry.Username,
		entry.Action,
		entry.ResourceType,
		entry.ResourceID,
		entry.Detail,
		entry.SourceIP,
		entry.StatusCode,
		rowHash,
		prevHash,
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
		       row_hash, prev_hash
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
			&c.RowHash, &c.PrevHash); err != nil {
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
		detail, source_ip, status_code FROM audit_logs WHERE 1=1`
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
			&e.ResourceType, &e.ResourceID, &e.Detail, &e.SourceIP, &e.StatusCode); err != nil {
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
