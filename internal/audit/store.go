package audit

import (
	"context"
	"fmt"
	"time"

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

// initSchema creates the database schema if it doesn't exist
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

// Log inserts a single audit log entry
func (s *Store) Log(ctx context.Context, entry *AuditEntry) error {
	query := `
		INSERT INTO audit_logs (
			timestamp, username, action, resource_type, resource_id,
			detail, source_ip, status_code
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`

	ts := entry.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}

	_, err := s.pool.Exec(ctx, query,
		ts,
		entry.Username,
		entry.Action,
		entry.ResourceType,
		entry.ResourceID,
		entry.Detail,
		entry.SourceIP,
		entry.StatusCode,
	)
	if err != nil {
		return fmt.Errorf("failed to insert audit log: %w", err)
	}

	return nil
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
