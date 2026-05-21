package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PgRevocationStore is the Postgres-backed implementation of
// RevocationStore. Single table, single index on expires_at
// for cleanup, primary key on jti for the hot-path lookup.
type PgRevocationStore struct {
	pool *pgxpool.Pool
}

// NewPgRevocationStore creates the store and ensures the
// schema is in place. ADD COLUMN IF NOT EXISTS would be
// non-destructive on existing deployments — the table itself
// uses CREATE TABLE IF NOT EXISTS.
func NewPgRevocationStore(ctx context.Context, pool *pgxpool.Pool) (*PgRevocationStore, error) {
	s := &PgRevocationStore{pool: pool}
	if err := s.initSchema(ctx); err != nil {
		return nil, fmt.Errorf("revocation store: init schema: %w", err)
	}
	return s, nil
}

func (s *PgRevocationStore) initSchema(ctx context.Context) error {
	schema := `
		CREATE TABLE IF NOT EXISTS jwt_revocations (
			jti         TEXT PRIMARY KEY,
			expires_at  TIMESTAMPTZ NOT NULL,
			revoked_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			reason      TEXT NOT NULL DEFAULT ''
		);
		CREATE INDEX IF NOT EXISTS idx_jwt_revocations_expires_at
			ON jwt_revocations(expires_at);
	`
	_, err := s.pool.Exec(ctx, schema)
	return err
}

// IsRevoked returns true when the row exists. We don't filter
// by expires_at here — a revoked token past its exp would have
// already been rejected by the JWT exp validator, but if the
// row hasn't been cleaned up yet there's no harm in answering
// "revoked" for it (the answer is technically correct and the
// caller's JWT exp check is the real gate).
func (s *PgRevocationStore) IsRevoked(ctx context.Context, jti string) (bool, error) {
	if jti == "" {
		return false, nil
	}
	var found int
	err := s.pool.QueryRow(ctx,
		`SELECT 1 FROM jwt_revocations WHERE jti = $1`, jti,
	).Scan(&found)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("revocation lookup: %w", err)
	}
	return true, nil
}

// Revoke inserts a row, or no-ops on conflict — the first
// revocation is the canonical one and the reason/revoked_at
// stay frozen at the first call. We don't want a later
// revoke to overwrite the audit history.
func (s *PgRevocationStore) Revoke(ctx context.Context, jti string, expiresAt time.Time, reason string) error {
	if jti == "" {
		return fmt.Errorf("revoke: empty jti")
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO jwt_revocations (jti, expires_at, reason)
		VALUES ($1, $2, $3)
		ON CONFLICT (jti) DO NOTHING
	`, jti, expiresAt, reason)
	if err != nil {
		return fmt.Errorf("revoke insert: %w", err)
	}
	return nil
}

// CleanupExpired deletes rows whose token expiry is in the
// past — they can no longer authenticate even without the
// revocation row, so keeping them around wastes table space
// and slows the index.
func (s *PgRevocationStore) CleanupExpired(ctx context.Context, now time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM jwt_revocations WHERE expires_at < $1`, now,
	)
	if err != nil {
		return 0, fmt.Errorf("cleanup expired: %w", err)
	}
	return tag.RowsAffected(), nil
}

// List returns revocation rows. See RevocationStore.List
// for semantics. Builds the WHERE clause dynamically based
// on params; bind-variable indices are 1-based to match
// pgx conventions.
func (s *PgRevocationStore) List(ctx context.Context, params ListRevocationsParams) ([]Revocation, error) {
	limit := params.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	q := `SELECT jti, expires_at, revoked_at, reason FROM jwt_revocations`
	var args []any
	var conds []string

	if !params.IncludeExpired {
		conds = append(conds, fmt.Sprintf("expires_at > $%d", len(args)+1))
		args = append(args, time.Now())
	}
	if params.JTIPrefix != "" {
		conds = append(conds, fmt.Sprintf("jti LIKE $%d", len(args)+1))
		args = append(args, params.JTIPrefix+"%")
	}
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	q += fmt.Sprintf(" ORDER BY revoked_at DESC LIMIT $%d", len(args)+1)
	args = append(args, limit)

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list revocations: %w", err)
	}
	defer rows.Close()

	var out []Revocation
	for rows.Next() {
		var r Revocation
		if err := rows.Scan(&r.JTI, &r.ExpiresAt, &r.RevokedAt, &r.Reason); err != nil {
			return nil, fmt.Errorf("scan revocation row: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
