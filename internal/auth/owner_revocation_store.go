//go:build !containarium_client

package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PgOwnerRevocationStore is the Postgres-backed owner-revocation store for the
// model gateway (#2111): the durable counterpart of
// modelgateway.MemOwnerRevocations, the same way PgRevocationStore is the
// durable counterpart of the in-memory per-jti list.
//
// It satisfies modelgateway.OwnerRevocationChecker (RevokedBefore) and the
// gateway's write half (RevokeOwner) structurally — this package does not
// import modelgateway.
//
// One row per key owner, not per token: the table is bounded by the number of
// owners a daemon serves, and there is no sweeper — an owner cutoff stays
// meaningful for as long as any token minted before it could be presented.
type PgOwnerRevocationStore struct {
	pool *pgxpool.Pool
}

// NewPgOwnerRevocationStore creates the store and ensures its table exists
// (CREATE TABLE IF NOT EXISTS — non-destructive on an existing deployment).
func NewPgOwnerRevocationStore(ctx context.Context, pool *pgxpool.Pool) (*PgOwnerRevocationStore, error) {
	s := &PgOwnerRevocationStore{pool: pool}
	if err := s.initSchema(ctx); err != nil {
		return nil, fmt.Errorf("owner revocation store: init schema: %w", err)
	}
	return s, nil
}

func (s *PgOwnerRevocationStore) initSchema(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS gateway_owner_revocations (
			key_owner       TEXT PRIMARY KEY,
			revoked_before  TIMESTAMPTZ NOT NULL,
			reason          TEXT NOT NULL DEFAULT '',
			updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
	`)
	return err
}

// RevokedBefore returns keyOwner's cutoff, or the zero time when the owner has
// never been revoked (or keyOwner is empty). A database error is returned, not
// swallowed: the gateway's isOwnerRevoked is what decides to fail open on it,
// under its own lookup timeout.
func (s *PgOwnerRevocationStore) RevokedBefore(ctx context.Context, keyOwner string) (time.Time, error) {
	if keyOwner == "" {
		return time.Time{}, nil
	}
	var cutoff time.Time
	err := s.pool.QueryRow(ctx,
		`SELECT revoked_before FROM gateway_owner_revocations WHERE key_owner = $1`, keyOwner,
	).Scan(&cutoff)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return time.Time{}, nil
		}
		return time.Time{}, fmt.Errorf("owner revocation lookup: %w", err)
	}
	return cutoff, nil
}

// RevokeOwner records at as keyOwner's cutoff, keeping the latest one if
// several revocations land — a revocation must never narrow. The conditional
// upsert makes that one atomic statement, so concurrent revocations cannot
// race an older cutoff over a newer one. The reason travels with the cutoff
// that is kept.
func (s *PgOwnerRevocationStore) RevokeOwner(ctx context.Context, keyOwner string, at time.Time, reason string) error {
	if keyOwner == "" {
		return fmt.Errorf("revoke owner: empty key_owner")
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO gateway_owner_revocations (key_owner, revoked_before, reason)
		VALUES ($1, $2, $3)
		ON CONFLICT (key_owner) DO UPDATE
			SET revoked_before = EXCLUDED.revoked_before,
			    reason         = EXCLUDED.reason,
			    updated_at     = NOW()
			WHERE gateway_owner_revocations.revoked_before < EXCLUDED.revoked_before
	`, keyOwner, at, reason)
	if err != nil {
		return fmt.Errorf("revoke owner upsert: %w", err)
	}
	return nil
}
