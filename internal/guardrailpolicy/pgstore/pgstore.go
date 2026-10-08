// Package pgstore is the Postgres guardrailpolicy.Store. It is a separate
// package so the containarium client binary, which uses guardrailpolicy for
// validation and display, does not link the database driver.
package pgstore

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"

	"github.com/footprintai/containarium/internal/guardrailpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Store keeps the policy in a singleton row. The row is seeded at
// bootstrap with a NULL policy, which is the stored "not configured" state;
// every Set locks that row, so concurrent Sets serialize and the revision
// never repeats.
type Store struct {
	pool *pgxpool.Pool
}

// New bootstraps the table and its singleton row on a pool the
// daemon already owns. Idempotent: an existing row (and its revision) is kept.
func New(ctx context.Context, pool *pgxpool.Pool) (*Store, error) {
	if _, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS guardrail_policy (
			id         SMALLINT PRIMARY KEY CHECK (id = 1),
			revision   BIGINT NOT NULL DEFAULT 0,
			policy     BYTEA,
			updated_at TIMESTAMPTZ,
			updated_by TEXT NOT NULL DEFAULT ''
		);
		INSERT INTO guardrail_policy (id) VALUES (1) ON CONFLICT (id) DO NOTHING;
	`); err != nil {
		return nil, fmt.Errorf("init guardrail_policy schema: %w", err)
	}
	return &Store{pool: pool}, nil
}

// decodeRow turns the row into a policy; a NULL policy column is "not
// configured" and reported as (nil, nil) so callers choose the error.
func decodeRow(revision int64, raw []byte) (*pb.ServerGuardrailPolicy, error) {
	if raw == nil {
		return nil, nil
	}
	p := &pb.ServerGuardrailPolicy{}
	if err := proto.Unmarshal(raw, p); err != nil {
		return nil, fmt.Errorf("decode stored guardrail policy: %w", err)
	}
	p.Revision = revision // the column is authoritative
	return p, nil
}

func (s *Store) Get(ctx context.Context) (*pb.ServerGuardrailPolicy, error) {
	var (
		revision int64
		raw      []byte
	)
	// No ErrNoRows special case: the bootstrap seeds the row, so a missing
	// row is a damaged table and must read as an error, never as "no policy".
	if err := s.pool.QueryRow(ctx, `SELECT revision, policy FROM guardrail_policy WHERE id = 1`).Scan(&revision, &raw); err != nil {
		return nil, fmt.Errorf("read guardrail policy: %w", err)
	}
	p, err := decodeRow(revision, raw)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, guardrailpolicy.ErrNotConfigured
	}
	return p, nil
}

func (s *Store) Set(ctx context.Context, policy *pb.GuardrailPolicy, signers []*pb.GuardrailTrustedSigner, updatedBy string) (*guardrailpolicy.SetResult, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin guardrail policy set: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var (
		revision int64
		raw      []byte
	)
	if err := tx.QueryRow(ctx, `SELECT revision, policy FROM guardrail_policy WHERE id = 1 FOR UPDATE`).Scan(&revision, &raw); err != nil {
		return nil, fmt.Errorf("lock guardrail policy row: %w", err)
	}
	prev, err := decodeRow(revision, raw)
	if err != nil {
		return nil, err
	}
	cur := guardrailpolicy.Next(prev, policy, signers, updatedBy, time.Now())
	if prev == nil {
		cur.Revision = revision + 1
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(cur)
	if err != nil {
		return nil, fmt.Errorf("encode guardrail policy: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE guardrail_policy SET revision = $1, policy = $2, updated_at = $3, updated_by = $4 WHERE id = 1`,
		cur.GetRevision(), encoded, cur.GetUpdatedAt().AsTime(), updatedBy); err != nil {
		return nil, fmt.Errorf("store guardrail policy: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit guardrail policy: %w", err)
	}
	return &guardrailpolicy.SetResult{Previous: prev, Current: guardrailpolicy.Clone(cur)}, nil
}
