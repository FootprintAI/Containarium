package server

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// ErrCodingToolEgressPolicyNotFound is returned by Get when no policy is
// stored under the key.
var ErrCodingToolEgressPolicyNotFound = errors.New("coding-tool egress policy not found")

// CodingToolEgressPolicyStore persists coding-tool egress policies (#2378),
// keyed by tenant; the empty tenant is the cluster default. Separate from
// NetworkPolicyStore (its own table) so a tenant's NetworkPolicy never
// changes meaning. Callers pass a policy already validated by
// codeegress.Normalize.
type CodingToolEgressPolicyStore interface {
	// Set replaces the policy under p.Tenant, assigning the next revision
	// (monotonic across all keys and deletes) and stamping updated_at and
	// updatedBy. It returns the stored policy and the revision it replaced
	// (0 when there was none).
	Set(ctx context.Context, p *pb.CodingToolEgressPolicy, updatedBy string) (stored *pb.CodingToolEgressPolicy, previousRevision int64, err error)
	Get(ctx context.Context, tenant string) (*pb.CodingToolEgressPolicy, error)
	// Delete removes the policy and returns the revision it removed (0 when
	// there was none; deleting a missing policy is not an error).
	Delete(ctx context.Context, tenant string) (removedRevision int64, err error)
}

// --- in-memory ------------------------------------------------------

// MemCodingToolEgressPolicyStore is goroutine-safe and does not survive a
// restart; for --standalone daemons and tests.
type MemCodingToolEgressPolicyStore struct {
	mu       sync.RWMutex
	m        map[string]*pb.CodingToolEgressPolicy
	revision int64
}

func NewMemCodingToolEgressPolicyStore() *MemCodingToolEgressPolicyStore {
	return &MemCodingToolEgressPolicyStore{m: make(map[string]*pb.CodingToolEgressPolicy)}
}

func (s *MemCodingToolEgressPolicyStore) Set(_ context.Context, p *pb.CodingToolEgressPolicy, updatedBy string) (*pb.CodingToolEgressPolicy, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var prev int64
	if old, ok := s.m[p.GetTenant()]; ok {
		prev = old.GetRevision()
	}
	s.revision++
	np := cloneCodeEgressPolicy(p)
	np.Revision = s.revision
	np.UpdatedAt = timestamppb.New(time.Now().UTC())
	np.UpdatedBy = updatedBy
	s.m[p.GetTenant()] = np
	return cloneCodeEgressPolicy(np), prev, nil
}

func (s *MemCodingToolEgressPolicyStore) Get(_ context.Context, tenant string) (*pb.CodingToolEgressPolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.m[tenant]
	if !ok {
		return nil, ErrCodingToolEgressPolicyNotFound
	}
	return cloneCodeEgressPolicy(p), nil
}

func (s *MemCodingToolEgressPolicyStore) Delete(_ context.Context, tenant string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.m[tenant]
	if !ok {
		return 0, nil
	}
	delete(s.m, tenant)
	return p.GetRevision(), nil
}

func cloneCodeEgressPolicy(p *pb.CodingToolEgressPolicy) *pb.CodingToolEgressPolicy {
	out := &pb.CodingToolEgressPolicy{
		Tenant:        p.GetTenant(),
		Mode:          p.GetMode(),
		EgressCidrs:   append([]string(nil), p.GetEgressCidrs()...),
		EgressDomains: append([]string(nil), p.GetEgressDomains()...),
		Revision:      p.GetRevision(),
		UpdatedBy:     p.GetUpdatedBy(),
	}
	if t := p.GetUpdatedAt(); t != nil {
		out.UpdatedAt = timestamppb.New(t.AsTime())
	}
	return out
}

// --- postgres -------------------------------------------------------

// PostgresCodingToolEgressPolicyStore keeps policies in their own table, with
// revisions from a sequence so they stay monotonic across deletes and
// restarts.
type PostgresCodingToolEgressPolicyStore struct {
	pool *pgxpool.Pool
}

func NewPostgresCodingToolEgressPolicyStore(ctx context.Context, pool *pgxpool.Pool) (*PostgresCodingToolEgressPolicyStore, error) {
	const schema = `
		CREATE SEQUENCE IF NOT EXISTS coding_tool_egress_policy_revision_seq;
		CREATE TABLE IF NOT EXISTS coding_tool_egress_policies (
			tenant TEXT PRIMARY KEY,
			mode INTEGER NOT NULL DEFAULT 0,
			egress_cidrs TEXT[] NOT NULL DEFAULT '{}',
			egress_domains TEXT[] NOT NULL DEFAULT '{}',
			revision BIGINT NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_by TEXT NOT NULL DEFAULT ''
		);
	`
	if _, err := pool.Exec(ctx, schema); err != nil {
		return nil, fmt.Errorf("init coding_tool_egress_policies schema: %w", err)
	}
	return &PostgresCodingToolEgressPolicyStore{pool: pool}, nil
}

func (s *PostgresCodingToolEgressPolicyStore) Set(ctx context.Context, p *pb.CodingToolEgressPolicy, updatedBy string) (*pb.CodingToolEgressPolicy, int64, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after a successful Commit

	var prev int64
	err = tx.QueryRow(ctx, `SELECT revision FROM coding_tool_egress_policies WHERE tenant = $1 FOR UPDATE`, p.GetTenant()).Scan(&prev)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, 0, fmt.Errorf("read previous revision: %w", err)
	}

	stored := cloneCodeEgressPolicy(p)
	stored.UpdatedBy = updatedBy
	var updatedAt time.Time
	// nonNilStrings: pgx writes a nil slice as NULL, which the NOT NULL
	// array columns reject.
	err = tx.QueryRow(ctx, `
		INSERT INTO coding_tool_egress_policies (tenant, mode, egress_cidrs, egress_domains, revision, updated_at, updated_by)
		VALUES ($1, $2, $3, $4, nextval('coding_tool_egress_policy_revision_seq'), NOW(), $5)
		ON CONFLICT (tenant) DO UPDATE SET
			mode = EXCLUDED.mode,
			egress_cidrs = EXCLUDED.egress_cidrs,
			egress_domains = EXCLUDED.egress_domains,
			revision = EXCLUDED.revision,
			updated_at = EXCLUDED.updated_at,
			updated_by = EXCLUDED.updated_by
		RETURNING revision, updated_at`,
		p.GetTenant(), int32(p.GetMode()), nonNilStrings(p.GetEgressCidrs()), nonNilStrings(p.GetEgressDomains()), updatedBy,
	).Scan(&stored.Revision, &updatedAt)
	if err != nil {
		return nil, 0, fmt.Errorf("save coding-tool egress policy: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, 0, fmt.Errorf("commit: %w", err)
	}
	stored.UpdatedAt = timestamppb.New(updatedAt)
	return stored, prev, nil
}

func (s *PostgresCodingToolEgressPolicyStore) Get(ctx context.Context, tenant string) (*pb.CodingToolEgressPolicy, error) {
	p := &pb.CodingToolEgressPolicy{}
	var mode int32
	var updatedAt time.Time
	err := s.pool.QueryRow(ctx, `SELECT tenant, mode, egress_cidrs, egress_domains, revision, updated_at, updated_by
		FROM coding_tool_egress_policies WHERE tenant = $1`, tenant).
		Scan(&p.Tenant, &mode, &p.EgressCidrs, &p.EgressDomains, &p.Revision, &updatedAt, &p.UpdatedBy)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrCodingToolEgressPolicyNotFound
		}
		return nil, fmt.Errorf("get coding-tool egress policy: %w", err)
	}
	p.Mode = pb.NetworkPolicyMode(mode)
	p.UpdatedAt = timestamppb.New(updatedAt)
	return p, nil
}

func (s *PostgresCodingToolEgressPolicyStore) Delete(ctx context.Context, tenant string) (int64, error) {
	var removed int64
	err := s.pool.QueryRow(ctx, `DELETE FROM coding_tool_egress_policies WHERE tenant = $1 RETURNING revision`, tenant).Scan(&removed)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil
		}
		return 0, fmt.Errorf("delete coding-tool egress policy: %w", err)
	}
	return removed, nil
}
