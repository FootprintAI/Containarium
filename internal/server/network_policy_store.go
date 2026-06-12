package server

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// ErrNetworkPolicyNotFound is returned by a NetworkPolicyStore.Get when the
// tenant has no policy.
var ErrNetworkPolicyNotFound = errors.New("network policy not found")

// NetworkPolicyStore persists per-tenant NetworkPolicy values. Two impls:
// PostgresNetworkPolicyStore (durable, used when the daemon has a DB pool) and
// MemNetworkPolicyStore (in-memory, for --standalone daemons and tests).
type NetworkPolicyStore interface {
	Set(ctx context.Context, p *pb.NetworkPolicy) error
	Get(ctx context.Context, tenant string) (*pb.NetworkPolicy, error)
	List(ctx context.Context) ([]*pb.NetworkPolicy, error)
	Delete(ctx context.Context, tenant string) error
}

// --- in-memory ------------------------------------------------------

// MemNetworkPolicyStore is a goroutine-safe in-memory store. Policies do not
// survive a daemon restart — used on --standalone daemons (no Postgres) and in
// tests.
type MemNetworkPolicyStore struct {
	mu sync.RWMutex
	m  map[string]*pb.NetworkPolicy
}

func NewMemNetworkPolicyStore() *MemNetworkPolicyStore {
	return &MemNetworkPolicyStore{m: make(map[string]*pb.NetworkPolicy)}
}

func (s *MemNetworkPolicyStore) Set(_ context.Context, p *pb.NetworkPolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[p.GetTenant()] = clonePolicy(p)
	return nil
}

func (s *MemNetworkPolicyStore) Get(_ context.Context, tenant string) (*pb.NetworkPolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.m[tenant]
	if !ok {
		return nil, ErrNetworkPolicyNotFound
	}
	return clonePolicy(p), nil
}

func (s *MemNetworkPolicyStore) List(_ context.Context) ([]*pb.NetworkPolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*pb.NetworkPolicy, 0, len(s.m))
	for _, p := range s.m {
		out = append(out, clonePolicy(p))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GetTenant() < out[j].GetTenant() })
	return out, nil
}

func (s *MemNetworkPolicyStore) Delete(_ context.Context, tenant string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, tenant)
	return nil
}

// clonePolicy makes a defensive copy so callers can't mutate stored state via
// the returned pointer (and vice versa).
func clonePolicy(p *pb.NetworkPolicy) *pb.NetworkPolicy {
	if p == nil {
		return nil
	}
	return &pb.NetworkPolicy{
		Tenant:           p.GetTenant(),
		AllowIntraTenant: p.GetAllowIntraTenant(),
		EgressCidrs:      append([]string(nil), p.GetEgressCidrs()...),
		EgressDomains:    append([]string(nil), p.GetEgressDomains()...),
		AllowMetadata:    p.GetAllowMetadata(),
		Mode:             p.GetMode(),
		Source:           p.GetSource(),
	}
}

// --- postgres -------------------------------------------------------

// PostgresNetworkPolicyStore persists policies in a network_policies table.
// Mirrors the RouteStore pattern (pool + initSchema + upsert/CRUD).
type PostgresNetworkPolicyStore struct {
	pool *pgxpool.Pool
}

func NewPostgresNetworkPolicyStore(ctx context.Context, pool *pgxpool.Pool) (*PostgresNetworkPolicyStore, error) {
	s := &PostgresNetworkPolicyStore{pool: pool}
	schema := `
		CREATE TABLE IF NOT EXISTS network_policies (
			tenant TEXT PRIMARY KEY,
			allow_intra_tenant BOOLEAN NOT NULL DEFAULT false,
			egress_cidrs TEXT[] NOT NULL DEFAULT '{}',
			egress_domains TEXT[] NOT NULL DEFAULT '{}',
			mode INTEGER NOT NULL DEFAULT 0,
			allow_metadata BOOLEAN NOT NULL DEFAULT false,
			source TEXT NOT NULL DEFAULT '',
			updated_at TIMESTAMP NOT NULL DEFAULT NOW()
		);
		-- Non-destructive upgrades for tables created before these columns
		-- (allow_metadata: #315 Phase D; source: #354 convergence).
		ALTER TABLE network_policies ADD COLUMN IF NOT EXISTS allow_metadata BOOLEAN NOT NULL DEFAULT false;
		ALTER TABLE network_policies ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT '';
	`
	if _, err := pool.Exec(ctx, schema); err != nil {
		return nil, fmt.Errorf("init network_policies schema: %w", err)
	}
	return s, nil
}

func (s *PostgresNetworkPolicyStore) Set(ctx context.Context, p *pb.NetworkPolicy) error {
	const q = `
		INSERT INTO network_policies (tenant, allow_intra_tenant, egress_cidrs, egress_domains, mode, allow_metadata, source, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
		ON CONFLICT (tenant) DO UPDATE SET
			allow_intra_tenant = EXCLUDED.allow_intra_tenant,
			egress_cidrs = EXCLUDED.egress_cidrs,
			egress_domains = EXCLUDED.egress_domains,
			mode = EXCLUDED.mode,
			allow_metadata = EXCLUDED.allow_metadata,
			source = EXCLUDED.source,
			updated_at = NOW()
	`
	// egress_cidrs / egress_domains are `TEXT[] NOT NULL DEFAULT '{}'`, but the
	// DEFAULT only applies when the column is OMITTED — here we pass them
	// explicitly, and pgx encodes a nil []string as SQL NULL, which violates the
	// NOT NULL constraint (SQLSTATE 23502). A policy that allows no domains (or no
	// CIDRs) arrives with a nil slice, so coerce nil -> empty so the array lands
	// as '{}' rather than NULL.
	_, err := s.pool.Exec(ctx, q,
		p.GetTenant(), p.GetAllowIntraTenant(),
		nonNilStrings(p.GetEgressCidrs()), nonNilStrings(p.GetEgressDomains()), int32(p.GetMode()),
		p.GetAllowMetadata(), p.GetSource())
	if err != nil {
		return fmt.Errorf("save network policy: %w", err)
	}
	return nil
}

// nonNilStrings returns s, or an empty (non-nil) slice when s is nil, so a
// NOT NULL Postgres array column stores '{}' instead of NULL.
func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (s *PostgresNetworkPolicyStore) Get(ctx context.Context, tenant string) (*pb.NetworkPolicy, error) {
	const q = `SELECT tenant, allow_intra_tenant, egress_cidrs, egress_domains, mode, allow_metadata, source
		FROM network_policies WHERE tenant = $1`
	p := &pb.NetworkPolicy{}
	var mode int32
	err := s.pool.QueryRow(ctx, q, tenant).Scan(&p.Tenant, &p.AllowIntraTenant, &p.EgressCidrs, &p.EgressDomains, &mode, &p.AllowMetadata, &p.Source)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNetworkPolicyNotFound
		}
		return nil, fmt.Errorf("get network policy: %w", err)
	}
	p.Mode = pb.NetworkPolicyMode(mode)
	return p, nil
}

func (s *PostgresNetworkPolicyStore) List(ctx context.Context) ([]*pb.NetworkPolicy, error) {
	const q = `SELECT tenant, allow_intra_tenant, egress_cidrs, egress_domains, mode, allow_metadata, source
		FROM network_policies ORDER BY tenant`
	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list network policies: %w", err)
	}
	defer rows.Close()
	var out []*pb.NetworkPolicy
	for rows.Next() {
		p := &pb.NetworkPolicy{}
		var mode int32
		if err := rows.Scan(&p.Tenant, &p.AllowIntraTenant, &p.EgressCidrs, &p.EgressDomains, &mode, &p.AllowMetadata, &p.Source); err != nil {
			return nil, fmt.Errorf("scan network policy: %w", err)
		}
		p.Mode = pb.NetworkPolicyMode(mode)
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *PostgresNetworkPolicyStore) Delete(ctx context.Context, tenant string) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM network_policies WHERE tenant = $1`, tenant); err != nil {
		return fmt.Errorf("delete network policy: %w", err)
	}
	return nil
}
