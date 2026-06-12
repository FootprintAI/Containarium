package server

import (
	"context"
	"encoding/json"
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
	// MutateDenyRules atomically reads the tenant's virtual-patch deny rules,
	// applies fn, and writes the result back — under a lock (mem) / row lock
	// (postgres) — so concurrent edits don't lose updates (#660). The allow-policy
	// is left untouched. If the tenant has no policy yet, a minimal one is created
	// (so an operator can virtual-patch before declaring an allow-policy). Returns
	// the resulting stored policy.
	MutateDenyRules(ctx context.Context, tenant string, fn func(existing []*pb.NetworkPolicyDenyRule) ([]*pb.NetworkPolicyDenyRule, error)) (*pb.NetworkPolicy, error)
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
	np := clonePolicy(p)
	// Set declares the allow-policy; virtual-patch deny rules are owned by
	// MutateDenyRules. Preserve the existing tenant's deny rules (a new tenant
	// starts with none) so `set` never clobbers them and needs no client read.
	if old, ok := s.m[p.GetTenant()]; ok {
		np.DenyRules = cloneDenyRules(old.GetDenyRules())
	} else {
		np.DenyRules = nil
	}
	s.m[p.GetTenant()] = np
	return nil
}

func (s *MemNetworkPolicyStore) MutateDenyRules(_ context.Context, tenant string, fn func([]*pb.NetworkPolicyDenyRule) ([]*pb.NetworkPolicyDenyRule, error)) (*pb.NetworkPolicy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.m[tenant]
	if !ok {
		p = &pb.NetworkPolicy{Tenant: tenant}
	}
	newRules, err := fn(cloneDenyRules(p.GetDenyRules()))
	if err != nil {
		return nil, err
	}
	np := clonePolicy(p)
	np.DenyRules = newRules
	s.m[tenant] = np
	return clonePolicy(np), nil
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
		DenyRules:        cloneDenyRules(p.GetDenyRules()),
	}
}

// cloneDenyRules deep-copies a deny-rule slice so stored state can't be mutated
// through a returned pointer (and vice versa).
func cloneDenyRules(in []*pb.NetworkPolicyDenyRule) []*pb.NetworkPolicyDenyRule {
	if in == nil {
		return nil
	}
	out := make([]*pb.NetworkPolicyDenyRule, len(in))
	for i, r := range in {
		out[i] = &pb.NetworkPolicyDenyRule{
			Cidr:      r.GetCidr(),
			Port:      r.GetPort(),
			Proto:     r.GetProto(),
			Note:      r.GetNote(),
			ExpiresAt: r.GetExpiresAt(),
		}
	}
	return out
}

// denyRuleRow is the JSON shape stored in the network_policies.deny_rules JSONB
// column. Local to the store so the persisted form is explicit and decoupled
// from the proto wire names.
type denyRuleRow struct {
	Cidr      string `json:"cidr"`
	Port      uint32 `json:"port,omitempty"`
	Proto     string `json:"proto,omitempty"`
	Note      string `json:"note,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

func encodeDenyRules(rules []*pb.NetworkPolicyDenyRule) ([]byte, error) {
	rows := make([]denyRuleRow, 0, len(rules))
	for _, r := range rules {
		rows = append(rows, denyRuleRow{r.GetCidr(), r.GetPort(), r.GetProto(), r.GetNote(), r.GetExpiresAt()})
	}
	return json.Marshal(rows)
}

func decodeDenyRules(b []byte) ([]*pb.NetworkPolicyDenyRule, error) {
	if len(b) == 0 {
		return nil, nil
	}
	var rows []denyRuleRow
	if err := json.Unmarshal(b, &rows); err != nil {
		return nil, fmt.Errorf("decode deny_rules: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	out := make([]*pb.NetworkPolicyDenyRule, len(rows))
	for i, r := range rows {
		out[i] = &pb.NetworkPolicyDenyRule{Cidr: r.Cidr, Port: r.Port, Proto: r.Proto, Note: r.Note, ExpiresAt: r.ExpiresAt}
	}
	return out, nil
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
			deny_rules JSONB NOT NULL DEFAULT '[]',
			updated_at TIMESTAMP NOT NULL DEFAULT NOW()
		);
		-- Non-destructive upgrades for tables created before these columns
		-- (allow_metadata: #315 Phase D; source: #354 convergence;
		-- deny_rules: #660 virtual patching).
		ALTER TABLE network_policies ADD COLUMN IF NOT EXISTS allow_metadata BOOLEAN NOT NULL DEFAULT false;
		ALTER TABLE network_policies ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT '';
		ALTER TABLE network_policies ADD COLUMN IF NOT EXISTS deny_rules JSONB NOT NULL DEFAULT '[]';
	`
	if _, err := pool.Exec(ctx, schema); err != nil {
		return nil, fmt.Errorf("init network_policies schema: %w", err)
	}
	return s, nil
}

func (s *PostgresNetworkPolicyStore) Set(ctx context.Context, p *pb.NetworkPolicy) error {
	// deny_rules are deliberately NOT in the UPDATE set: Set declares the
	// allow-policy, while virtual-patch deny rules (#660) are owned by
	// MutateDenyRules. A new row starts with '[]'; an upsert preserves the
	// existing tenant's deny rules untouched — so `set` never clobbers them and
	// needs no client round-trip.
	const q = `
		INSERT INTO network_policies (tenant, allow_intra_tenant, egress_cidrs, egress_domains, mode, allow_metadata, source, deny_rules, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, '[]'::jsonb, NOW())
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
	const q = `SELECT tenant, allow_intra_tenant, egress_cidrs, egress_domains, mode, allow_metadata, source, deny_rules
		FROM network_policies WHERE tenant = $1`
	p := &pb.NetworkPolicy{}
	var mode int32
	var denyJSON []byte
	err := s.pool.QueryRow(ctx, q, tenant).Scan(&p.Tenant, &p.AllowIntraTenant, &p.EgressCidrs, &p.EgressDomains, &mode, &p.AllowMetadata, &p.Source, &denyJSON)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNetworkPolicyNotFound
		}
		return nil, fmt.Errorf("get network policy: %w", err)
	}
	p.Mode = pb.NetworkPolicyMode(mode)
	if p.DenyRules, err = decodeDenyRules(denyJSON); err != nil {
		return nil, err
	}
	return p, nil
}

func (s *PostgresNetworkPolicyStore) List(ctx context.Context) ([]*pb.NetworkPolicy, error) {
	const q = `SELECT tenant, allow_intra_tenant, egress_cidrs, egress_domains, mode, allow_metadata, source, deny_rules
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
		var denyJSON []byte
		if err := rows.Scan(&p.Tenant, &p.AllowIntraTenant, &p.EgressCidrs, &p.EgressDomains, &mode, &p.AllowMetadata, &p.Source, &denyJSON); err != nil {
			return nil, fmt.Errorf("scan network policy: %w", err)
		}
		p.Mode = pb.NetworkPolicyMode(mode)
		if p.DenyRules, err = decodeDenyRules(denyJSON); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// MutateDenyRules atomically applies fn to the tenant's deny rules in a single
// transaction: it ensures the row exists, locks it (FOR UPDATE), applies fn to
// the decoded rules, and writes the result — so two concurrent patches serialize
// rather than lost-update. The allow-policy columns are untouched.
func (s *PostgresNetworkPolicyStore) MutateDenyRules(ctx context.Context, tenant string, fn func([]*pb.NetworkPolicyDenyRule) ([]*pb.NetworkPolicyDenyRule, error)) (*pb.NetworkPolicy, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after a successful Commit

	// Ensure the row exists so the FOR UPDATE below always has something to lock
	// (closes the create-race for a tenant's first deny rule).
	if _, err := tx.Exec(ctx, `INSERT INTO network_policies (tenant) VALUES ($1) ON CONFLICT (tenant) DO NOTHING`, tenant); err != nil {
		return nil, fmt.Errorf("ensure policy row: %w", err)
	}

	p := &pb.NetworkPolicy{Tenant: tenant}
	var mode int32
	var denyJSON []byte
	err = tx.QueryRow(ctx, `SELECT allow_intra_tenant, egress_cidrs, egress_domains, mode, allow_metadata, source, deny_rules
		FROM network_policies WHERE tenant = $1 FOR UPDATE`, tenant).
		Scan(&p.AllowIntraTenant, &p.EgressCidrs, &p.EgressDomains, &mode, &p.AllowMetadata, &p.Source, &denyJSON)
	if err != nil {
		return nil, fmt.Errorf("lock policy: %w", err)
	}
	p.Mode = pb.NetworkPolicyMode(mode)
	existing, err := decodeDenyRules(denyJSON)
	if err != nil {
		return nil, err
	}
	newRules, err := fn(existing)
	if err != nil {
		return nil, err
	}
	enc, err := encodeDenyRules(newRules)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE network_policies SET deny_rules = $2::jsonb, updated_at = NOW() WHERE tenant = $1`, tenant, string(enc)); err != nil {
		return nil, fmt.Errorf("update deny_rules: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	p.DenyRules = newRules
	return p, nil
}

func (s *PostgresNetworkPolicyStore) Delete(ctx context.Context, tenant string) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM network_policies WHERE tenant = $1`, tenant); err != nil {
		return fmt.Errorf("delete network policy: %w", err)
	}
	return nil
}
