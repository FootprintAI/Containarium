package server

import (
	"context"
	"fmt"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TenantRegistry assigns a stable, non-zero uint32 ID to each tenant name. The
// eBPF network-policy maps (#315) key everything on this ID — a container's
// veth_policy entry, its egress_cidr LPM entries, and the ip_tenant map all
// carry the tenant's uint32. The ID MUST be stable across daemon restarts: the
// BPF maps are repopulated from stored policies + live containers on boot, and
// if a tenant's ID changed between runs its egress rules would be keyed to a
// different ID than its containers — silently misrouting policy. So this is a
// registry (assign once, persist, reuse), NOT a hash of the tenant name (a hash
// collision would merge two tenants' policies — unacceptable for a security
// control).
//
// ID 0 is reserved: the BPF programs treat a zero tenant_id / absent map entry
// as "unmanaged", so assigned IDs start at 1.
type TenantRegistry interface {
	// ID returns the tenant's stable ID, assigning (and persisting) a new one on
	// first use. Idempotent: repeated calls for the same tenant return the same ID.
	ID(ctx context.Context, tenant string) (uint32, error)
}

// --- in-memory ------------------------------------------------------

// MemTenantRegistry assigns IDs from a monotonic counter held in memory. IDs do
// not survive a restart — used on --standalone daemons (no Postgres) and tests.
// On a standalone daemon that's acceptable: the maps are rebuilt from scratch on
// boot anyway, and a single run is internally consistent.
type MemTenantRegistry struct {
	mu   sync.Mutex
	ids  map[string]uint32
	next uint32
}

func NewMemTenantRegistry() *MemTenantRegistry {
	return &MemTenantRegistry{ids: make(map[string]uint32), next: 1}
}

func (r *MemTenantRegistry) ID(_ context.Context, tenant string) (uint32, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if id, ok := r.ids[tenant]; ok {
		return id, nil
	}
	id := r.next
	r.ids[tenant] = id
	r.next++
	return id, nil
}

// --- postgres -------------------------------------------------------

// PostgresTenantRegistry persists assignments in a tenant_ids table so IDs are
// stable across restarts. Mirrors the store pattern (pool + initSchema).
type PostgresTenantRegistry struct {
	pool *pgxpool.Pool
	mu   sync.Mutex        // serialize assignment so the MAX(id)+1 read-modify-write is atomic per daemon
	c    map[string]uint32 // local cache so the hot path avoids a round-trip
}

func NewPostgresTenantRegistry(ctx context.Context, pool *pgxpool.Pool) (*PostgresTenantRegistry, error) {
	r := &PostgresTenantRegistry{pool: pool, c: make(map[string]uint32)}
	schema := `
		CREATE TABLE IF NOT EXISTS tenant_ids (
			tenant TEXT PRIMARY KEY,
			id INTEGER NOT NULL UNIQUE,
			created_at TIMESTAMP NOT NULL DEFAULT NOW()
		);
	`
	if _, err := pool.Exec(ctx, schema); err != nil {
		return nil, fmt.Errorf("init tenant_ids schema: %w", err)
	}
	return r, nil
}

func (r *PostgresTenantRegistry) ID(ctx context.Context, tenant string) (uint32, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if id, ok := r.c[tenant]; ok {
		return id, nil
	}
	// Assign-or-fetch in one statement: the ON CONFLICT no-op UPDATE lets
	// RETURNING return the existing id for an already-registered tenant, while a
	// fresh tenant gets MAX(id)+1. The per-daemon mutex serializes the MAX read so
	// concurrent assignments can't pick the same id; the UNIQUE(id) constraint is
	// the backstop if two daemons ever race.
	const q = `
		INSERT INTO tenant_ids (tenant, id)
		VALUES ($1, (SELECT COALESCE(MAX(id), 0) + 1 FROM tenant_ids))
		ON CONFLICT (tenant) DO UPDATE SET tenant = EXCLUDED.tenant
		RETURNING id
	`
	var id int32
	if err := r.pool.QueryRow(ctx, q, tenant).Scan(&id); err != nil {
		return 0, fmt.Errorf("assign tenant id for %q: %w", tenant, err)
	}
	uid := uint32(id) // #nosec G115 -- id is a small positive serial, never negative
	r.c[tenant] = uid
	return uid, nil
}
