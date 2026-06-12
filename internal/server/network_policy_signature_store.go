package server

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/footprintai/containarium/internal/netpolicy"
	"github.com/footprintai/containarium/internal/safecast"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// ErrSignatureNotFound is returned by a signature store's delete/get for an
// unknown name (delete treats it as a no-op; the server maps it to idempotent
// success).
var ErrSignatureNotFound = errors.New("network-policy signature not found")

// NetworkPolicySignatureStore persists operator-managed Tier 2 exploit
// signatures (#661 PR-B). They are GLOBAL (not tenant-scoped). Set upserts by
// name and assigns a stable id (>= netpolicy.OperatorIDBase) the first time a
// name is seen, so the id echoed in a match's audit row never changes under an
// operator.
type NetworkPolicySignatureStore interface {
	Set(ctx context.Context, name string, pattern []byte, enabled bool, note string) (*pb.NetworkPolicySignature, error)
	List(ctx context.Context) ([]*pb.NetworkPolicySignature, error)
	Delete(ctx context.Context, name string) error
}

// --- in-memory ------------------------------------------------------

type memSignature struct {
	id      uint16
	pattern []byte
	enabled bool
	note    string
}

// MemNetworkPolicySignatureStore is a goroutine-safe in-memory store used on
// --standalone daemons and in tests.
type MemNetworkPolicySignatureStore struct {
	mu     sync.RWMutex
	m      map[string]memSignature
	nextID uint16
}

func NewMemNetworkPolicySignatureStore() *MemNetworkPolicySignatureStore {
	return &MemNetworkPolicySignatureStore{m: make(map[string]memSignature), nextID: netpolicy.OperatorIDBase}
}

func (s *MemNetworkPolicySignatureStore) Set(_ context.Context, name string, pattern []byte, enabled bool, note string) (*pb.NetworkPolicySignature, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.m[name]
	id := cur.id
	if !ok {
		id = s.nextID
		s.nextID++
	}
	rec := memSignature{id: id, pattern: append([]byte(nil), pattern...), enabled: enabled, note: note}
	s.m[name] = rec
	return sigToProto(name, rec), nil
}

func (s *MemNetworkPolicySignatureStore) List(_ context.Context) ([]*pb.NetworkPolicySignature, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*pb.NetworkPolicySignature, 0, len(s.m))
	for name, rec := range s.m {
		out = append(out, sigToProto(name, rec))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GetName() < out[j].GetName() })
	return out, nil
}

func (s *MemNetworkPolicySignatureStore) Delete(_ context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[name]; !ok {
		return ErrSignatureNotFound
	}
	delete(s.m, name)
	return nil
}

func sigToProto(name string, rec memSignature) *pb.NetworkPolicySignature {
	return &pb.NetworkPolicySignature{
		Name:    name,
		Pattern: string(rec.pattern),
		Enabled: rec.enabled,
		Id:      uint32(rec.id),
		Note:    rec.note,
	}
}

// --- postgres -------------------------------------------------------

type PostgresNetworkPolicySignatureStore struct {
	pool *pgxpool.Pool
}

func NewPostgresNetworkPolicySignatureStore(ctx context.Context, pool *pgxpool.Pool) (*PostgresNetworkPolicySignatureStore, error) {
	s := &PostgresNetworkPolicySignatureStore{pool: pool}
	const schema = `
		CREATE TABLE IF NOT EXISTS network_policy_signatures (
			name TEXT PRIMARY KEY,
			id INTEGER NOT NULL UNIQUE,
			pattern BYTEA NOT NULL,
			enabled BOOLEAN NOT NULL DEFAULT true,
			note TEXT NOT NULL DEFAULT '',
			updated_at TIMESTAMP NOT NULL DEFAULT NOW()
		);`
	if _, err := pool.Exec(ctx, schema); err != nil {
		return nil, fmt.Errorf("init network_policy_signatures schema: %w", err)
	}
	return s, nil
}

func (s *PostgresNetworkPolicySignatureStore) Set(ctx context.Context, name string, pattern []byte, enabled bool, note string) (*pb.NetworkPolicySignature, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after a successful Commit

	// Keep an existing name's id; assign the next free id (>= OperatorIDBase) for a
	// new one. The whole read-assign-write runs in one transaction so concurrent
	// inserts can't collide on an id.
	var id int32
	err = tx.QueryRow(ctx, `SELECT id FROM network_policy_signatures WHERE name = $1`, name).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		if err := tx.QueryRow(ctx,
			`SELECT COALESCE(MAX(id), $1 - 1) + 1 FROM network_policy_signatures`,
			int32(netpolicy.OperatorIDBase)).Scan(&id); err != nil {
			return nil, fmt.Errorf("assign signature id: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("lookup signature id: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO network_policy_signatures (name, id, pattern, enabled, note, updated_at)
		VALUES ($1, $2, $3, $4, $5, NOW())
		ON CONFLICT (name) DO UPDATE SET
			pattern = EXCLUDED.pattern, enabled = EXCLUDED.enabled, note = EXCLUDED.note, updated_at = NOW()`,
		name, id, pattern, enabled, note); err != nil {
		return nil, fmt.Errorf("upsert signature: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	return &pb.NetworkPolicySignature{Name: name, Pattern: string(pattern), Enabled: enabled, Id: safecast.U32(id), Note: note}, nil
}

func (s *PostgresNetworkPolicySignatureStore) List(ctx context.Context) ([]*pb.NetworkPolicySignature, error) {
	rows, err := s.pool.Query(ctx, `SELECT name, id, pattern, enabled, note FROM network_policy_signatures ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list signatures: %w", err)
	}
	defer rows.Close()
	var out []*pb.NetworkPolicySignature
	for rows.Next() {
		var (
			name, note string
			id         int32
			pattern    []byte
			enabled    bool
		)
		if err := rows.Scan(&name, &id, &pattern, &enabled, &note); err != nil {
			return nil, fmt.Errorf("scan signature: %w", err)
		}
		out = append(out, &pb.NetworkPolicySignature{Name: name, Pattern: string(pattern), Enabled: enabled, Id: safecast.U32(id), Note: note})
	}
	return out, rows.Err()
}

func (s *PostgresNetworkPolicySignatureStore) Delete(ctx context.Context, name string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM network_policy_signatures WHERE name = $1`, name)
	if err != nil {
		return fmt.Errorf("delete signature: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrSignatureNotFound
	}
	return nil
}
