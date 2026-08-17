package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store is the persistence contract for managed clusters. Two
// implementations exist — MemStore (daemon-without-Postgres degrade
// path + unit tests) and PGStore — held to the same behavior by the
// integration test suite (house rule from #1300: the contract is
// stated once, against both).
type Store interface {
	Create(ctx context.Context, c *Cluster) error
	Get(ctx context.Context, owner, name string) (*Cluster, error)
	// List returns clusters for one owner, or every cluster when
	// owner is empty, ordered by (owner, name).
	List(ctx context.Context, owner string) ([]*Cluster, error)
	SetState(ctx context.Context, owner, name string, st State, reason string) error
	SetEndpoint(ctx context.Context, owner, name, endpoint string) error
	UpdateNodeGroups(ctx context.Context, owner, name string, groups []NodeGroup) error
	// Delete removes the cluster and (transitively) its nodes and
	// events — the "re-created cluster starts empty" guarantee.
	Delete(ctx context.Context, owner, name string) error
	UpsertNode(ctx context.Context, n *Node) error
	ListNodes(ctx context.Context, owner, name string) ([]*Node, error)
	DeleteNode(ctx context.Context, vmName string) error
	AppendEvent(ctx context.Context, owner, name string, e Event) error
	// ListEvents returns the newest events first, at most limit
	// (limit <= 0 = all).
	ListEvents(ctx context.Context, owner, name string, limit int) ([]Event, error)
	Close()
}

// PGStore is the Postgres-backed Store.
type PGStore struct {
	pool *pgxpool.Pool
}

// NewPGStore initializes the schema on a shared pool (house pattern:
// idempotent DDL in the constructor; the pool is owned by the caller).
func NewPGStore(ctx context.Context, pool *pgxpool.Pool) (*PGStore, error) {
	s := &PGStore{pool: pool}
	if err := s.initSchema(ctx); err != nil {
		return nil, fmt.Errorf("init k8s cluster schema: %w", err)
	}
	return s, nil
}

func (s *PGStore) initSchema(ctx context.Context) error {
	schema := `
		CREATE TABLE IF NOT EXISTS k8s_clusters (
			id UUID PRIMARY KEY,
			owner TEXT NOT NULL,
			name TEXT NOT NULL,
			state TEXT NOT NULL,
			state_reason TEXT NOT NULL DEFAULT '',
			k3s_version TEXT NOT NULL DEFAULT '',
			api_endpoint TEXT NOT NULL DEFAULT '',
			node_groups JSONB NOT NULL,
			created_at TIMESTAMPTZ NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL,
			UNIQUE(owner, name)
		);
		CREATE INDEX IF NOT EXISTS idx_k8s_clusters_owner ON k8s_clusters(owner);

		CREATE TABLE IF NOT EXISTS k8s_cluster_nodes (
			vm_name TEXT PRIMARY KEY,
			cluster_id UUID NOT NULL REFERENCES k8s_clusters(id) ON DELETE CASCADE,
			role TEXT NOT NULL,
			node_group TEXT NOT NULL DEFAULT '',
			state TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_k8s_cluster_nodes_cluster ON k8s_cluster_nodes(cluster_id);

		CREATE TABLE IF NOT EXISTS k8s_cluster_events (
			id BIGSERIAL PRIMARY KEY,
			cluster_id UUID NOT NULL REFERENCES k8s_clusters(id) ON DELETE CASCADE,
			at TIMESTAMPTZ NOT NULL,
			kind TEXT NOT NULL,
			node_group TEXT NOT NULL DEFAULT '',
			reason TEXT NOT NULL DEFAULT ''
		);
		CREATE INDEX IF NOT EXISTS idx_k8s_cluster_events_cluster ON k8s_cluster_events(cluster_id, id DESC);
	`
	_, err := s.pool.Exec(ctx, schema)
	return err
}

func (s *PGStore) clusterID(ctx context.Context, owner, name string) (string, error) {
	var id string
	err := s.pool.QueryRow(ctx,
		`SELECT id FROM k8s_clusters WHERE owner = $1 AND name = $2`, owner, name).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return id, err
}

func (s *PGStore) Create(ctx context.Context, c *Cluster) error {
	groups, err := json.Marshal(c.NodeGroups)
	if err != nil {
		return fmt.Errorf("marshal node groups: %w", err)
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO k8s_clusters (id, owner, name, state, state_reason, k3s_version, api_endpoint, node_groups, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		c.ID, c.Owner, c.Name, string(c.State), c.StateReason, c.K3sVersion, c.APIEndpoint, groups, c.CreatedAt, c.UpdatedAt)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique_violation
		return ErrAlreadyExists
	}
	return err
}

func scanCluster(row pgx.Row) (*Cluster, error) {
	var c Cluster
	var state string
	var groups []byte
	err := row.Scan(&c.ID, &c.Owner, &c.Name, &state, &c.StateReason, &c.K3sVersion, &c.APIEndpoint, &groups, &c.CreatedAt, &c.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	c.State = State(state)
	if err := json.Unmarshal(groups, &c.NodeGroups); err != nil {
		return nil, fmt.Errorf("unmarshal node groups: %w", err)
	}
	return &c, nil
}

const clusterCols = `id, owner, name, state, state_reason, k3s_version, api_endpoint, node_groups, created_at, updated_at`

func (s *PGStore) Get(ctx context.Context, owner, name string) (*Cluster, error) {
	return scanCluster(s.pool.QueryRow(ctx,
		`SELECT `+clusterCols+` FROM k8s_clusters WHERE owner = $1 AND name = $2`, owner, name))
}

func (s *PGStore) List(ctx context.Context, owner string) ([]*Cluster, error) {
	query := `SELECT ` + clusterCols + ` FROM k8s_clusters ORDER BY owner, name`
	args := []any{}
	if owner != "" {
		query = `SELECT ` + clusterCols + ` FROM k8s_clusters WHERE owner = $1 ORDER BY owner, name`
		args = append(args, owner)
	}
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Cluster
	for rows.Next() {
		c, err := scanCluster(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *PGStore) exec1(ctx context.Context, query string, args ...any) error {
	tag, err := s.pool.Exec(ctx, query, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PGStore) SetState(ctx context.Context, owner, name string, st State, reason string) error {
	return s.exec1(ctx,
		`UPDATE k8s_clusters SET state = $3, state_reason = $4, updated_at = $5 WHERE owner = $1 AND name = $2`,
		owner, name, string(st), reason, time.Now().UTC())
}

func (s *PGStore) SetEndpoint(ctx context.Context, owner, name, endpoint string) error {
	return s.exec1(ctx,
		`UPDATE k8s_clusters SET api_endpoint = $3, updated_at = $4 WHERE owner = $1 AND name = $2`,
		owner, name, endpoint, time.Now().UTC())
}

func (s *PGStore) UpdateNodeGroups(ctx context.Context, owner, name string, groups []NodeGroup) error {
	data, err := json.Marshal(groups)
	if err != nil {
		return fmt.Errorf("marshal node groups: %w", err)
	}
	return s.exec1(ctx,
		`UPDATE k8s_clusters SET node_groups = $3, updated_at = $4 WHERE owner = $1 AND name = $2`,
		owner, name, data, time.Now().UTC())
}

func (s *PGStore) Delete(ctx context.Context, owner, name string) error {
	// Nodes and events go with the cluster via ON DELETE CASCADE.
	return s.exec1(ctx, `DELETE FROM k8s_clusters WHERE owner = $1 AND name = $2`, owner, name)
}

func (s *PGStore) UpsertNode(ctx context.Context, n *Node) error {
	id, err := s.clusterID(ctx, n.Owner, n.Cluster)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO k8s_cluster_nodes (vm_name, cluster_id, role, node_group, state, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (vm_name) DO UPDATE SET role = EXCLUDED.role, node_group = EXCLUDED.node_group, state = EXCLUDED.state`,
		n.VMName, id, n.Role, n.Group, n.State, n.CreatedAt)
	return err
}

func (s *PGStore) ListNodes(ctx context.Context, owner, name string) ([]*Node, error) {
	id, err := s.clusterID(ctx, owner, name)
	if err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx,
		`SELECT vm_name, role, node_group, state, created_at FROM k8s_cluster_nodes WHERE cluster_id = $1 ORDER BY vm_name`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Node
	for rows.Next() {
		n := &Node{Owner: owner, Cluster: name}
		if err := rows.Scan(&n.VMName, &n.Role, &n.Group, &n.State, &n.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *PGStore) DeleteNode(ctx context.Context, vmName string) error {
	return s.exec1(ctx, `DELETE FROM k8s_cluster_nodes WHERE vm_name = $1`, vmName)
}

func (s *PGStore) AppendEvent(ctx context.Context, owner, name string, e Event) error {
	id, err := s.clusterID(ctx, owner, name)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO k8s_cluster_events (cluster_id, at, kind, node_group, reason) VALUES ($1, $2, $3, $4, $5)`,
		id, e.At, string(e.Kind), e.Group, e.Reason)
	return err
}

func (s *PGStore) ListEvents(ctx context.Context, owner, name string, limit int) ([]Event, error) {
	id, err := s.clusterID(ctx, owner, name)
	if err != nil {
		return nil, err
	}
	query := `SELECT at, kind, node_group, reason FROM k8s_cluster_events WHERE cluster_id = $1 ORDER BY id DESC`
	args := []any{id}
	if limit > 0 {
		query += ` LIMIT $2`
		args = append(args, limit)
	}
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var kind string
		if err := rows.Scan(&e.At, &kind, &e.Group, &e.Reason); err != nil {
			return nil, err
		}
		e.Kind = EventKind(kind)
		out = append(out, e)
	}
	return out, rows.Err()
}

// Close is a no-op: the pool is shared and owned by the caller.
func (s *PGStore) Close() {}
