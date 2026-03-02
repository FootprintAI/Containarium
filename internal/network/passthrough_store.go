package network

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	// ErrPassthroughNotFound is returned when a passthrough route is not found
	ErrPassthroughNotFound = errors.New("passthrough route not found")
)

// PassthroughRecord represents a passthrough route stored in PostgreSQL (source of truth)
type PassthroughRecord struct {
	ID            string
	ExternalPort  int
	TargetIP      string
	TargetPort    int
	Protocol      string // "tcp" or "udp"
	ContainerName string
	Description   string
	Active        bool
	CreatedBy     string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// PassthroughStore handles persistent storage of passthrough routes using PostgreSQL
type PassthroughStore struct {
	pool *pgxpool.Pool
}

// NewPassthroughStore creates a new passthrough store using an existing connection pool
func NewPassthroughStore(ctx context.Context, pool *pgxpool.Pool) (*PassthroughStore, error) {
	store := &PassthroughStore{pool: pool}

	if err := store.initSchema(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize passthrough schema: %w", err)
	}

	return store, nil
}

// initSchema creates the passthrough_routes table if it doesn't exist
func (s *PassthroughStore) initSchema(ctx context.Context) error {
	schema := `
		CREATE TABLE IF NOT EXISTS passthrough_routes (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			external_port INTEGER NOT NULL,
			target_ip TEXT NOT NULL,
			target_port INTEGER NOT NULL,
			protocol TEXT NOT NULL DEFAULT 'tcp',
			container_name TEXT,
			description TEXT,
			active BOOLEAN NOT NULL DEFAULT true,
			created_by TEXT,
			created_at TIMESTAMP NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
			UNIQUE (external_port, protocol)
		);

		CREATE INDEX IF NOT EXISTS idx_passthrough_routes_active ON passthrough_routes(active);
		CREATE INDEX IF NOT EXISTS idx_passthrough_routes_port_proto ON passthrough_routes(external_port, protocol);
	`

	_, err := s.pool.Exec(ctx, schema)
	return err
}

// Save saves or updates a passthrough route (upsert by external_port + protocol)
func (s *PassthroughStore) Save(ctx context.Context, route *PassthroughRecord) error {
	query := `
		INSERT INTO passthrough_routes (external_port, target_ip, target_port, protocol,
			container_name, description, active, created_by, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (external_port, protocol) DO UPDATE SET
			target_ip = EXCLUDED.target_ip,
			target_port = EXCLUDED.target_port,
			container_name = EXCLUDED.container_name,
			description = EXCLUDED.description,
			active = EXCLUDED.active,
			updated_at = EXCLUDED.updated_at
		RETURNING id
	`

	now := time.Now()
	if route.CreatedAt.IsZero() {
		route.CreatedAt = now
	}
	route.UpdatedAt = now

	if route.Protocol == "" {
		route.Protocol = "tcp"
	}

	err := s.pool.QueryRow(ctx, query,
		route.ExternalPort,
		route.TargetIP,
		route.TargetPort,
		route.Protocol,
		route.ContainerName,
		route.Description,
		route.Active,
		route.CreatedBy,
		route.CreatedAt,
		route.UpdatedAt,
	).Scan(&route.ID)

	if err != nil {
		return fmt.Errorf("failed to save passthrough route: %w", err)
	}

	return nil
}

// GetByPortProtocol retrieves a passthrough route by external port and protocol
func (s *PassthroughStore) GetByPortProtocol(ctx context.Context, externalPort int, protocol string) (*PassthroughRecord, error) {
	query := `
		SELECT id, external_port, target_ip, target_port, protocol,
			COALESCE(container_name, ''), COALESCE(description, ''), active,
			COALESCE(created_by, ''), created_at, updated_at
		FROM passthrough_routes
		WHERE external_port = $1 AND protocol = $2
	`

	route := &PassthroughRecord{}
	err := s.pool.QueryRow(ctx, query, externalPort, protocol).Scan(
		&route.ID,
		&route.ExternalPort,
		&route.TargetIP,
		&route.TargetPort,
		&route.Protocol,
		&route.ContainerName,
		&route.Description,
		&route.Active,
		&route.CreatedBy,
		&route.CreatedAt,
		&route.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrPassthroughNotFound
		}
		return nil, fmt.Errorf("failed to get passthrough route: %w", err)
	}

	return route, nil
}

// List retrieves all passthrough routes, optionally filtering by active status
func (s *PassthroughStore) List(ctx context.Context, activeOnly bool) ([]*PassthroughRecord, error) {
	var query string

	if activeOnly {
		query = `
			SELECT id, external_port, target_ip, target_port, protocol,
				COALESCE(container_name, ''), COALESCE(description, ''), active,
				COALESCE(created_by, ''), created_at, updated_at
			FROM passthrough_routes
			WHERE active = true
			ORDER BY external_port ASC
		`
	} else {
		query = `
			SELECT id, external_port, target_ip, target_port, protocol,
				COALESCE(container_name, ''), COALESCE(description, ''), active,
				COALESCE(created_by, ''), created_at, updated_at
			FROM passthrough_routes
			ORDER BY external_port ASC
		`
	}

	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list passthrough routes: %w", err)
	}
	defer rows.Close()

	var routes []*PassthroughRecord
	for rows.Next() {
		route := &PassthroughRecord{}
		if err := rows.Scan(
			&route.ID,
			&route.ExternalPort,
			&route.TargetIP,
			&route.TargetPort,
			&route.Protocol,
			&route.ContainerName,
			&route.Description,
			&route.Active,
			&route.CreatedBy,
			&route.CreatedAt,
			&route.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan passthrough route: %w", err)
		}
		routes = append(routes, route)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating passthrough routes: %w", err)
	}

	return routes, nil
}

// Delete removes a passthrough route by external port and protocol
func (s *PassthroughStore) Delete(ctx context.Context, externalPort int, protocol string) error {
	query := "DELETE FROM passthrough_routes WHERE external_port = $1 AND protocol = $2"
	result, err := s.pool.Exec(ctx, query, externalPort, protocol)

	if err != nil {
		return fmt.Errorf("failed to delete passthrough route: %w", err)
	}

	if result.RowsAffected() == 0 {
		return ErrPassthroughNotFound
	}

	return nil
}

// SetActive sets the active status of a passthrough route
func (s *PassthroughStore) SetActive(ctx context.Context, externalPort int, protocol string, active bool) error {
	query := "UPDATE passthrough_routes SET active = $1, updated_at = $2 WHERE external_port = $3 AND protocol = $4"
	result, err := s.pool.Exec(ctx, query, active, time.Now(), externalPort, protocol)

	if err != nil {
		return fmt.Errorf("failed to update passthrough route active status: %w", err)
	}

	if result.RowsAffected() == 0 {
		return ErrPassthroughNotFound
	}

	return nil
}

// Count returns the total number of passthrough routes
func (s *PassthroughStore) Count(ctx context.Context, activeOnly bool) (int32, error) {
	var query string
	if activeOnly {
		query = "SELECT COUNT(*) FROM passthrough_routes WHERE active = true"
	} else {
		query = "SELECT COUNT(*) FROM passthrough_routes"
	}

	var count int32
	err := s.pool.QueryRow(ctx, query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count passthrough routes: %w", err)
	}

	return count, nil
}
