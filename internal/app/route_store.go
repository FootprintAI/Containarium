package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	// ErrRouteNotFound is returned when a route is not found
	ErrRouteNotFound = errors.New("route not found")
)

// RouteCreator identifies who created a route.
type RouteCreator string

const (
	// RouteCreatorSystem marks routes created automatically by the daemon (e.g. management UI).
	RouteCreatorSystem RouteCreator = "system"
	// RouteCreatorUser marks routes created by a user via the API.
	RouteCreatorUser RouteCreator = "user"
)

// RouteRecord represents a route stored in PostgreSQL (source of truth)
type RouteRecord struct {
	ID            string
	Subdomain     string
	FullDomain    string
	TargetIP      string
	TargetPort    int
	Protocol      string // "http" or "grpc"
	ContainerName string
	AppID         *string // nullable, references apps table
	Description   string
	Active        bool
	CreatedBy     string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// RouteStore handles persistent storage of routes using PostgreSQL
type RouteStore struct {
	pool *pgxpool.Pool
}

// NewRouteStore creates a new route store using an existing connection pool
func NewRouteStore(ctx context.Context, pool *pgxpool.Pool) (*RouteStore, error) {
	store := &RouteStore{pool: pool}

	// Initialize schema
	if err := store.initSchema(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize route schema: %w", err)
	}

	return store, nil
}

// initSchema creates the routes table if it doesn't exist
func (s *RouteStore) initSchema(ctx context.Context) error {
	// Ensure apps table exists (at least the id column) so the FK constraint works.
	// When app hosting is enabled, the full apps table is created by app.Store.
	// When it's not, we create a minimal stub so routes can still reference it.
	appsStub := `
		CREATE TABLE IF NOT EXISTS apps (
			id UUID PRIMARY KEY,
			data JSONB NOT NULL DEFAULT '{}',
			username TEXT NOT NULL DEFAULT '',
			name TEXT NOT NULL DEFAULT '',
			state TEXT NOT NULL DEFAULT '',
			subdomain TEXT UNIQUE NOT NULL DEFAULT '',
			port INTEGER NOT NULL DEFAULT 0,
			container_name TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMP NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
			deployed_at TIMESTAMP
		);
	`
	if _, err := s.pool.Exec(ctx, appsStub); err != nil {
		return fmt.Errorf("failed to ensure apps table: %w", err)
	}

	schema := `
		CREATE TABLE IF NOT EXISTS routes (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			subdomain TEXT NOT NULL,
			full_domain TEXT UNIQUE NOT NULL,
			target_ip TEXT NOT NULL,
			target_port INTEGER NOT NULL,
			protocol TEXT NOT NULL DEFAULT 'http',
			container_name TEXT,
			app_id UUID REFERENCES apps(id) ON DELETE SET NULL,
			description TEXT,
			active BOOLEAN NOT NULL DEFAULT true,
			created_by TEXT,
			created_at TIMESTAMP NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMP NOT NULL DEFAULT NOW()
		);

		CREATE INDEX IF NOT EXISTS idx_routes_subdomain ON routes(subdomain);
		CREATE INDEX IF NOT EXISTS idx_routes_active ON routes(active);
		CREATE INDEX IF NOT EXISTS idx_routes_app_id ON routes(app_id);
		CREATE INDEX IF NOT EXISTS idx_routes_full_domain ON routes(full_domain);
	`

	_, err := s.pool.Exec(ctx, schema)
	return err
}

// Save saves or updates a route (upsert by full_domain)
func (s *RouteStore) Save(ctx context.Context, route *RouteRecord) error {
	query := `
		INSERT INTO routes (subdomain, full_domain, target_ip, target_port, protocol,
			container_name, app_id, description, active, created_by, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (full_domain) DO UPDATE SET
			subdomain = EXCLUDED.subdomain,
			target_ip = EXCLUDED.target_ip,
			target_port = EXCLUDED.target_port,
			protocol = EXCLUDED.protocol,
			container_name = EXCLUDED.container_name,
			app_id = EXCLUDED.app_id,
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
		route.Protocol = "http"
	}

	err := s.pool.QueryRow(ctx, query,
		route.Subdomain,
		route.FullDomain,
		route.TargetIP,
		route.TargetPort,
		route.Protocol,
		route.ContainerName,
		route.AppID,
		route.Description,
		route.Active,
		route.CreatedBy,
		route.CreatedAt,
		route.UpdatedAt,
	).Scan(&route.ID)

	if err != nil {
		return fmt.Errorf("failed to save route: %w", err)
	}

	return nil
}

// GetByDomain retrieves a route by its full domain
func (s *RouteStore) GetByDomain(ctx context.Context, fullDomain string) (*RouteRecord, error) {
	query := `
		SELECT id, subdomain, full_domain, target_ip, target_port, protocol,
			COALESCE(container_name, ''), app_id, COALESCE(description, ''), active,
			COALESCE(created_by, ''), created_at, updated_at
		FROM routes
		WHERE full_domain = $1
	`

	route := &RouteRecord{}
	err := s.pool.QueryRow(ctx, query, fullDomain).Scan(
		&route.ID,
		&route.Subdomain,
		&route.FullDomain,
		&route.TargetIP,
		&route.TargetPort,
		&route.Protocol,
		&route.ContainerName,
		&route.AppID,
		&route.Description,
		&route.Active,
		&route.CreatedBy,
		&route.CreatedAt,
		&route.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrRouteNotFound
		}
		return nil, fmt.Errorf("failed to get route: %w", err)
	}

	return route, nil
}

// List retrieves all routes, optionally filtering by active status
func (s *RouteStore) List(ctx context.Context, activeOnly bool) ([]*RouteRecord, error) {
	var query string
	var args []interface{}

	if activeOnly {
		query = `
			SELECT id, subdomain, full_domain, target_ip, target_port, protocol,
				COALESCE(container_name, ''), app_id, COALESCE(description, ''), active,
				COALESCE(created_by, ''), created_at, updated_at
			FROM routes
			WHERE active = true
			ORDER BY created_at DESC
		`
	} else {
		query = `
			SELECT id, subdomain, full_domain, target_ip, target_port, protocol,
				COALESCE(container_name, ''), app_id, COALESCE(description, ''), active,
				COALESCE(created_by, ''), created_at, updated_at
			FROM routes
			ORDER BY created_at DESC
		`
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list routes: %w", err)
	}
	defer rows.Close()

	var routes []*RouteRecord
	for rows.Next() {
		route := &RouteRecord{}
		if err := rows.Scan(
			&route.ID,
			&route.Subdomain,
			&route.FullDomain,
			&route.TargetIP,
			&route.TargetPort,
			&route.Protocol,
			&route.ContainerName,
			&route.AppID,
			&route.Description,
			&route.Active,
			&route.CreatedBy,
			&route.CreatedAt,
			&route.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan route: %w", err)
		}
		routes = append(routes, route)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating routes: %w", err)
	}

	return routes, nil
}

// Delete removes a route by its full domain
func (s *RouteStore) Delete(ctx context.Context, fullDomain string) error {
	query := "DELETE FROM routes WHERE full_domain = $1"
	result, err := s.pool.Exec(ctx, query, fullDomain)

	if err != nil {
		return fmt.Errorf("failed to delete route: %w", err)
	}

	if result.RowsAffected() == 0 {
		return ErrRouteNotFound
	}

	return nil
}

// DeleteByAppID removes all routes associated with an app
func (s *RouteStore) DeleteByAppID(ctx context.Context, appID string) error {
	query := "DELETE FROM routes WHERE app_id = $1"
	_, err := s.pool.Exec(ctx, query, appID)

	if err != nil {
		return fmt.Errorf("failed to delete routes by app ID: %w", err)
	}

	return nil
}

// SetActive sets the active status of a route
func (s *RouteStore) SetActive(ctx context.Context, fullDomain string, active bool) error {
	query := "UPDATE routes SET active = $1, updated_at = $2 WHERE full_domain = $3"
	result, err := s.pool.Exec(ctx, query, active, time.Now(), fullDomain)

	if err != nil {
		return fmt.Errorf("failed to update route active status: %w", err)
	}

	if result.RowsAffected() == 0 {
		return ErrRouteNotFound
	}

	return nil
}

// Count returns the total number of routes
func (s *RouteStore) Count(ctx context.Context, activeOnly bool) (int32, error) {
	var query string
	if activeOnly {
		query = "SELECT COUNT(*) FROM routes WHERE active = true"
	} else {
		query = "SELECT COUNT(*) FROM routes"
	}

	var count int32
	err := s.pool.QueryRow(ctx, query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count routes: %w", err)
	}

	return count, nil
}
