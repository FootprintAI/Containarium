package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/encoding/protojson"

	v1 "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

var (
	// ErrNotFound is returned when an app is not found
	ErrNotFound = errors.New("app not found")

	// ErrAlreadyExists is returned when trying to create an app that already exists
	ErrAlreadyExists = errors.New("app already exists")
)

// Store handles persistent storage of applications using PostgreSQL
type Store struct {
	pool *pgxpool.Pool
}

// NewStore creates a new app store connected to PostgreSQL
// connectionString format: postgres://user:password@host:port/database?sslmode=disable
func NewStore(ctx context.Context, connectionString string) (*Store, error) {
	pool, err := pgxpool.New(ctx, connectionString)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Test the connection
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	store := &Store{pool: pool}

	// Initialize schema
	if err := store.initSchema(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return store, nil
}

// Close closes the database connection pool
func (s *Store) Close() {
	if s.pool != nil {
		s.pool.Close()
	}
}

// initSchema creates the database schema if it doesn't exist
func (s *Store) initSchema(ctx context.Context) error {
	schema := `
		CREATE TABLE IF NOT EXISTS apps (
			id UUID PRIMARY KEY,
			data JSONB NOT NULL,
			username TEXT NOT NULL,
			name TEXT NOT NULL,
			state TEXT NOT NULL,
			subdomain TEXT UNIQUE NOT NULL,
			port INTEGER NOT NULL,
			container_name TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL,
			deployed_at TIMESTAMP,
			UNIQUE(username, name)
		);

		CREATE INDEX IF NOT EXISTS idx_apps_username ON apps(username);
		CREATE INDEX IF NOT EXISTS idx_apps_state ON apps(state);
		CREATE INDEX IF NOT EXISTS idx_apps_subdomain ON apps(subdomain);
		CREATE INDEX IF NOT EXISTS idx_apps_username_name ON apps(username, name);
	`

	_, err := s.pool.Exec(ctx, schema)
	return err
}

// Save saves an app to the database (insert or update)
func (s *Store) Save(ctx context.Context, app *v1.App) error {
	// Serialize protobuf to JSON
	jsonData, err := protojson.Marshal(app)
	if err != nil {
		return fmt.Errorf("failed to marshal app: %w", err)
	}

	// Upsert query
	query := `
		INSERT INTO apps (id, data, username, name, state, subdomain, port, container_name, created_at, updated_at, deployed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (id) DO UPDATE SET
			data = EXCLUDED.data,
			state = EXCLUDED.state,
			port = EXCLUDED.port,
			updated_at = EXCLUDED.updated_at,
			deployed_at = EXCLUDED.deployed_at
	`

	createdAt := app.CreatedAt.AsTime()
	updatedAt := app.UpdatedAt.AsTime()
	var deployedAt *time.Time
	if app.DeployedAt != nil {
		t := app.DeployedAt.AsTime()
		deployedAt = &t
	}

	_, err = s.pool.Exec(ctx, query,
		app.Id,
		jsonData,
		app.Username,
		app.Name,
		app.State.String(),
		app.Subdomain,
		app.Port,
		app.ContainerName,
		createdAt,
		updatedAt,
		deployedAt,
	)

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == "23505" { // unique_violation
				return ErrAlreadyExists
			}
		}
		return fmt.Errorf("failed to save app: %w", err)
	}

	return nil
}

// GetByID retrieves an app by its ID
func (s *Store) GetByID(ctx context.Context, id string) (*v1.App, error) {
	var jsonData []byte

	query := "SELECT data FROM apps WHERE id = $1"
	err := s.pool.QueryRow(ctx, query, id).Scan(&jsonData)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed to get app: %w", err)
	}

	app := &v1.App{}
	if err := protojson.Unmarshal(jsonData, app); err != nil {
		return nil, fmt.Errorf("failed to unmarshal app: %w", err)
	}

	return app, nil
}

// GetByName retrieves an app by username and app name
func (s *Store) GetByName(ctx context.Context, username, name string) (*v1.App, error) {
	var jsonData []byte

	query := "SELECT data FROM apps WHERE username = $1 AND name = $2"
	err := s.pool.QueryRow(ctx, query, username, name).Scan(&jsonData)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed to get app: %w", err)
	}

	app := &v1.App{}
	if err := protojson.Unmarshal(jsonData, app); err != nil {
		return nil, fmt.Errorf("failed to unmarshal app: %w", err)
	}

	return app, nil
}

// List retrieves all apps for a username, optionally filtered by state
func (s *Store) List(ctx context.Context, username string, stateFilter v1.AppState) ([]*v1.App, error) {
	var query string
	var args []interface{}

	if username == "" {
		// List all apps (admin)
		if stateFilter == v1.AppState_APP_STATE_UNSPECIFIED {
			query = "SELECT data FROM apps ORDER BY created_at DESC"
		} else {
			query = "SELECT data FROM apps WHERE state = $1 ORDER BY created_at DESC"
			args = append(args, stateFilter.String())
		}
	} else {
		// List apps for specific user
		if stateFilter == v1.AppState_APP_STATE_UNSPECIFIED {
			query = "SELECT data FROM apps WHERE username = $1 ORDER BY created_at DESC"
			args = append(args, username)
		} else {
			query = "SELECT data FROM apps WHERE username = $1 AND state = $2 ORDER BY created_at DESC"
			args = append(args, username, stateFilter.String())
		}
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list apps: %w", err)
	}
	defer rows.Close()

	var apps []*v1.App
	for rows.Next() {
		var jsonData []byte
		if err := rows.Scan(&jsonData); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		app := &v1.App{}
		if err := protojson.Unmarshal(jsonData, app); err != nil {
			return nil, fmt.Errorf("failed to unmarshal app: %w", err)
		}

		apps = append(apps, app)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rows: %w", err)
	}

	return apps, nil
}

// Delete removes an app from the database
func (s *Store) Delete(ctx context.Context, id string) error {
	query := "DELETE FROM apps WHERE id = $1"
	result, err := s.pool.Exec(ctx, query, id)

	if err != nil {
		return fmt.Errorf("failed to delete app: %w", err)
	}

	if result.RowsAffected() == 0 {
		return ErrNotFound
	}

	return nil
}

// DeleteByName removes an app by username and name
func (s *Store) DeleteByName(ctx context.Context, username, name string) error {
	query := "DELETE FROM apps WHERE username = $1 AND name = $2"
	result, err := s.pool.Exec(ctx, query, username, name)

	if err != nil {
		return fmt.Errorf("failed to delete app: %w", err)
	}

	if result.RowsAffected() == 0 {
		return ErrNotFound
	}

	return nil
}

// Count returns the total number of apps, optionally filtered by username and state
func (s *Store) Count(ctx context.Context, username string, stateFilter v1.AppState) (int32, error) {
	var query string
	var args []interface{}

	if username == "" {
		if stateFilter == v1.AppState_APP_STATE_UNSPECIFIED {
			query = "SELECT COUNT(*) FROM apps"
		} else {
			query = "SELECT COUNT(*) FROM apps WHERE state = $1"
			args = append(args, stateFilter.String())
		}
	} else {
		if stateFilter == v1.AppState_APP_STATE_UNSPECIFIED {
			query = "SELECT COUNT(*) FROM apps WHERE username = $1"
			args = append(args, username)
		} else {
			query = "SELECT COUNT(*) FROM apps WHERE username = $1 AND state = $2"
			args = append(args, username, stateFilter.String())
		}
	}

	var count int32
	err := s.pool.QueryRow(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count apps: %w", err)
	}

	return count, nil
}
