package collaborator

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/footprintai/containarium/internal/safecast"
)

var (
	// ErrNotFound is returned when a collaborator is not found
	ErrNotFound = errors.New("collaborator not found")

	// ErrAlreadyExists is returned when trying to add a collaborator that already exists
	ErrAlreadyExists = errors.New("collaborator already exists")
)

// Collaborator represents a user with access to a container
type Collaborator struct {
	ID                   string
	ContainerName        string
	OwnerUsername        string
	CollaboratorUsername string
	AccountName          string // e.g., "alice-container-bob"
	SSHPublicKey         string
	CreatedAt            time.Time
	CreatedBy            string
	HasSudo              bool // Full sudo access (not just su - owner)
	HasContainerRuntime  bool // Docker/podman group membership
}

// Store handles persistent storage of collaborators using PostgreSQL
type Store struct {
	pool *pgxpool.Pool
}

// NewStore creates a new collaborator store connected to PostgreSQL
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
		CREATE TABLE IF NOT EXISTS collaborators (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			container_name TEXT NOT NULL,
			owner_username TEXT NOT NULL,
			collaborator_username TEXT NOT NULL,
			account_name TEXT NOT NULL,
			ssh_public_key TEXT NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			created_by TEXT,
			UNIQUE(container_name, collaborator_username)
		);

		CREATE INDEX IF NOT EXISTS idx_collaborators_container ON collaborators(container_name);
		CREATE INDEX IF NOT EXISTS idx_collaborators_owner ON collaborators(owner_username);
		CREATE INDEX IF NOT EXISTS idx_collaborators_collaborator ON collaborators(collaborator_username);
		CREATE INDEX IF NOT EXISTS idx_collaborators_account ON collaborators(account_name);

		ALTER TABLE collaborators ADD COLUMN IF NOT EXISTS has_sudo BOOLEAN DEFAULT FALSE;
		ALTER TABLE collaborators ADD COLUMN IF NOT EXISTS has_container_runtime BOOLEAN DEFAULT FALSE;
	`

	_, err := s.pool.Exec(ctx, schema)
	return err
}

// Add adds a new collaborator to the database
func (s *Store) Add(ctx context.Context, c *Collaborator) error {
	query := `
		INSERT INTO collaborators (container_name, owner_username, collaborator_username, account_name, ssh_public_key, created_at, created_by, has_sudo, has_container_runtime)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id
	`

	createdAt := c.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now()
	}

	err := s.pool.QueryRow(ctx, query,
		c.ContainerName,
		c.OwnerUsername,
		c.CollaboratorUsername,
		c.AccountName,
		c.SSHPublicKey,
		createdAt,
		c.CreatedBy,
		c.HasSudo,
		c.HasContainerRuntime,
	).Scan(&c.ID)

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == "23505" { // unique_violation
				return ErrAlreadyExists
			}
		}
		return fmt.Errorf("failed to add collaborator: %w", err)
	}

	return nil
}

// Get retrieves a collaborator by container name and collaborator username
func (s *Store) Get(ctx context.Context, containerName, collaboratorUsername string) (*Collaborator, error) {
	query := `
		SELECT id, container_name, owner_username, collaborator_username, account_name, ssh_public_key, created_at, created_by, COALESCE(has_sudo, false), COALESCE(has_container_runtime, false)
		FROM collaborators
		WHERE container_name = $1 AND collaborator_username = $2
	`

	c := &Collaborator{}
	var createdBy *string

	err := s.pool.QueryRow(ctx, query, containerName, collaboratorUsername).Scan(
		&c.ID,
		&c.ContainerName,
		&c.OwnerUsername,
		&c.CollaboratorUsername,
		&c.AccountName,
		&c.SSHPublicKey,
		&c.CreatedAt,
		&createdBy,
		&c.HasSudo,
		&c.HasContainerRuntime,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed to get collaborator: %w", err)
	}

	if createdBy != nil {
		c.CreatedBy = *createdBy
	}

	return c, nil
}

// List retrieves all collaborators for a container
func (s *Store) List(ctx context.Context, containerName string) ([]*Collaborator, error) {
	query := `
		SELECT id, container_name, owner_username, collaborator_username, account_name, ssh_public_key, created_at, created_by, COALESCE(has_sudo, false), COALESCE(has_container_runtime, false)
		FROM collaborators
		WHERE container_name = $1
		ORDER BY created_at DESC
	`

	rows, err := s.pool.Query(ctx, query, containerName)
	if err != nil {
		return nil, fmt.Errorf("failed to list collaborators: %w", err)
	}
	defer rows.Close()

	return s.scanCollaborators(rows)
}

// ListByOwner retrieves all collaborators for containers owned by a user
func (s *Store) ListByOwner(ctx context.Context, ownerUsername string) ([]*Collaborator, error) {
	query := `
		SELECT id, container_name, owner_username, collaborator_username, account_name, ssh_public_key, created_at, created_by, COALESCE(has_sudo, false), COALESCE(has_container_runtime, false)
		FROM collaborators
		WHERE owner_username = $1
		ORDER BY created_at DESC
	`

	rows, err := s.pool.Query(ctx, query, ownerUsername)
	if err != nil {
		return nil, fmt.Errorf("failed to list collaborators by owner: %w", err)
	}
	defer rows.Close()

	return s.scanCollaborators(rows)
}

// ListByCollaborator retrieves all containers a user has access to as a collaborator
func (s *Store) ListByCollaborator(ctx context.Context, collaboratorUsername string) ([]*Collaborator, error) {
	query := `
		SELECT id, container_name, owner_username, collaborator_username, account_name, ssh_public_key, created_at, created_by, COALESCE(has_sudo, false), COALESCE(has_container_runtime, false)
		FROM collaborators
		WHERE collaborator_username = $1
		ORDER BY created_at DESC
	`

	rows, err := s.pool.Query(ctx, query, collaboratorUsername)
	if err != nil {
		return nil, fmt.Errorf("failed to list by collaborator: %w", err)
	}
	defer rows.Close()

	return s.scanCollaborators(rows)
}

// ListAll retrieves all collaborators (for sync-accounts recovery)
func (s *Store) ListAll(ctx context.Context) ([]*Collaborator, error) {
	query := `
		SELECT id, container_name, owner_username, collaborator_username, account_name, ssh_public_key, created_at, created_by, COALESCE(has_sudo, false), COALESCE(has_container_runtime, false)
		FROM collaborators
		ORDER BY created_at DESC
	`

	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list all collaborators: %w", err)
	}
	defer rows.Close()

	return s.scanCollaborators(rows)
}

// Remove removes a collaborator from the database
func (s *Store) Remove(ctx context.Context, containerName, collaboratorUsername string) error {
	query := "DELETE FROM collaborators WHERE container_name = $1 AND collaborator_username = $2"
	result, err := s.pool.Exec(ctx, query, containerName, collaboratorUsername)

	if err != nil {
		return fmt.Errorf("failed to remove collaborator: %w", err)
	}

	if result.RowsAffected() == 0 {
		return ErrNotFound
	}

	return nil
}

// RemoveByContainer removes all collaborators for a container (used when deleting container)
func (s *Store) RemoveByContainer(ctx context.Context, containerName string) (int64, error) {
	query := "DELETE FROM collaborators WHERE container_name = $1"
	result, err := s.pool.Exec(ctx, query, containerName)

	if err != nil {
		return 0, fmt.Errorf("failed to remove collaborators by container: %w", err)
	}

	return result.RowsAffected(), nil
}

// Count returns the number of collaborators for a container
func (s *Store) Count(ctx context.Context, containerName string) (int32, error) {
	query := "SELECT COUNT(*) FROM collaborators WHERE container_name = $1"

	var count int64
	err := s.pool.QueryRow(ctx, query, containerName).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count collaborators: %w", err)
	}

	return safecast.I32(count), nil
}

// scanCollaborators is a helper to scan rows into Collaborator structs
func (s *Store) scanCollaborators(rows pgx.Rows) ([]*Collaborator, error) {
	var collaborators []*Collaborator

	for rows.Next() {
		c := &Collaborator{}
		var createdBy *string

		if err := rows.Scan(
			&c.ID,
			&c.ContainerName,
			&c.OwnerUsername,
			&c.CollaboratorUsername,
			&c.AccountName,
			&c.SSHPublicKey,
			&c.CreatedAt,
			&createdBy,
			&c.HasSudo,
			&c.HasContainerRuntime,
		); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		if createdBy != nil {
			c.CreatedBy = *createdBy
		}

		collaborators = append(collaborators, c)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rows: %w", err)
	}

	return collaborators, nil
}
