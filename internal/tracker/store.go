package tracker

import (
	"context"
	"errors"
	"fmt"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Connection is the storage-layer view of a TrackerConnection. Provider is
// the typed enum, not the DB's TEXT column — the string<->enum conversion
// happens at this store boundary (providerToString / providerFromString),
// per the "protobuf enums over magic strings" convention: every caller
// above this package sees pb.TrackerProvider, never a raw string.
type Connection struct {
	Username         string
	Name             string
	Provider         pb.TrackerProvider
	BaseURL          string
	Project          string
	CredentialSecret string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// ErrNotFound is returned by Get / Delete when the (username, name) tuple
// has no row.
var ErrNotFound = errors.New("tracker: connection not found")

// Store handles per-tenant tracker-connection persistence. Holds no
// credential material itself — CredentialSecret only names a secret that
// lives in internal/secrets, in SECRET_DELIVERY_BROKER_ONLY mode; that
// cross-package validation happens in internal/server (this package has
// no dependency on internal/secrets).
type Store struct {
	pool *pgxpool.Pool
}

// NewStore opens the tracker-connections store, creating the table on
// first run. Idempotent on every subsequent call, same idiom as
// internal/secrets.NewStore.
func NewStore(ctx context.Context, pool *pgxpool.Pool) (*Store, error) {
	if pool == nil {
		return nil, errors.New("tracker: pool is nil")
	}
	s := &Store{pool: pool}
	if err := s.initSchema(ctx); err != nil {
		return nil, fmt.Errorf("init schema: %w", err)
	}
	return s, nil
}

func (s *Store) initSchema(ctx context.Context) error {
	const schema = `
		CREATE TABLE IF NOT EXISTS tracker_connections (
			username          TEXT NOT NULL,
			name              TEXT NOT NULL,
			provider          TEXT NOT NULL CHECK (provider IN ('github', 'gitlab')),
			base_url          TEXT NOT NULL DEFAULT '',
			project           TEXT NOT NULL,
			credential_secret TEXT NOT NULL,
			created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			PRIMARY KEY (username, name)
		);
	`
	_, err := s.pool.Exec(ctx, schema)
	return err
}

// providerToString converts the typed enum to the DB's stored string.
// Rejects UNSPECIFIED (and anything else unrecognized) — provider is
// never inferred or defaulted, per the design note.
func providerToString(p pb.TrackerProvider) (string, error) {
	switch p {
	case pb.TrackerProvider_TRACKER_PROVIDER_GITHUB:
		return "github", nil
	case pb.TrackerProvider_TRACKER_PROVIDER_GITLAB:
		return "gitlab", nil
	default:
		return "", fmt.Errorf("tracker: provider must be GITHUB or GITLAB, got %v", p)
	}
}

// providerFromString is providerToString's inverse, used when reading a
// row back. An unrecognized string (should be unreachable given the CHECK
// constraint and providerToString gating every write) maps to
// UNSPECIFIED rather than guessing.
func providerFromString(s string) pb.TrackerProvider {
	switch s {
	case "github":
		return pb.TrackerProvider_TRACKER_PROVIDER_GITHUB
	case "gitlab":
		return pb.TrackerProvider_TRACKER_PROVIDER_GITLAB
	default:
		return pb.TrackerProvider_TRACKER_PROVIDER_UNSPECIFIED
	}
}

// Set creates or updates a tracker connection. Idempotent — repeated
// calls with the same (username, name) replace every field.
func (s *Store) Set(ctx context.Context, c Connection) (*Connection, error) {
	if c.Username == "" {
		return nil, errors.New("tracker: username is required")
	}
	if c.Name == "" {
		return nil, errors.New("tracker: name is required")
	}
	if c.Project == "" {
		return nil, errors.New("tracker: project is required")
	}
	if c.CredentialSecret == "" {
		return nil, errors.New("tracker: credential_secret is required")
	}
	providerStr, err := providerToString(c.Provider)
	if err != nil {
		return nil, err
	}

	const q = `
		INSERT INTO tracker_connections (username, name, provider, base_url, project, credential_secret)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (username, name) DO UPDATE SET
			provider          = EXCLUDED.provider,
			base_url          = EXCLUDED.base_url,
			project           = EXCLUDED.project,
			credential_secret = EXCLUDED.credential_secret,
			updated_at        = NOW()
		RETURNING created_at, updated_at;
	`
	var createdAt, updatedAt time.Time
	if err := s.pool.QueryRow(ctx, q, c.Username, c.Name, providerStr, c.BaseURL, c.Project, c.CredentialSecret).
		Scan(&createdAt, &updatedAt); err != nil {
		return nil, fmt.Errorf("upsert tracker connection: %w", err)
	}
	out := c
	out.CreatedAt = createdAt
	out.UpdatedAt = updatedAt
	return &out, nil
}

// Get returns a single named connection. ErrNotFound if it doesn't exist
// for this tenant — a connection named by another tenant never matches,
// since the lookup is always scoped by username.
func (s *Store) Get(ctx context.Context, username, name string) (*Connection, error) {
	if username == "" {
		return nil, errors.New("tracker: username is required")
	}
	const q = `
		SELECT provider, base_url, project, credential_secret, created_at, updated_at
		FROM tracker_connections
		WHERE username = $1 AND name = $2
	`
	var providerStr, baseURL, project, credSecret string
	var createdAt, updatedAt time.Time
	if err := s.pool.QueryRow(ctx, q, username, name).
		Scan(&providerStr, &baseURL, &project, &credSecret, &createdAt, &updatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("select tracker connection: %w", err)
	}
	return &Connection{
		Username:         username,
		Name:             name,
		Provider:         providerFromString(providerStr),
		BaseURL:          baseURL,
		Project:          project,
		CredentialSecret: credSecret,
		CreatedAt:        createdAt,
		UpdatedAt:        updatedAt,
	}, nil
}

// List returns every connection owned by the tenant, ordered by name.
func (s *Store) List(ctx context.Context, username string) ([]Connection, error) {
	if username == "" {
		return nil, errors.New("tracker: username is required")
	}
	const q = `
		SELECT name, provider, base_url, project, credential_secret, created_at, updated_at
		FROM tracker_connections
		WHERE username = $1
		ORDER BY name
	`
	rows, err := s.pool.Query(ctx, q, username)
	if err != nil {
		return nil, fmt.Errorf("list tracker connections: %w", err)
	}
	defer rows.Close()

	var out []Connection
	for rows.Next() {
		var c Connection
		var providerStr string
		c.Username = username
		if err := rows.Scan(&c.Name, &providerStr, &c.BaseURL, &c.Project, &c.CredentialSecret, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan tracker connection row: %w", err)
		}
		c.Provider = providerFromString(providerStr)
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tracker connection rows: %w", err)
	}
	return out, nil
}

// Delete removes a single connection. Does not touch the credential
// secret it referenced. Returns ErrNotFound if no such row existed.
func (s *Store) Delete(ctx context.Context, username, name string) error {
	if username == "" {
		return errors.New("tracker: username is required")
	}
	const q = `DELETE FROM tracker_connections WHERE username = $1 AND name = $2`
	tag, err := s.pool.Exec(ctx, q, username, name)
	if err != nil {
		return fmt.Errorf("delete tracker connection: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
