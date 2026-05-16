// Package secrets implements the daemon-side Postgres-backed store
// for tenant secrets, layered on top of pkg/core/secrets crypto.
// See docs/SECRETS-MANAGEMENT-DESIGN.md.
package secrets

import (
	"context"
	"errors"
	"fmt"
	"time"

	corecrypto "github.com/footprintai/containarium/pkg/core/secrets"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SecretMetadata is the public-safe view of a stored secret —
// matches the proto message of the same name. The plaintext value
// lives only in memory during Get and never in this struct.
type SecretMetadata struct {
	Username  string
	Name      string
	Version   int32
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Store handles per-tenant secret persistence. All on-disk data is
// AES-256-GCM ciphertext bound to (username, name); the cipher
// instance holds the master key in process memory and is reused
// across calls.
type Store struct {
	pool   *pgxpool.Pool
	cipher *corecrypto.Cipher
}

// ErrNotFound is returned by Get / Delete when the (username, name)
// tuple has no row.
var ErrNotFound = errors.New("secrets: not found")

// NewStore opens the secrets store. Creates the `secrets` table on
// first run; idempotent on every subsequent call.
//
// The cipher must already be constructed from the daemon's master
// key (see pkg/core/secrets.LoadOrCreateMasterKey + NewCipher).
func NewStore(ctx context.Context, pool *pgxpool.Pool, cipher *corecrypto.Cipher) (*Store, error) {
	if pool == nil {
		return nil, errors.New("secrets: pool is nil")
	}
	if cipher == nil {
		return nil, errors.New("secrets: cipher is nil")
	}
	s := &Store{pool: pool, cipher: cipher}
	if err := s.initSchema(ctx); err != nil {
		return nil, fmt.Errorf("init schema: %w", err)
	}
	return s, nil
}

func (s *Store) initSchema(ctx context.Context) error {
	schema := `
		CREATE TABLE IF NOT EXISTS secrets (
			id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			username     TEXT NOT NULL,
			name         TEXT NOT NULL,
			nonce        BYTEA NOT NULL,
			ciphertext   BYTEA NOT NULL,
			version      INT  NOT NULL DEFAULT 1,
			created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			UNIQUE (username, name)
		);

		CREATE INDEX IF NOT EXISTS idx_secrets_username
			ON secrets(username);
	`
	_, err := s.pool.Exec(ctx, schema)
	return err
}

// Set creates or updates a secret. Idempotent — repeated calls with
// the same (username, name) bump the version and replace the
// ciphertext. Validates name + value at the API boundary before
// touching crypto or the DB.
func (s *Store) Set(ctx context.Context, username, name, value string) (*SecretMetadata, error) {
	if username == "" {
		return nil, fmt.Errorf("username is required")
	}
	if err := corecrypto.ValidateName(name); err != nil {
		return nil, err
	}
	if err := corecrypto.ValidateValue(value); err != nil {
		return nil, err
	}

	nonce, ct, err := s.cipher.Encrypt(username, name, []byte(value))
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}

	// INSERT ... ON CONFLICT DO UPDATE handles both create and
	// rotate in a single round-trip. The version bumps on every
	// rotation; the row's created_at stays as the original
	// (set-once-ever timestamp), updated_at moves to NOW().
	const q = `
		INSERT INTO secrets (username, name, nonce, ciphertext, version)
		VALUES ($1, $2, $3, $4, 1)
		ON CONFLICT (username, name)
		DO UPDATE SET
			nonce       = EXCLUDED.nonce,
			ciphertext  = EXCLUDED.ciphertext,
			version     = secrets.version + 1,
			updated_at  = NOW()
		RETURNING version, created_at, updated_at;
	`
	var version int32
	var createdAt, updatedAt time.Time
	if err := s.pool.QueryRow(ctx, q, username, name, nonce, ct).Scan(&version, &createdAt, &updatedAt); err != nil {
		return nil, fmt.Errorf("upsert secret: %w", err)
	}
	return &SecretMetadata{
		Username:  username,
		Name:      name,
		Version:   version,
		CreatedAt: createdAt,
		UpdatedAt: updatedAt,
	}, nil
}

// Get reads a single secret's decrypted plaintext value. Returns
// ErrNotFound if the (username, name) tuple isn't in the table.
//
// Failed decryption (wrong master key, tampered ciphertext) returns
// the underlying crypto error so callers can distinguish "you
// looked up something that exists but I can't decrypt it" from
// "nothing here."
func (s *Store) Get(ctx context.Context, username, name string) (meta *SecretMetadata, value string, err error) {
	if username == "" {
		return nil, "", fmt.Errorf("username is required")
	}
	if verr := corecrypto.ValidateName(name); verr != nil {
		return nil, "", verr
	}

	const q = `
		SELECT nonce, ciphertext, version, created_at, updated_at
		FROM secrets
		WHERE username = $1 AND name = $2
	`
	var nonce, ct []byte
	var version int32
	var createdAt, updatedAt time.Time
	if err := s.pool.QueryRow(ctx, q, username, name).Scan(&nonce, &ct, &version, &createdAt, &updatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, "", ErrNotFound
		}
		return nil, "", fmt.Errorf("select secret: %w", err)
	}

	plaintext, err := s.cipher.Decrypt(username, name, nonce, ct)
	if err != nil {
		return nil, "", fmt.Errorf("decrypt secret: %w", err)
	}
	return &SecretMetadata{
		Username:  username,
		Name:      name,
		Version:   version,
		CreatedAt: createdAt,
		UpdatedAt: updatedAt,
	}, string(plaintext), nil
}

// List returns metadata for all secrets owned by the tenant.
// Values are never returned by this path — only Get returns the
// decrypted plaintext (and is audit-logged at the caller's layer).
func (s *Store) List(ctx context.Context, username string) ([]SecretMetadata, error) {
	if username == "" {
		return nil, fmt.Errorf("username is required")
	}
	const q = `
		SELECT username, name, version, created_at, updated_at
		FROM secrets
		WHERE username = $1
		ORDER BY name
	`
	rows, err := s.pool.Query(ctx, q, username)
	if err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
	}
	defer rows.Close()

	var out []SecretMetadata
	for rows.Next() {
		var m SecretMetadata
		if err := rows.Scan(&m.Username, &m.Name, &m.Version, &m.CreatedAt, &m.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan secret row: %w", err)
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate secret rows: %w", err)
	}
	return out, nil
}

// Delete removes a single secret. Returns ErrNotFound if no such
// row existed (so callers can return a clean 404 instead of a
// generic 200).
func (s *Store) Delete(ctx context.Context, username, name string) error {
	if username == "" {
		return fmt.Errorf("username is required")
	}
	if err := corecrypto.ValidateName(name); err != nil {
		return err
	}
	const q = `DELETE FROM secrets WHERE username = $1 AND name = $2`
	tag, err := s.pool.Exec(ctx, q, username, name)
	if err != nil {
		return fmt.Errorf("delete secret: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// LoadAllForUser returns the decrypted plaintext values for every
// secret owned by the tenant. Used by the daemon's env-var
// stamping path (CreateContainer / StartContainer / RefreshSecrets)
// to build the map of environment.<NAME>=<value> assignments.
//
// This path is the hot one: returning N decrypted values in one
// round-trip beats N Get calls. The caller is responsible for not
// logging the map or persisting it outside the LXC config.
func (s *Store) LoadAllForUser(ctx context.Context, username string) (map[string]string, error) {
	if username == "" {
		return nil, fmt.Errorf("username is required")
	}
	const q = `
		SELECT name, nonce, ciphertext
		FROM secrets
		WHERE username = $1
	`
	rows, err := s.pool.Query(ctx, q, username)
	if err != nil {
		return nil, fmt.Errorf("load secrets for user: %w", err)
	}
	defer rows.Close()

	out := make(map[string]string)
	for rows.Next() {
		var name string
		var nonce, ct []byte
		if err := rows.Scan(&name, &nonce, &ct); err != nil {
			return nil, fmt.Errorf("scan secret row: %w", err)
		}
		pt, decErr := s.cipher.Decrypt(username, name, nonce, ct)
		if decErr != nil {
			return nil, fmt.Errorf("decrypt secret %s/%s: %w", username, name, decErr)
		}
		out[name] = string(pt)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate secret rows: %w", err)
	}
	return out, nil
}
