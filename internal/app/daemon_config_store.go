package app

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DaemonConfigStore handles persistent storage of daemon configuration using PostgreSQL.
// It stores key-value pairs so the daemon can self-bootstrap after VM recreation.
type DaemonConfigStore struct {
	pool *pgxpool.Pool
}

// NewDaemonConfigStore creates a new daemon config store and initializes the schema.
func NewDaemonConfigStore(ctx context.Context, pool *pgxpool.Pool) (*DaemonConfigStore, error) {
	store := &DaemonConfigStore{pool: pool}
	if err := store.initSchema(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize daemon_config schema: %w", err)
	}
	return store, nil
}

func (s *DaemonConfigStore) initSchema(ctx context.Context) error {
	schema := `
		CREATE TABLE IF NOT EXISTS daemon_config (
			key        TEXT PRIMARY KEY,
			value      TEXT NOT NULL,
			updated_at TIMESTAMP NOT NULL DEFAULT NOW()
		);
	`
	_, err := s.pool.Exec(ctx, schema)
	return err
}

// Get retrieves a single config value by key. Returns empty string if not found.
func (s *DaemonConfigStore) Get(ctx context.Context, key string) (string, error) {
	var value string
	err := s.pool.QueryRow(ctx,
		"SELECT value FROM daemon_config WHERE key = $1", key,
	).Scan(&value)
	if err != nil {
		return "", err
	}
	return value, nil
}

// Set upserts a single config key-value pair.
func (s *DaemonConfigStore) Set(ctx context.Context, key, value string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO daemon_config (key, value, updated_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at
	`, key, value, time.Now())
	return err
}

// GetAll retrieves all config key-value pairs.
func (s *DaemonConfigStore) GetAll(ctx context.Context) (map[string]string, error) {
	rows, err := s.pool.Query(ctx, "SELECT key, value FROM daemon_config")
	if err != nil {
		return nil, fmt.Errorf("failed to query daemon_config: %w", err)
	}
	defer rows.Close()

	config := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, fmt.Errorf("failed to scan daemon_config row: %w", err)
		}
		config[k] = v
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating daemon_config: %w", err)
	}
	return config, nil
}

// SetAll batch-upserts multiple config key-value pairs in a single transaction.
func (s *DaemonConfigStore) SetAll(ctx context.Context, config map[string]string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	now := time.Now()
	for k, v := range config {
		_, err := tx.Exec(ctx, `
			INSERT INTO daemon_config (key, value, updated_at)
			VALUES ($1, $2, $3)
			ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at
		`, k, v, now)
		if err != nil {
			return fmt.Errorf("failed to upsert key %q: %w", k, err)
		}
	}

	return tx.Commit(ctx)
}
