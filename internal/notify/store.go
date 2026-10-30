package notify

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is returned when a user has no channel.
var ErrNotFound = errors.New("notify: no channel configured")

// ChannelStore holds one ntfy channel per user.
type ChannelStore interface {
	Get(ctx context.Context, username string) (Channel, error)
	Set(ctx context.Context, ch Channel) (Channel, error)
	Delete(ctx context.Context, username string) error
	List(ctx context.Context) ([]Channel, error)
}

// MemStore is an in-memory ChannelStore, for tests and for a daemon without
// Postgres.
type MemStore struct {
	mu sync.Mutex
	m  map[string]Channel
}

// NewMemStore returns an empty MemStore.
func NewMemStore() *MemStore { return &MemStore{m: map[string]Channel{}} }

func (s *MemStore) Get(_ context.Context, username string) (Channel, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch, ok := s.m[username]
	if !ok {
		return Channel{}, ErrNotFound
	}
	return ch, nil
}

func (s *MemStore) Set(_ context.Context, ch Channel) (Channel, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch.UpdatedAt = time.Now().UTC()
	s.m[ch.Username] = ch
	return ch, nil
}

func (s *MemStore) Delete(_ context.Context, username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[username]; !ok {
		return ErrNotFound
	}
	delete(s.m, username)
	return nil
}

func (s *MemStore) List(context.Context) ([]Channel, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Channel, 0, len(s.m))
	for _, ch := range s.m {
		out = append(out, ch)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out, nil
}

// PGStore is the Postgres ChannelStore.
type PGStore struct {
	pool *pgxpool.Pool
}

// schemaLockKey serializes concurrent schema creation, as in
// internal/tracker (CREATE TABLE IF NOT EXISTS is not safe to race).
const schemaLockKey = "notify/schema"

// NewPGStore creates the table if needed and returns the store.
func NewPGStore(ctx context.Context, pool *pgxpool.Pool) (*PGStore, error) {
	if pool == nil {
		return nil, errors.New("notify: pool is nil")
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin schema transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, schemaLockKey); err != nil {
		return nil, fmt.Errorf("lock schema: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS notify_channels (
			username       TEXT PRIMARY KEY,
			kind           TEXT NOT NULL CHECK (kind IN ('ntfy')),
			server         TEXT NOT NULL,
			topic          TEXT NOT NULL,
			token_secret   TEXT NOT NULL DEFAULT '',
			redact_command BOOLEAN NOT NULL DEFAULT FALSE,
			updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`); err != nil {
		return nil, fmt.Errorf("create notify_channels: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit schema: %w", err)
	}
	return &PGStore{pool: pool}, nil
}

const channelColumns = `username, server, topic, token_secret, redact_command, updated_at`

func scanChannel(row pgx.Row) (Channel, error) {
	var ch Channel
	err := row.Scan(&ch.Username, &ch.Server, &ch.Topic, &ch.TokenSecret, &ch.RedactCommand, &ch.UpdatedAt)
	return ch, err
}

func (s *PGStore) Get(ctx context.Context, username string) (Channel, error) {
	ch, err := scanChannel(s.pool.QueryRow(ctx, `SELECT `+channelColumns+` FROM notify_channels WHERE username = $1`, username))
	if errors.Is(err, pgx.ErrNoRows) {
		return Channel{}, ErrNotFound
	}
	return ch, err
}

func (s *PGStore) Set(ctx context.Context, ch Channel) (Channel, error) {
	return scanChannel(s.pool.QueryRow(ctx, `
		INSERT INTO notify_channels (username, kind, server, topic, token_secret, redact_command, updated_at)
		VALUES ($1, 'ntfy', $2, $3, $4, $5, NOW())
		ON CONFLICT (username) DO UPDATE SET
			kind = 'ntfy', server = EXCLUDED.server, topic = EXCLUDED.topic,
			token_secret = EXCLUDED.token_secret, redact_command = EXCLUDED.redact_command,
			updated_at = NOW()
		RETURNING `+channelColumns,
		ch.Username, ch.Server, ch.Topic, ch.TokenSecret, ch.RedactCommand))
}

func (s *PGStore) Delete(ctx context.Context, username string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM notify_channels WHERE username = $1`, username)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PGStore) List(ctx context.Context) ([]Channel, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+channelColumns+` FROM notify_channels ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Channel
	for rows.Next() {
		ch, err := scanChannel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ch)
	}
	return out, rows.Err()
}
