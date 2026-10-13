package alert

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// PGCredentialStateStore is the Postgres CredentialStateStore: one row per
// skill holding the last credential source the watcher saw. The source is
// stored by its proto enum NAME, so a reader of the table never needs the
// numeric mapping, and parsed back through the generated value map.
type PGCredentialStateStore struct {
	pool *pgxpool.Pool
}

// NewPGCredentialStateStore creates the table if needed.
func NewPGCredentialStateStore(ctx context.Context, pool *pgxpool.Pool) (*PGCredentialStateStore, error) {
	s := &PGCredentialStateStore{pool: pool}
	if _, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS code_credential_watch_state (
			skill_id TEXT PRIMARY KEY,
			credential_source TEXT NOT NULL,
			observed_at TIMESTAMPTZ NOT NULL
		)`); err != nil {
		return nil, fmt.Errorf("initialize code_credential_watch_state: %w", err)
	}
	return s, nil
}

// LastSeen implements CredentialStateStore.
func (s *PGCredentialStateStore) LastSeen(ctx context.Context, skillID string) (pb.CodeCredentialSource, bool, error) {
	var name string
	err := s.pool.QueryRow(ctx,
		`SELECT credential_source FROM code_credential_watch_state WHERE skill_id = $1`, skillID).Scan(&name)
	if errors.Is(err, pgx.ErrNoRows) {
		return pb.CodeCredentialSource_CODE_CREDENTIAL_SOURCE_UNSPECIFIED, false, nil
	}
	if err != nil {
		return pb.CodeCredentialSource_CODE_CREDENTIAL_SOURCE_UNSPECIFIED, false, fmt.Errorf("read credential state for %s: %w", skillID, err)
	}
	v, ok := pb.CodeCredentialSource_value[name]
	if !ok {
		return pb.CodeCredentialSource_CODE_CREDENTIAL_SOURCE_UNSPECIFIED, false, fmt.Errorf("credential state for %s: unrecognized source %q", skillID, name)
	}
	return pb.CodeCredentialSource(v), true, nil
}

// Record implements CredentialStateStore (upsert).
func (s *PGCredentialStateStore) Record(ctx context.Context, skillID string, src pb.CodeCredentialSource, observedAt time.Time) error {
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO code_credential_watch_state (skill_id, credential_source, observed_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (skill_id) DO UPDATE
			SET credential_source = EXCLUDED.credential_source, observed_at = EXCLUDED.observed_at`,
		skillID, src.String(), observedAt); err != nil {
		return fmt.Errorf("record credential state for %s: %w", skillID, err)
	}
	return nil
}
