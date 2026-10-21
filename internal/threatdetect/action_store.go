package threatdetect

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// PGActionStore persists SecurityActions to Postgres, sharing the findings
// pool. A throttle's previous CPU limit lives here, so this is the store
// whose absence makes the responder refuse to throttle or freeze.
type PGActionStore struct {
	pool *pgxpool.Pool
}

// NewActionStore creates the store and its schema.
func NewActionStore(ctx context.Context, pool *pgxpool.Pool) (*PGActionStore, error) {
	s := &PGActionStore{pool: pool}
	if err := s.initSchema(ctx); err != nil {
		return nil, fmt.Errorf("threatdetect: init security_actions schema: %w", err)
	}
	return s, nil
}

func (s *PGActionStore) initSchema(ctx context.Context) error {
	// killed_pid is the pid the signature rule's additive kill (#2638)
	// signalled for the same finding, NULL when none.
	schema := `
		CREATE TABLE IF NOT EXISTS security_actions (
			id              BIGSERIAL PRIMARY KEY,
			finding_id      BIGINT      NOT NULL REFERENCES security_findings(id),
			container       TEXT        NOT NULL,
			tenant_id       TEXT        NOT NULL,
			action          TEXT        NOT NULL,
			prev_cpu_count  TEXT        NOT NULL DEFAULT '',
			prev_cpu_allow  TEXT        NOT NULL DEFAULT '',
			killed_pid      INTEGER,
			error           TEXT        NOT NULL DEFAULT '',
			pending         BOOLEAN     NOT NULL DEFAULT FALSE,
			applied_at      TIMESTAMPTZ NOT NULL,
			expires_at      TIMESTAMPTZ NOT NULL,
			released_at     TIMESTAMPTZ,
			released_by     TEXT        NOT NULL DEFAULT ''
		);
		ALTER TABLE security_actions ADD COLUMN IF NOT EXISTS pending BOOLEAN NOT NULL DEFAULT FALSE;
		ALTER TABLE security_actions ADD COLUMN IF NOT EXISTS instance_id TEXT NOT NULL DEFAULT '';
		CREATE UNIQUE INDEX IF NOT EXISTS security_actions_open_per_container
			ON security_actions (container) WHERE released_at IS NULL;
	`
	_, err := s.pool.Exec(ctx, schema)
	return err
}

const actionColumns = `id, finding_id, container, tenant_id, action, prev_cpu_count, prev_cpu_allow,
	killed_pid, error, pending, applied_at, expires_at, released_at, released_by, instance_id`

func (s *PGActionStore) Insert(ctx context.Context, a *SecurityAction) error {
	var releasedAt *time.Time
	if !a.ReleasedAt.IsZero() {
		t := a.ReleasedAt
		releasedAt = &t
	}
	var killedPID *int64
	if a.KilledPID != 0 {
		v := int64(a.KilledPID)
		killedPID = &v
	}
	row := s.pool.QueryRow(ctx, `
		INSERT INTO security_actions
			(finding_id, container, tenant_id, action, prev_cpu_count, prev_cpu_allow, killed_pid, error, pending, applied_at, expires_at, released_at, released_by, instance_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		RETURNING id
	`, a.FindingID, a.Container, a.TenantID, a.Action.String(), a.PrevCPUCount, a.PrevCPUAllowance,
		killedPID, a.Error, a.Pending, a.AppliedAt, a.ExpiresAt, releasedAt, a.ReleasedBy, a.InstanceID)
	if err := row.Scan(&a.ID); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation {
			return fmt.Errorf("threatdetect: %s: %w", a.Container, ErrActionOpen)
		}
		return fmt.Errorf("threatdetect: insert security action: %w", err)
	}
	return nil
}

func (s *PGActionStore) Open(ctx context.Context, container string) (*SecurityAction, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+actionColumns+` FROM security_actions WHERE container = $1 AND released_at IS NULL`, container)
	a, err := scanAction(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("threatdetect: %s: %w", container, ErrNoOpenAction)
		}
		return nil, err
	}
	return a, nil
}

func (s *PGActionStore) Release(ctx context.Context, id int64, releasedBy string, at time.Time) error {
	tag, err := s.pool.Exec(ctx, `UPDATE security_actions SET released_at = $2, released_by = $3 WHERE id = $1 AND released_at IS NULL`, id, at, releasedBy)
	if err != nil {
		return fmt.Errorf("threatdetect: release security action %d: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("threatdetect: action %d: %w", id, ErrNoOpenAction)
	}
	return nil
}

func (s *PGActionStore) ListExpired(ctx context.Context, now time.Time) ([]*SecurityAction, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+actionColumns+` FROM security_actions WHERE released_at IS NULL AND NOT pending AND expires_at <= $1 ORDER BY expires_at`, now)
	if err != nil {
		return nil, fmt.Errorf("threatdetect: list expired security actions: %w", err)
	}
	defer rows.Close()
	var out []*SecurityAction
	for rows.Next() {
		a, err := scanAction(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("threatdetect: iterate security actions: %w", err)
	}
	return out, nil
}

func (s *PGActionStore) MarkApplied(ctx context.Context, id int64) error {
	tag, err := s.pool.Exec(ctx, `UPDATE security_actions SET pending = FALSE WHERE id = $1 AND released_at IS NULL AND pending`, id)
	if err != nil {
		return fmt.Errorf("threatdetect: mark security action %d applied: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("threatdetect: action %d: %w", id, ErrNoOpenAction)
	}
	return nil
}

func (s *PGActionStore) Fail(ctx context.Context, id int64, cause string, at time.Time) error {
	tag, err := s.pool.Exec(ctx, `UPDATE security_actions SET pending = FALSE, error = $2, released_at = $3, released_by = $4 WHERE id = $1 AND released_at IS NULL`,
		id, cause, at, ReleasedByError)
	if err != nil {
		return fmt.Errorf("threatdetect: fail security action %d: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("threatdetect: action %d: %w", id, ErrNoOpenAction)
	}
	return nil
}

func (s *PGActionStore) Latest(ctx context.Context, container string) (*SecurityAction, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+actionColumns+` FROM security_actions WHERE container = $1 ORDER BY id DESC LIMIT 1`, container)
	a, err := scanAction(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("threatdetect: %s: %w", container, ErrNoOpenAction)
		}
		return nil, err
	}
	return a, nil
}

func (s *PGActionStore) ListOrphaned(ctx context.Context, cutoff time.Time) ([]*SecurityAction, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+actionColumns+` FROM security_actions WHERE released_at IS NULL AND pending AND applied_at <= $1 ORDER BY applied_at`, cutoff)
	if err != nil {
		return nil, fmt.Errorf("threatdetect: list orphaned security actions: %w", err)
	}
	defer rows.Close()
	var out []*SecurityAction
	for rows.Next() {
		a, err := scanAction(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("threatdetect: iterate security actions: %w", err)
	}
	return out, nil
}

func (s *PGActionStore) ListByFinding(ctx context.Context, findingID int64) ([]*SecurityAction, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+actionColumns+` FROM security_actions WHERE finding_id = $1 ORDER BY id DESC`, findingID)
	if err != nil {
		return nil, fmt.Errorf("threatdetect: list security actions for finding %d: %w", findingID, err)
	}
	defer rows.Close()
	var out []*SecurityAction
	for rows.Next() {
		a, err := scanAction(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("threatdetect: iterate security actions: %w", err)
	}
	return out, nil
}

func scanAction(row rowScanner) (*SecurityAction, error) {
	var a SecurityAction
	var action string
	var releasedAt *time.Time
	var killedPID *int64
	if err := row.Scan(&a.ID, &a.FindingID, &a.Container, &a.TenantID, &action, &a.PrevCPUCount, &a.PrevCPUAllowance,
		&killedPID, &a.Error, &a.Pending, &a.AppliedAt, &a.ExpiresAt, &releasedAt, &a.ReleasedBy, &a.InstanceID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		return nil, fmt.Errorf("threatdetect: scan security action: %w", err)
	}
	a.Action = pb.ProcessAction(pb.ProcessAction_value[action])
	if releasedAt != nil {
		a.ReleasedAt = *releasedAt
	}
	if killedPID != nil && *killedPID > 0 && *killedPID <= math.MaxUint32 {
		a.KilledPID = uint32(*killedPID)
	}
	return &a, nil
}
