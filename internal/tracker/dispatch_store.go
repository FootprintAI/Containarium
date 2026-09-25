package tracker

import (
	"context"
	"errors"
	"fmt"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Dispatch store (#2022): one durable row per dispatch of a routed
// `scope:<role>` issue. Exactly-once is NOT application logic — it is the
// partial unique index tracker_dispatches_active: at most one queued or
// running row per (username, connection, issue_number), so two
// dispatchers (or one restarted mid-tick) racing on the same issue get
// one insert and one unique violation. See
// docs/architecture/issue-triggered-agents.md ("Exactly-once").

// Dispatch is the storage-layer view of a TrackerDispatch.
type Dispatch struct {
	ID          string
	Username    string
	Connection  string
	IssueNumber int64
	Scope       string
	SkillID     string
	// RunID is chosen by the dispatcher before the run starts, so the
	// run JWT's run_id claim and this row always agree.
	RunID string
	// Depth is the issue's lineage depth. Always 0 until issue lineage
	// (#2024) and its dispatcher-side enforcement (#2025) land.
	Depth         int32
	State         pb.TrackerDispatchState
	FailureReason string
	// LabelsPending is set when the forge label write that projects
	// State failed; the retry is #2026's.
	LabelsPending bool
	CreatedAt     time.Time
	StartedAt     time.Time
	EndedAt       time.Time
}

// ErrDispatchActive is returned by InsertDispatch when the issue already
// has a queued or running dispatch — the exactly-once index said no. The
// caller skips the issue; it is not a failure.
var ErrDispatchActive = errors.New("tracker: issue already has an active dispatch")

// ErrDispatchNotFound is returned by GetDispatch for an unknown id.
var ErrDispatchNotFound = errors.New("tracker: dispatch not found")

// ErrInvalidDispatchTransition is returned by TransitionDispatch for a
// (from, to) pair the state machine never allows (anything out of a
// terminal state, or backwards).
var ErrInvalidDispatchTransition = errors.New("tracker: invalid dispatch state transition")

// pgUniqueViolation is SQLSTATE 23505.
const pgUniqueViolation = "23505"

// dispatchSchema is applied from Store.initSchema after
// tracker_connections. Deleting a connection drops its dispatch history
// and warnings, same as its routes.
const dispatchSchema = `
	CREATE TABLE IF NOT EXISTS tracker_dispatches (
		id             UUID PRIMARY KEY,
		seq            BIGSERIAL NOT NULL,
		username       TEXT NOT NULL,
		connection     TEXT NOT NULL,
		issue_number   BIGINT NOT NULL,
		scope          TEXT NOT NULL,
		skill_id       TEXT NOT NULL,
		run_id         TEXT NOT NULL DEFAULT '',
		depth          INT NOT NULL DEFAULT 0,
		state          TEXT NOT NULL CHECK (state IN ('queued', 'running', 'done', 'failed')),
		failure_reason TEXT NOT NULL DEFAULT '',
		labels_pending BOOLEAN NOT NULL DEFAULT false,
		created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		started_at     TIMESTAMPTZ,
		ended_at       TIMESTAMPTZ,
		FOREIGN KEY (username, connection) REFERENCES tracker_connections (username, name) ON DELETE CASCADE
	);

	-- The exactly-once guarantee (#2022).
	CREATE UNIQUE INDEX IF NOT EXISTS tracker_dispatches_active
		ON tracker_dispatches (username, connection, issue_number)
		WHERE state IN ('queued', 'running');

	CREATE INDEX IF NOT EXISTS tracker_dispatches_by_connection
		ON tracker_dispatches (username, connection, seq DESC);

	-- One stamped warning per (issue, unrouted scope), ever — not one
	-- per tick.
	CREATE TABLE IF NOT EXISTS tracker_dispatch_warnings (
		username     TEXT NOT NULL,
		connection   TEXT NOT NULL,
		issue_number BIGINT NOT NULL,
		scope        TEXT NOT NULL,
		created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		PRIMARY KEY (username, connection, issue_number, scope),
		FOREIGN KEY (username, connection) REFERENCES tracker_connections (username, name) ON DELETE CASCADE
	);
`

// dispatchStateToString / dispatchStateFromString convert at the store
// boundary; every caller above sees the typed enum.
func dispatchStateToString(s pb.TrackerDispatchState) (string, error) {
	switch s {
	case pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_QUEUED:
		return "queued", nil
	case pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_RUNNING:
		return "running", nil
	case pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_DONE:
		return "done", nil
	case pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_FAILED:
		return "failed", nil
	default:
		return "", fmt.Errorf("tracker: unknown dispatch state %v", s)
	}
}

func dispatchStateFromString(s string) pb.TrackerDispatchState {
	switch s {
	case "queued":
		return pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_QUEUED
	case "running":
		return pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_RUNNING
	case "done":
		return pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_DONE
	case "failed":
		return pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_FAILED
	default:
		return pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_UNSPECIFIED
	}
}

// validDispatchTransition is the state machine: out of an active state
// only, forward only. queued->done is allowed (a run can end before
// anything marked it running).
func validDispatchTransition(from, to pb.TrackerDispatchState) bool {
	const (
		queued  = pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_QUEUED
		running = pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_RUNNING
		done    = pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_DONE
		failed  = pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_FAILED
	)
	switch from {
	case queued:
		return to == running || to == done || to == failed
	case running:
		return to == done || to == failed
	default:
		return false
	}
}

// InsertDispatch inserts a new QUEUED dispatch row with a fresh id.
// Returns ErrDispatchActive if the issue already has a queued or running
// row, ErrNotFound if the connection does not exist.
func (s *Store) InsertDispatch(ctx context.Context, d Dispatch) (*Dispatch, error) {
	switch {
	case d.Username == "":
		return nil, errors.New("tracker: username is required")
	case d.Connection == "":
		return nil, errors.New("tracker: connection is required")
	case d.IssueNumber <= 0:
		return nil, errors.New("tracker: issue_number must be positive")
	case d.Scope == "":
		return nil, errors.New("tracker: scope is required")
	case d.SkillID == "":
		return nil, errors.New("tracker: skill_id is required")
	}

	out := d
	out.ID = uuid.NewString()
	out.State = pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_QUEUED
	out.FailureReason = ""
	out.LabelsPending = false
	out.StartedAt, out.EndedAt = time.Time{}, time.Time{}

	const q = `
		INSERT INTO tracker_dispatches (id, username, connection, issue_number, scope, skill_id, run_id, depth, state)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'queued')
		RETURNING created_at
	`
	if err := s.pool.QueryRow(ctx, q, out.ID, d.Username, d.Connection, d.IssueNumber, d.Scope, d.SkillID, d.RunID, d.Depth).
		Scan(&out.CreatedAt); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			switch pgErr.Code {
			case pgUniqueViolation:
				return nil, ErrDispatchActive
			case pgForeignKeyViolation:
				return nil, ErrNotFound
			}
		}
		return nil, fmt.Errorf("insert tracker dispatch: %w", err)
	}
	return &out, nil
}

// TransitionDispatch is the compare-and-set state change: it moves the
// row from `from` to `to` only if it is still in `from`. A lost race (or
// an unknown id) returns (false, nil) — never a double transition.
// Entering RUNNING stamps started_at; entering DONE/FAILED stamps
// ended_at. reason, when non-empty, is recorded as failure_reason.
func (s *Store) TransitionDispatch(ctx context.Context, id string, from, to pb.TrackerDispatchState, reason string, at time.Time) (bool, error) {
	if !validDispatchTransition(from, to) {
		return false, fmt.Errorf("%w: %v -> %v", ErrInvalidDispatchTransition, from, to)
	}
	fromStr, err := dispatchStateToString(from)
	if err != nil {
		return false, err
	}
	toStr, err := dispatchStateToString(to)
	if err != nil {
		return false, err
	}
	const q = `
		UPDATE tracker_dispatches SET
			state          = $3,
			started_at     = CASE WHEN $3 = 'running' THEN $4::timestamptz ELSE started_at END,
			ended_at       = CASE WHEN $3 IN ('done', 'failed') THEN $4::timestamptz ELSE ended_at END,
			failure_reason = CASE WHEN $5 <> '' THEN $5 ELSE failure_reason END
		WHERE id = $1 AND state = $2
	`
	tag, err := s.pool.Exec(ctx, q, id, fromStr, toStr, at, reason)
	if err != nil {
		return false, fmt.Errorf("transition tracker dispatch: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// SetDispatchLabelsPending records whether the forge still lags the
// row's state.
func (s *Store) SetDispatchLabelsPending(ctx context.Context, id string, pending bool) error {
	tag, err := s.pool.Exec(ctx, `UPDATE tracker_dispatches SET labels_pending = $2 WHERE id = $1`, id, pending)
	if err != nil {
		return fmt.Errorf("set tracker dispatch labels_pending: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrDispatchNotFound
	}
	return nil
}

const dispatchColumns = `id, username, connection, issue_number, scope, skill_id, run_id, depth, state,
	failure_reason, labels_pending, created_at, started_at, ended_at`

func scanDispatch(row pgx.Row) (*Dispatch, error) {
	var d Dispatch
	var state string
	var startedAt, endedAt *time.Time
	if err := row.Scan(&d.ID, &d.Username, &d.Connection, &d.IssueNumber, &d.Scope, &d.SkillID, &d.RunID, &d.Depth,
		&state, &d.FailureReason, &d.LabelsPending, &d.CreatedAt, &startedAt, &endedAt); err != nil {
		return nil, err
	}
	d.State = dispatchStateFromString(state)
	if startedAt != nil {
		d.StartedAt = *startedAt
	}
	if endedAt != nil {
		d.EndedAt = *endedAt
	}
	return &d, nil
}

// GetDispatch returns one row by id, or ErrDispatchNotFound.
func (s *Store) GetDispatch(ctx context.Context, id string) (*Dispatch, error) {
	d, err := scanDispatch(s.pool.QueryRow(ctx, `SELECT `+dispatchColumns+` FROM tracker_dispatches WHERE id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrDispatchNotFound
		}
		return nil, fmt.Errorf("select tracker dispatch: %w", err)
	}
	return d, nil
}

// ListDispatches returns a connection's dispatch rows, newest first.
// UNSPECIFIED state matches every state.
func (s *Store) ListDispatches(ctx context.Context, username, connection string, state pb.TrackerDispatchState) ([]Dispatch, error) {
	if username == "" {
		return nil, errors.New("tracker: username is required")
	}
	var stateFilter *string
	if state != pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_UNSPECIFIED {
		str, err := dispatchStateToString(state)
		if err != nil {
			return nil, err
		}
		stateFilter = &str
	}
	q := `SELECT ` + dispatchColumns + ` FROM tracker_dispatches
		WHERE username = $1 AND connection = $2 AND ($3::text IS NULL OR state = $3)
		ORDER BY seq DESC`
	rows, err := s.pool.Query(ctx, q, username, connection, stateFilter)
	if err != nil {
		return nil, fmt.Errorf("list tracker dispatches: %w", err)
	}
	defer rows.Close()
	var out []Dispatch
	for rows.Next() {
		d, err := scanDispatch(rows)
		if err != nil {
			return nil, fmt.Errorf("scan tracker dispatch row: %w", err)
		}
		out = append(out, *d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tracker dispatch rows: %w", err)
	}
	return out, nil
}

// RecordDispatchWarning records that the unrouted-scope warning for
// (issue, scope) is being posted. Returns true only the first time —
// the caller posts the comment only then, so an issue gets one warning
// ever, not one per tick. Concurrent dispatchers are safe: the primary
// key admits one inserter.
func (s *Store) RecordDispatchWarning(ctx context.Context, username, connection string, issue int64, scope string) (bool, error) {
	const q = `
		INSERT INTO tracker_dispatch_warnings (username, connection, issue_number, scope)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT DO NOTHING
	`
	tag, err := s.pool.Exec(ctx, q, username, connection, issue, scope)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgForeignKeyViolation {
			return false, ErrNotFound
		}
		return false, fmt.Errorf("record tracker dispatch warning: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// ForgetDispatchWarning undoes RecordDispatchWarning when the comment
// could not be posted, so the next tick tries again.
func (s *Store) ForgetDispatchWarning(ctx context.Context, username, connection string, issue int64, scope string) error {
	const q = `DELETE FROM tracker_dispatch_warnings WHERE username = $1 AND connection = $2 AND issue_number = $3 AND scope = $4`
	if _, err := s.pool.Exec(ctx, q, username, connection, issue, scope); err != nil {
		return fmt.Errorf("forget tracker dispatch warning: %w", err)
	}
	return nil
}

// DeleteQueuedDispatch removes a QUEUED row whose run was never started
// — the tick's post-insert re-read (#2023) found the issue no longer
// dispatchable (a peer finished it after this tick's list, or a human
// changed its labels). Only a QUEUED row can be removed; a row that
// moved on returns (false, nil).
func (s *Store) DeleteQueuedDispatch(ctx context.Context, id string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM tracker_dispatches WHERE id = $1 AND state = 'queued'`, id)
	if err != nil {
		return false, fmt.Errorf("delete queued tracker dispatch: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}
