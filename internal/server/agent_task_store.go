package server

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AgentTaskQueue is the pull-based run queue's storage contract (#1182).
// Two impls, selected as NetworkPolicyStore and CrewRunStore are:
// PostgresAgentTaskQueue when the daemon has a pool, MemAgentTaskQueue for
// --standalone daemons and tests.
//
// The lease semantics are the whole contract and both impls must match:
//
//   - Enqueue appends (FIFO).
//   - Lease hands out the oldest *visible* task and hides it for a window,
//     minting a fresh token. Visible means never leased, or the lease
//     deadline has passed.
//   - Complete removes a task only if the caller presents the *current*
//     token, so a slow worker cannot clobber the retry that overtook it.
//
// One thing the durable impl must get right that the in-memory one never
// had to: **lease tokens have to stay unique across a daemon restart.** The
// in-memory queue mints them from a counter that resets to zero on start, so
// after a restart it would happily re-mint "lease-1" — and a worker holding
// the pre-restart "lease-1" would then be accepted as the current owner,
// completing a task that had already been redelivered to someone else. The
// Postgres impl draws tokens from a sequence, which does not reset. That is
// what makes "a pre-restart lease token is rejected" hold rather than being
// an accident of timing.
type AgentTaskQueue interface {
	Enqueue(ctx context.Context, skillID, inputJSON string) (string, error)
	Lease(ctx context.Context, skillFilter string, d time.Duration) (leasedTask, bool, error)
	Complete(ctx context.Context, taskID, leaseToken, artifactJSON, errMsg string) (bool, error)
	Depth(ctx context.Context) (int, error)
	Result(ctx context.Context, taskID string) (taskResult, bool, error)
}

// --- in-memory ------------------------------------------------------

// MemAgentTaskQueue adapts the existing lock-guarded queue to the interface.
// Tasks do not survive a daemon restart.
type MemAgentTaskQueue struct{ q *agentTaskQueue }

func NewMemAgentTaskQueue() *MemAgentTaskQueue {
	return &MemAgentTaskQueue{q: newAgentTaskQueue()}
}

func (m *MemAgentTaskQueue) Enqueue(_ context.Context, skillID, inputJSON string) (string, error) {
	return m.q.enqueue(skillID, inputJSON), nil
}

func (m *MemAgentTaskQueue) Lease(_ context.Context, skillFilter string, d time.Duration) (leasedTask, bool, error) {
	t, ok := m.q.lease(skillFilter, d)
	return t, ok, nil
}

func (m *MemAgentTaskQueue) Complete(_ context.Context, taskID, leaseToken, artifactJSON, errMsg string) (bool, error) {
	return m.q.complete(taskID, leaseToken, artifactJSON, errMsg), nil
}

func (m *MemAgentTaskQueue) Depth(_ context.Context) (int, error) { return m.q.depth(), nil }

func (m *MemAgentTaskQueue) Result(_ context.Context, taskID string) (taskResult, bool, error) {
	r, ok := m.q.result(taskID)
	return r, ok, nil
}

// --- postgres -------------------------------------------------------

// PostgresAgentTaskQueue persists tasks so a daemon restart does not lose
// them.
type PostgresAgentTaskQueue struct{ pool *pgxpool.Pool }

// NewPostgresAgentTaskQueue creates the tables and the token sequence.
func NewPostgresAgentTaskQueue(ctx context.Context, pool *pgxpool.Pool) (*PostgresAgentTaskQueue, error) {
	const schema = `
		CREATE TABLE IF NOT EXISTS agent_tasks (
			id TEXT PRIMARY KEY,
			skill_id TEXT NOT NULL,
			input_json TEXT NOT NULL DEFAULT '',
			lease_token TEXT,
			lease_deadline TIMESTAMPTZ,
			enqueued_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
		-- Lease scans read (visible, oldest-first) filtered by skill.
		CREATE INDEX IF NOT EXISTS agent_tasks_lease_idx
			ON agent_tasks (skill_id, enqueued_at);

		CREATE TABLE IF NOT EXISTS agent_task_results (
			id TEXT PRIMARY KEY,
			skill_id TEXT NOT NULL,
			artifact_json TEXT NOT NULL DEFAULT '',
			error TEXT NOT NULL DEFAULT '',
			completed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);

		-- Ids and lease tokens come from sequences rather than a counter in
		-- process memory, so neither restarts at zero. A reused lease token
		-- would let a worker holding a pre-restart lease complete a task that
		-- had since been redelivered.
		CREATE SEQUENCE IF NOT EXISTS agent_task_id_seq;
		CREATE SEQUENCE IF NOT EXISTS agent_lease_token_seq;
	`
	if _, err := pool.Exec(ctx, schema); err != nil {
		return nil, fmt.Errorf("init agent_tasks schema: %w", err)
	}
	return &PostgresAgentTaskQueue{pool: pool}, nil
}

func (p *PostgresAgentTaskQueue) Enqueue(ctx context.Context, skillID, inputJSON string) (string, error) {
	const q = `
		INSERT INTO agent_tasks (id, skill_id, input_json)
		VALUES ('task-' || nextval('agent_task_id_seq'), $1, $2)
		RETURNING id
	`
	var id string
	if err := p.pool.QueryRow(ctx, q, skillID, inputJSON).Scan(&id); err != nil {
		return "", fmt.Errorf("enqueue task: %w", err)
	}
	return id, nil
}

// Lease claims the oldest visible task in one statement.
//
// FOR UPDATE SKIP LOCKED is what makes this safe with many workers polling at
// once: each concurrent lease takes a different row instead of blocking on the
// same one and then handing the same task to two workers. The in-memory queue
// got this from holding a mutex across the whole scan; a database needs to be
// told.
func (p *PostgresAgentTaskQueue) Lease(ctx context.Context, skillFilter string, d time.Duration) (leasedTask, bool, error) {
	if d <= 0 {
		d = defaultLeaseDuration
	}
	const q = `
		UPDATE agent_tasks SET
			lease_token = 'lease-' || nextval('agent_lease_token_seq'),
			lease_deadline = NOW() + $2::interval
		WHERE id = (
			SELECT id FROM agent_tasks
			WHERE ($1 = '' OR skill_id = $1)
			  AND (lease_token IS NULL OR lease_deadline <= NOW())
			ORDER BY enqueued_at
			FOR UPDATE SKIP LOCKED
			LIMIT 1
		)
		RETURNING id, skill_id, input_json, lease_token
	`
	var t leasedTask
	err := p.pool.QueryRow(ctx, q, skillFilter, d.String()).
		Scan(&t.ID, &t.SkillID, &t.InputJSON, &t.LeaseToken)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return leasedTask{}, false, nil
	case err != nil:
		return leasedTask{}, false, fmt.Errorf("lease task: %w", err)
	}
	return t, true, nil
}

// Complete removes the task and records its outcome, atomically, and only when
// the presented token is the current one.
func (p *PostgresAgentTaskQueue) Complete(ctx context.Context, taskID, leaseToken, artifactJSON, errMsg string) (bool, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("complete task %s: begin: %w", taskID, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// The token comparison lives in the DELETE, so checking and removing cannot
	// interleave with a redelivery between them.
	const del = `
		DELETE FROM agent_tasks
		WHERE id = $1 AND lease_token IS NOT NULL AND lease_token = $2
		RETURNING skill_id
	`
	var skillID string
	switch err := tx.QueryRow(ctx, del, taskID, leaseToken).Scan(&skillID); {
	case errors.Is(err, pgx.ErrNoRows):
		// Gone, never leased, or a newer lease owns it now.
		return false, nil
	case err != nil:
		return false, fmt.Errorf("complete task %s: %w", taskID, err)
	}

	const ins = `
		INSERT INTO agent_task_results (id, skill_id, artifact_json, error, completed_at)
		VALUES ($1, $2, $3, $4, NOW())
		ON CONFLICT (id) DO UPDATE SET
			artifact_json = EXCLUDED.artifact_json,
			error = EXCLUDED.error,
			completed_at = NOW()
	`
	if _, err := tx.Exec(ctx, ins, taskID, skillID, artifactJSON, errMsg); err != nil {
		return false, fmt.Errorf("record result %s: %w", taskID, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("complete task %s: commit: %w", taskID, err)
	}
	return true, nil
}

func (p *PostgresAgentTaskQueue) Depth(ctx context.Context) (int, error) {
	var n int
	if err := p.pool.QueryRow(ctx, `SELECT COUNT(*) FROM agent_tasks`).Scan(&n); err != nil {
		return 0, fmt.Errorf("queue depth: %w", err)
	}
	return n, nil
}

func (p *PostgresAgentTaskQueue) Result(ctx context.Context, taskID string) (taskResult, bool, error) {
	const q = `SELECT skill_id, artifact_json, error, completed_at FROM agent_task_results WHERE id = $1`
	var r taskResult
	switch err := p.pool.QueryRow(ctx, q, taskID).
		Scan(&r.skillID, &r.artifactJSON, &r.errMsg, &r.completedAt); {
	case errors.Is(err, pgx.ErrNoRows):
		return taskResult{}, false, nil
	case err != nil:
		return taskResult{}, false, fmt.Errorf("get task result %s: %w", taskID, err)
	}
	return r, true, nil
}

// setClock overrides the queue's clock. Test-only: lease expiry is a
// wall-clock property, and the alternative to injecting a clock is a test that
// sleeps for the lease duration.
func (m *MemAgentTaskQueue) setClock(now func() time.Time) { m.q.now = now }
