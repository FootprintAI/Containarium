// Package pgstore is the Postgres retention.Store. It is a separate package
// so the containarium client binary does not link the database driver.
package pgstore

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/footprintai/containarium/internal/retention"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Store keeps the mode in a singleton row, the policy bookkeeping in another (locked by every set,
// so revisions never repeat), the set windows one row per class, and the
// active holds one row per org. A released hold's row is deleted; its history
// is in the audit log.
type Store struct {
	pool *pgxpool.Pool
}

// bootstrapLockKey serializes concurrent bootstraps (daemons starting
// together) so the constraint upgrade and the hold-id normalisation below
// never race each other.
const bootstrapLockKey = "containarium.retention.bootstrap"

// New bootstraps the tables on a pool the daemon already owns. Idempotent,
// and safe when several daemons start at once. Over a schema an earlier
// release created, it also upgrades the data in place (see upgrade).
func New(ctx context.Context, pool *pgxpool.Pool) (*Store, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin retention bootstrap: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, bootstrapLockKey); err != nil {
		return nil, fmt.Errorf("lock retention bootstrap: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS retention_policy (
			id         SMALLINT PRIMARY KEY CHECK (id = 1),
			revision   BIGINT NOT NULL DEFAULT 0,
			updated_at TIMESTAMPTZ,
			updated_by TEXT NOT NULL DEFAULT ''
		);
		INSERT INTO retention_policy (id) VALUES (1) ON CONFLICT (id) DO NOTHING;
		CREATE TABLE IF NOT EXISTS retention_windows (
			class INTEGER PRIMARY KEY,
			days  INTEGER NOT NULL CHECK (days > 0)
		);
		-- The upper bound (retention.MaxDays) as a named constraint. It is
		-- added NOT VALID, so existing rows are not checked yet: upgrade
		-- clamps any row above the cap, then validates the constraint.
		DO $$ BEGIN
			IF NOT EXISTS (SELECT 1 FROM pg_constraint
				WHERE conrelid = 'retention_windows'::regclass AND conname = 'retention_windows_days_max') THEN
				ALTER TABLE retention_windows ADD CONSTRAINT retention_windows_days_max CHECK (days <= `+maxDaysSQL+`) NOT VALID;
			END IF;
		END $$;
		-- The daemon-wide mode: a singleton row, DRY_RUN (1) until an admin sets
		-- it. updated_at stays NULL until the first set.
		CREATE TABLE IF NOT EXISTS retention_mode (
			id         SMALLINT PRIMARY KEY CHECK (id = 1),
			mode       INTEGER NOT NULL DEFAULT 1 CHECK (mode IN (1, 2)),
			updated_at TIMESTAMPTZ,
			updated_by TEXT NOT NULL DEFAULT ''
		);
		INSERT INTO retention_mode (id) VALUES (1) ON CONFLICT (id) DO NOTHING;
		CREATE TABLE IF NOT EXISTS retention_legal_holds (
			org_id TEXT PRIMARY KEY,
			reason TEXT NOT NULL,
			set_by TEXT NOT NULL,
			set_at TIMESTAMPTZ NOT NULL
		);
	`); err != nil {
		return nil, fmt.Errorf("init retention schema: %w", err)
	}
	if err := upgrade(ctx, tx); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit retention bootstrap: %w", err)
	}
	return &Store{pool: pool}, nil
}

// upgrade brings data an earlier release stored into line with today's
// rules, inside the bootstrap transaction. Each change is logged.
//
//   - A window above retention.MaxDays (possible before the cap existed) is
//     clamped to the cap, then the cap's CHECK is validated. Failing the
//     bootstrap instead would leave every retention call UNAVAILABLE.
//   - A hold whose org id has surrounding whitespace (possible before ids
//     were trimmed) is stored under the trimmed id, so it can be released
//     by that id and the sweepers match it against record org ids. When
//     several stored ids trim to the same org, the earliest hold is kept and
//     each other one is logged in full and removed: the org stays held.
func upgrade(ctx context.Context, tx pgx.Tx) error {
	rows, err := tx.Query(ctx, `WITH old AS (
			SELECT class, days FROM retention_windows WHERE days > $1 FOR UPDATE
		)
		UPDATE retention_windows w SET days = $1 FROM old WHERE w.class = old.class
		RETURNING w.class, old.days`, retention.MaxDays)
	if err != nil {
		return fmt.Errorf("clamp retention windows: %w", err)
	}
	for rows.Next() {
		var class, days int32
		if err := rows.Scan(&class, &days); err != nil {
			rows.Close()
			return fmt.Errorf("clamp retention windows: %w", err)
		}
		log.Printf("Retention: clamped the stored %v window from %d to %d days (the cap)", pb.RetentionClass(class), days, retention.MaxDays)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("clamp retention windows: %w", err)
	}
	if _, err := tx.Exec(ctx, `ALTER TABLE retention_windows VALIDATE CONSTRAINT retention_windows_days_max`); err != nil {
		return fmt.Errorf("validate the retention window cap: %w", err)
	}
	return normaliseHoldIDs(ctx, tx)
}

// normaliseHoldIDs trims stored hold org ids the way retention.NormalizeHold
// does; see upgrade.
func normaliseHoldIDs(ctx context.Context, tx pgx.Tx) error {
	rows, err := tx.Query(ctx, `SELECT org_id, reason, set_by, set_at FROM retention_legal_holds ORDER BY set_at, org_id`)
	if err != nil {
		return fmt.Errorf("read legal holds: %w", err)
	}
	var holds []*pb.LegalHold
	for rows.Next() {
		h, err := scanHold(rows)
		if err != nil {
			rows.Close()
			return fmt.Errorf("read legal holds: %w", err)
		}
		holds = append(holds, h)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read legal holds: %w", err)
	}
	// Group by trimmed id; holds are ordered by set_at, so the first of a
	// group is the earliest and is the one kept.
	groups := map[string][]*pb.LegalHold{}
	var order []string
	for _, h := range holds {
		id := strings.TrimSpace(h.GetOrgId())
		if id == "" {
			log.Printf("Warning: retention: the legal hold stored as %q has an empty org id once trimmed; left as it is", h.GetOrgId())
			continue
		}
		if _, seen := groups[id]; !seen {
			order = append(order, id)
		}
		groups[id] = append(groups[id], h)
	}
	for _, id := range order {
		g := groups[id]
		if len(g) == 1 && g[0].GetOrgId() == id {
			continue // already normal
		}
		for _, h := range g[1:] {
			log.Printf("Retention: removed the legal hold stored as %q (reason %q, set by %s at %s): org %q is held by an earlier hold",
				h.GetOrgId(), h.GetReason(), h.GetSetBy(), h.GetSetAt().AsTime().Format(time.RFC3339), id)
			if _, err := tx.Exec(ctx, `DELETE FROM retention_legal_holds WHERE org_id = $1`, h.GetOrgId()); err != nil {
				return fmt.Errorf("normalise legal hold %q: %w", h.GetOrgId(), err)
			}
		}
		if g[0].GetOrgId() != id {
			if _, err := tx.Exec(ctx, `UPDATE retention_legal_holds SET org_id = $1 WHERE org_id = $2`, id, g[0].GetOrgId()); err != nil {
				return fmt.Errorf("normalise legal hold %q: %w", g[0].GetOrgId(), err)
			}
			log.Printf("Retention: the legal hold stored as %q is now stored as %q", g[0].GetOrgId(), id)
		}
	}
	return nil
}

// maxDaysSQL is retention.MaxDays as SQL text for the CHECK constraint.
var maxDaysSQL = strconv.Itoa(int(retention.MaxDays))

// readPolicy reads the bookkeeping row and every window in one statement, so
// a concurrent set can never be seen half applied. It never locks: SetPolicy
// takes the row lock in a statement of its own first (see there). The row is
// seeded at bootstrap, so no row is a damaged table and an error.
func readPolicy(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}) (*pb.RetentionPolicy, map[pb.RetentionClass]int32, error) {
	rows, err := q.Query(ctx, `SELECT p.revision, p.updated_at, p.updated_by, w.class, w.days
		FROM retention_policy p LEFT JOIN retention_windows w ON true WHERE p.id = 1`)
	if err != nil {
		return nil, nil, fmt.Errorf("read retention policy: %w", err)
	}
	defer rows.Close()
	var (
		found     bool
		revision  int64
		updatedAt *time.Time
		updatedBy string
		set       = map[pb.RetentionClass]int32{}
	)
	for rows.Next() {
		var class, days *int32
		if err := rows.Scan(&revision, &updatedAt, &updatedBy, &class, &days); err != nil {
			return nil, nil, fmt.Errorf("read retention policy: %w", err)
		}
		found = true
		if class != nil && days != nil {
			set[pb.RetentionClass(*class)] = *days
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("read retention policy: %w", err)
	}
	if !found {
		return nil, nil, fmt.Errorf("read retention policy: the policy row is missing")
	}
	return retention.BuildPolicy(set, revision, updatedAt, updatedBy), set, nil
}

func (s *Store) GetPolicy(ctx context.Context) (*pb.RetentionPolicy, error) {
	p, _, err := readPolicy(ctx, s.pool)
	return p, err
}

func (s *Store) SetPolicy(ctx context.Context, ws []*pb.RetentionWindow, updatedBy string, beforeCommit func(*retention.PolicySetResult) error) (*retention.PolicySetResult, error) {
	changes, err := retention.ValidateWindows(ws)
	if err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin retention policy set: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Lock the policy row in a statement of its own, then read in a second
	// one. Under READ COMMITTED a statement that waited on a row lock
	// re-checks only the locked row; joined window rows would still come
	// from the snapshot taken before the wait, so a set that waited for
	// another would report (and audit) windows without that set's changes.
	// The second statement takes a fresh snapshot after the lock is held.
	if _, err := tx.Exec(ctx, `SELECT 1 FROM retention_policy WHERE id = 1 FOR UPDATE`); err != nil {
		return nil, fmt.Errorf("lock retention policy: %w", err)
	}
	prev, set, err := readPolicy(ctx, tx)
	if err != nil {
		return nil, err
	}
	for c, d := range changes {
		set[c] = d
		if _, err := tx.Exec(ctx, `INSERT INTO retention_windows (class, days) VALUES ($1, $2)
			ON CONFLICT (class) DO UPDATE SET days = EXCLUDED.days`, int32(c), d); err != nil {
			return nil, fmt.Errorf("store retention window: %w", err)
		}
	}
	now := retention.Now()
	res := &retention.PolicySetResult{Previous: prev, Current: retention.BuildPolicy(set, prev.GetRevision()+1, &now, updatedBy)}
	if _, err := tx.Exec(ctx, `UPDATE retention_policy SET revision = $1, updated_at = $2, updated_by = $3 WHERE id = 1`,
		res.Current.GetRevision(), now, updatedBy); err != nil {
		return nil, fmt.Errorf("store retention policy: %w", err)
	}
	if beforeCommit != nil {
		if err := beforeCommit(res); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit retention policy: %w", err)
	}
	return res, nil
}

// readMode reads the mode row; lock is appended (" FOR UPDATE" inside a set).
func readMode(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, lock string) (*pb.RetentionModeState, error) {
	var (
		mode      int32
		updatedAt *time.Time
		updatedBy string
	)
	if err := q.QueryRow(ctx, `SELECT mode, updated_at, updated_by FROM retention_mode WHERE id = 1`+lock).
		Scan(&mode, &updatedAt, &updatedBy); err != nil {
		return nil, fmt.Errorf("read retention mode: %w", err)
	}
	return retention.BuildModeState(pb.RetentionMode(mode), updatedAt, updatedBy), nil
}

func (s *Store) GetMode(ctx context.Context) (*pb.RetentionModeState, error) {
	return readMode(ctx, s.pool, "")
}

func (s *Store) SetMode(ctx context.Context, mode pb.RetentionMode, updatedBy string, beforeCommit func(*retention.ModeSetResult) error) (*retention.ModeSetResult, error) {
	if err := retention.ValidateMode(mode); err != nil {
		return nil, err
	}
	var res *retention.ModeSetResult
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		prev, err := readMode(ctx, tx, " FOR UPDATE")
		if err != nil {
			return err
		}
		now := retention.Now()
		res = &retention.ModeSetResult{Previous: prev, Current: retention.BuildModeState(mode, &now, updatedBy)}
		if _, err := tx.Exec(ctx, `UPDATE retention_mode SET mode = $1, updated_at = $2, updated_by = $3 WHERE id = 1`,
			int32(mode), now, updatedBy); err != nil {
			return fmt.Errorf("store retention mode: %w", err)
		}
		if beforeCommit != nil {
			return beforeCommit(res)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (s *Store) ListHolds(ctx context.Context) ([]*pb.LegalHold, error) {
	rows, err := s.pool.Query(ctx, `SELECT org_id, reason, set_by, set_at FROM retention_legal_holds ORDER BY org_id`)
	if err != nil {
		return nil, fmt.Errorf("list legal holds: %w", err)
	}
	defer rows.Close()
	out := []*pb.LegalHold{}
	for rows.Next() {
		h, err := scanHold(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func scanHold(r pgx.Row) (*pb.LegalHold, error) {
	var (
		h     pb.LegalHold
		setAt time.Time
	)
	if err := r.Scan(&h.OrgId, &h.Reason, &h.SetBy, &setAt); err != nil {
		return nil, err
	}
	h.SetAt = timestamppb.New(setAt)
	return &h, nil
}

func (s *Store) SetHold(ctx context.Context, orgID, reason, setBy string, beforeCommit func(*pb.LegalHold) error) (*pb.LegalHold, error) {
	orgID, err := retention.NormalizeHold(orgID, reason, true)
	if err != nil {
		return nil, err
	}
	h := &pb.LegalHold{OrgId: orgID, Reason: reason, SetBy: setBy, SetAt: timestamppb.New(retention.Now())}
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO retention_legal_holds (org_id, reason, set_by, set_at)
			VALUES ($1, $2, $3, $4) ON CONFLICT (org_id) DO NOTHING`, orgID, reason, setBy, h.GetSetAt().AsTime())
		if err != nil {
			return fmt.Errorf("store legal hold: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return retention.ErrHoldExists
		}
		if beforeCommit != nil {
			return beforeCommit(h)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return h, nil
}

func (s *Store) ReleaseHold(ctx context.Context, orgID, _ string, beforeCommit func(*pb.LegalHold) error) (*pb.LegalHold, error) {
	orgID, err := retention.NormalizeHold(orgID, "", false)
	if err != nil {
		return nil, err
	}
	var h *pb.LegalHold
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		var err error
		h, err = scanHold(tx.QueryRow(ctx, `DELETE FROM retention_legal_holds WHERE org_id = $1
			RETURNING org_id, reason, set_by, set_at`, orgID))
		if errors.Is(err, pgx.ErrNoRows) {
			return retention.ErrHoldNotFound
		}
		if err != nil {
			return fmt.Errorf("release legal hold: %w", err)
		}
		if beforeCommit != nil {
			return beforeCommit(h)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return h, nil
}

// inTx runs fn in a transaction, committing only when fn succeeds.
func (s *Store) inTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
