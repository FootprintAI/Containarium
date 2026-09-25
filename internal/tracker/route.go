package tracker

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Scope routes (#2021): (tenant, connection, scope) -> skill id. The
// dispatcher (#2022) starts a run only for a `scope:<scope>` label that
// has a route here; an unmapped scope is never dispatched. See
// docs/architecture/issue-triggered-agents.md.

// ScopeLabelPrefix is the label prefix a route's Scope is the suffix of:
// the route with Scope "product" matches the label "scope:product".
const ScopeLabelPrefix = "scope:"

// Route is the storage-layer view of a TrackerRoute.
type Route struct {
	Username   string
	Connection string
	Scope      string
	SkillID    string
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// ErrRouteNotFound is returned by GetRoute / DeleteRoute when the
// (username, connection, scope) tuple has no row. SetRoute against a
// connection that does not exist returns ErrNotFound (the connection's
// error), not this one.
var ErrRouteNotFound = errors.New("tracker: route not found")

// routeScopeRe bounds a scope to what both GitHub and GitLab accept in a
// label and what a human would type after "scope:": no whitespace, no
// colon or slash, no leading punctuation, at most 64 characters.
var routeScopeRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// ValidateRouteScope rejects a scope that could never match a label as a
// route suffix. The full label ("scope:product") gets a pointed error,
// since it is the likeliest mistake.
func ValidateRouteScope(scope string) error {
	if scope == "" {
		return errors.New("tracker: scope is required")
	}
	if strings.HasPrefix(scope, ScopeLabelPrefix) {
		return fmt.Errorf("tracker: scope must be the label suffix without %q (use %q)", ScopeLabelPrefix, strings.TrimPrefix(scope, ScopeLabelPrefix))
	}
	if !routeScopeRe.MatchString(scope) {
		return fmt.Errorf("tracker: scope %q is invalid: must match [A-Za-z0-9][A-Za-z0-9._-]{0,63}", scope)
	}
	return nil
}

// routeSchema is applied from Store.initSchema, after tracker_connections
// exists (the foreign key needs it). ON DELETE CASCADE: deleting a
// connection drops its routes, so a reconnect under the same name never
// inherits stale routes.
const routeSchema = `
	CREATE TABLE IF NOT EXISTS tracker_routes (
		username   TEXT NOT NULL,
		connection TEXT NOT NULL,
		scope      TEXT NOT NULL,
		skill_id   TEXT NOT NULL,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		PRIMARY KEY (username, connection, scope),
		FOREIGN KEY (username, connection) REFERENCES tracker_connections (username, name) ON DELETE CASCADE
	);
`

// pgForeignKeyViolation is SQLSTATE 23503.
const pgForeignKeyViolation = "23503"

// SetRoute creates or updates a route. Idempotent — repeated calls with
// the same (username, connection, scope) replace SkillID and keep
// CreatedAt. Returns ErrNotFound if the connection does not exist.
func (s *Store) SetRoute(ctx context.Context, r Route) (*Route, error) {
	if r.Username == "" {
		return nil, errors.New("tracker: username is required")
	}
	if r.Connection == "" {
		return nil, errors.New("tracker: connection is required")
	}
	if err := ValidateRouteScope(r.Scope); err != nil {
		return nil, err
	}
	if r.SkillID == "" {
		return nil, errors.New("tracker: skill_id is required")
	}

	const q = `
		INSERT INTO tracker_routes (username, connection, scope, skill_id)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (username, connection, scope) DO UPDATE SET
			skill_id   = EXCLUDED.skill_id,
			updated_at = NOW()
		RETURNING created_at, updated_at;
	`
	out := r
	if err := s.pool.QueryRow(ctx, q, r.Username, r.Connection, r.Scope, r.SkillID).
		Scan(&out.CreatedAt, &out.UpdatedAt); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgForeignKeyViolation {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("upsert tracker route: %w", err)
	}
	return &out, nil
}

// GetRoute returns one route, or ErrRouteNotFound.
func (s *Store) GetRoute(ctx context.Context, username, connection, scope string) (*Route, error) {
	if username == "" {
		return nil, errors.New("tracker: username is required")
	}
	const q = `
		SELECT skill_id, created_at, updated_at FROM tracker_routes
		WHERE username = $1 AND connection = $2 AND scope = $3
	`
	r := Route{Username: username, Connection: connection, Scope: scope}
	if err := s.pool.QueryRow(ctx, q, username, connection, scope).
		Scan(&r.SkillID, &r.CreatedAt, &r.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrRouteNotFound
		}
		return nil, fmt.Errorf("select tracker route: %w", err)
	}
	return &r, nil
}

// ListRoutes returns one connection's routes, ordered by scope. An
// unknown connection yields an empty list, not an error.
func (s *Store) ListRoutes(ctx context.Context, username, connection string) ([]Route, error) {
	if username == "" {
		return nil, errors.New("tracker: username is required")
	}
	const q = `
		SELECT scope, skill_id, created_at, updated_at FROM tracker_routes
		WHERE username = $1 AND connection = $2
		ORDER BY scope
	`
	rows, err := s.pool.Query(ctx, q, username, connection)
	if err != nil {
		return nil, fmt.Errorf("list tracker routes: %w", err)
	}
	defer rows.Close()

	var out []Route
	for rows.Next() {
		r := Route{Username: username, Connection: connection}
		if err := rows.Scan(&r.Scope, &r.SkillID, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan tracker route row: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tracker route rows: %w", err)
	}
	return out, nil
}

// DeleteRoute removes one route, or returns ErrRouteNotFound.
func (s *Store) DeleteRoute(ctx context.Context, username, connection, scope string) error {
	if username == "" {
		return errors.New("tracker: username is required")
	}
	const q = `DELETE FROM tracker_routes WHERE username = $1 AND connection = $2 AND scope = $3`
	tag, err := s.pool.Exec(ctx, q, username, connection, scope)
	if err != nil {
		return fmt.Errorf("delete tracker route: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrRouteNotFound
	}
	return nil
}
