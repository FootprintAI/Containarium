package autosleep

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// trafficStorePool is the narrowed pgxpool surface the traffic adapter
// touches. Declared here so this file doesn't import the larger
// *traffic.Store directly — keeps the package free of any traffic.*
// type dependency at the public API level.
type trafficStorePool interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// TrafficStoreAdapter satisfies TrafficSource over a pgx pool, querying
// traffic_connections for the most recent activity timestamp per
// container. Constructed by daemon wiring from *traffic.Store's
// underlying pool.
//
// A nil receiver is intentionally accepted by the Manager: daemons
// without a traffic store skip the network signal entirely and fall
// back to the "since-start" branch of Decide.
type TrafficStoreAdapter struct {
	pool trafficStorePool
}

// NewTrafficStoreAdapter wraps a pgx pool for use as a TrafficSource.
// The container_name column in traffic_connections is the full Incus
// name ("alice-container"), so callers pass the same.
func NewTrafficStoreAdapter(pool *pgxpool.Pool) *TrafficStoreAdapter {
	if pool == nil {
		return nil
	}
	return &TrafficStoreAdapter{pool: pool}
}

// LastNetworkActivity returns the max(last activity) for the given
// container. Returns zero time on no rows; that's a distinct signal
// the Decide rules treat as "no traffic ever recorded" rather than
// confusing with epoch 0.
//
// An OPEN connection (ended_at IS NULL) counts as activity AS OF NOW, not
// as of when it started. This is the fix for #524's "a box running an active
// session is NOT stopped": a long-lived SSH/exec debug session is a single
// TCP connection whose conntrack row has no ended_at until it closes. The
// previous COALESCE(ended_at, started_at) pinned its activity to started_at,
// so a session open LONGER than the idle threshold looked idle and the box
// was slept out from under the person debugging it. Treating any open
// connection as now-active keeps the box awake for exactly as long as someone
// is connected; once the session closes the collector stamps ended_at (on the
// conntrack destroy event) and the box becomes eligible to sleep again. A
// closed connection contributes its ended_at (always set on close), which is
// its true last-activity instant.
func (a *TrafficStoreAdapter) LastNetworkActivity(ctx context.Context, containerName string) (time.Time, error) {
	if a == nil || a.pool == nil {
		return time.Time{}, nil
	}
	const q = `
		SELECT MAX(CASE WHEN ended_at IS NULL THEN now() ELSE ended_at END)
		FROM traffic_connections
		WHERE container_name = $1
	`
	var t *time.Time
	if err := a.pool.QueryRow(ctx, q, containerName).Scan(&t); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return time.Time{}, nil
		}
		return time.Time{}, err
	}
	if t == nil {
		return time.Time{}, nil
	}
	return *t, nil
}
