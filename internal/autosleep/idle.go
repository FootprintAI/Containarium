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
// We read max(GREATEST(ended_at, started_at)) so an open connection
// (no ended_at, only started_at) still counts. This matches the
// collector's semantics: ended_at is stamped only when a connection
// closes; a long-lived TCP session looks "active" because it started
// recently even if it hasn't ended.
func (a *TrafficStoreAdapter) LastNetworkActivity(ctx context.Context, containerName string) (time.Time, error) {
	if a == nil || a.pool == nil {
		return time.Time{}, nil
	}
	const q = `
		SELECT MAX(COALESCE(ended_at, started_at))
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
