//go:build !containarium_client

package server

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/footprintai/containarium/internal/policyreadiness"
)

// Bounded startup when core Postgres is down (#2824).
//
// Before this, every Postgres-backed store retried its own connection five
// times, one store after another, before the daemon opened a listener, so a
// dead Postgres kept the API dark for minutes. Now one check per DSN, bounded
// by CONTAINARIUM_STARTUP_POSTGRES_TIMEOUT, decides; if it fails, every later
// store setup is skipped at once and the daemon serves DEGRADED (readiness
// entry policyreadiness.CorePostgresService) until it is restarted.

const (
	envStartupPostgresTimeout     = "CONTAINARIUM_STARTUP_POSTGRES_TIMEOUT"
	defaultStartupPostgresTimeout = 20 * time.Second
)

// postgresPingTimeout bounds each connection attempt in connectToPostgres.
// A var so tests can shorten it.
var postgresPingTimeout = 5 * time.Second

func durationFromEnv(name string, def time.Duration) time.Duration {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		log.Printf("Warning: %s=%q is not a positive duration; using %s", name, v, def)
		return def
	}
	return d
}

func startupPostgresTimeoutFromEnv() time.Duration {
	return durationFromEnv(envStartupPostgresTimeout, defaultStartupPostgresTimeout)
}

// pingPostgres opens a throwaway pool and pings it under ctx.
func pingPostgres(ctx context.Context, dsn string) error {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return err
	}
	defer pool.Close()
	return pool.Ping(ctx)
}

// postgresStartupGate runs one bounded reachability check per DSN and caches
// the answer for the rest of startup.
type postgresStartupGate struct {
	timeout       time.Duration
	retryInterval time.Duration
	ping          func(ctx context.Context, dsn string) error
	health        *health.Server // nil in tests that do not check readiness

	mu      sync.Mutex
	results map[string]error
	failed  string // first DSN whose check failed
}

func newPostgresStartupGate(timeout time.Duration, ping func(context.Context, string) error, h *health.Server) *postgresStartupGate {
	return &postgresStartupGate{
		timeout:       timeout,
		retryInterval: time.Second,
		ping:          ping,
		health:        h,
		results:       map[string]error{},
	}
}

// check reports whether Postgres at dsn answered within the startup deadline.
// Only the first call per DSN waits.
func (g *postgresStartupGate) check(dsn string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err, ok := g.results[dsn]; ok {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), g.timeout)
	defer cancel()
	var lastErr error
	for {
		if lastErr = g.ping(ctx, dsn); lastErr == nil {
			break
		}
		select {
		case <-ctx.Done():
		case <-time.After(g.retryInterval):
			continue
		}
		break
	}
	var result error
	if lastErr != nil {
		result = fmt.Errorf("startup Postgres check failed within %s (%v); skipping database-backed stores", g.timeout, lastErr)
		if g.failed == "" {
			g.failed = dsn
			log.Printf("DEGRADED: %v. The daemon serves without them; they stay off until it restarts", result)
		}
	}
	g.results[dsn] = result
	if g.health != nil {
		status := healthpb.HealthCheckResponse_SERVING
		if g.failed != "" {
			status = healthpb.HealthCheckResponse_NOT_SERVING
		}
		g.health.SetServingStatus(policyreadiness.CorePostgresService, status)
	}
	return result
}

// connect is connectToPostgres behind the startup check.
func (g *postgresStartupGate) connect(dsn string, maxRetries int, retryInterval time.Duration) (*pgxpool.Pool, error) {
	if err := g.check(dsn); err != nil {
		return nil, err
	}
	return connectToPostgres(dsn, maxRetries, retryInterval)
}

// gatedStore runs a DSN-taking store constructor only when the startup check
// passed.
func gatedStore[T any](g *postgresStartupGate, dsn string, newFn func(context.Context, string) (T, error)) (T, error) {
	if err := g.check(dsn); err != nil {
		var zero T
		return zero, err
	}
	return newFn(context.Background(), dsn)
}

// failedDSN is the DSN whose startup check failed, or "".
func (g *postgresStartupGate) failedDSN() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.failed
}

// degradedReason is the operator-facing reason, or "" when not degraded.
func (g *postgresStartupGate) degradedReason() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.failed == "" {
		return ""
	}
	return g.results[g.failed].Error()
}
