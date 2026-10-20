package server

import (
	"context"
	"errors"
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
// store setup is skipped at once, the daemon serves DEGRADED (readiness entry
// policyreadiness.CorePostgresService), and — only with
// CONTAINARIUM_RESTART_ON_POSTGRES_RECOVERY=1 — a watcher restarts the daemon
// once when Postgres answers again, so every store comes up through the
// normal startup path.

const (
	envStartupPostgresTimeout     = "CONTAINARIUM_STARTUP_POSTGRES_TIMEOUT"
	envRestartOnPostgresRecovery  = "CONTAINARIUM_RESTART_ON_POSTGRES_RECOVERY"
	envPostgresRecoveryMinUptime  = "CONTAINARIUM_POSTGRES_RECOVERY_MIN_UPTIME"
	defaultStartupPostgresTimeout = 20 * time.Second
	// defaultPostgresRecoveryMinUptime is the flap guard: the daemon never
	// restarts itself sooner than this after it started.
	defaultPostgresRecoveryMinUptime = 2 * time.Minute
	// postgresRecoveryRequiredPings successful pings in a row before the
	// watcher restarts the daemon; any failure resets the count.
	postgresRecoveryRequiredPings = 3

	// ExitCodePostgresRecovered is the daemon's exit status when it restarts
	// itself because Postgres came back (EX_TEMPFAIL). Non-zero on purpose:
	// a systemd unit with Restart=on-failure (or always) restarts it.
	ExitCodePostgresRecovered = 75
)

// ErrRestartForPostgresRecovery is returned by DualServer.Start after a
// graceful shutdown triggered by the Postgres recovery watcher.
var ErrRestartForPostgresRecovery = errors.New("core Postgres is reachable again; restarting the daemon to wire its database-backed stores")

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

// postgresRecoveryWatcher decides when a daemon that started DEGRADED should
// restart itself: after minUptime, and only after `required` successful pings
// in a row.
type postgresRecoveryWatcher struct {
	ping      func(ctx context.Context) error
	started   time.Time
	now       func() time.Time
	sleep     func(ctx context.Context, d time.Duration) bool // false when ctx ended
	minUptime time.Duration
	required  int
	interval  time.Duration // between pings while Postgres answers; first backoff step
	maxDelay  time.Duration // backoff cap while it does not
}

// newPostgresRecoveryWatcher returns nil unless the startup check failed and
// CONTAINARIUM_RESTART_ON_POSTGRES_RECOVERY is on.
func newPostgresRecoveryWatcher(failedDSN string) *postgresRecoveryWatcher {
	if failedDSN == "" || !envBool(envRestartOnPostgresRecovery) {
		return nil
	}
	return &postgresRecoveryWatcher{
		ping: func(ctx context.Context) error {
			pctx, cancel := context.WithTimeout(ctx, postgresPingTimeout)
			defer cancel()
			return pingPostgres(pctx, failedDSN)
		},
		started:   time.Now(),
		now:       time.Now,
		sleep:     sleepCtx,
		minUptime: durationFromEnv(envPostgresRecoveryMinUptime, defaultPostgresRecoveryMinUptime),
		required:  postgresRecoveryRequiredPings,
		interval:  5 * time.Second,
		maxDelay:  60 * time.Second,
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// run blocks until it decides to restart (true) or ctx ends (false). It logs
// each state change once, not every ping.
func (w *postgresRecoveryWatcher) run(ctx context.Context) bool {
	log.Printf("Postgres recovery watcher: will restart the daemon once Postgres answers %d pings in a row (not before %s of uptime)", w.required, w.minUptime)
	delay := w.interval
	ok := 0
	loggedUp, loggedUptime := false, false
	for {
		if !w.sleep(ctx, delay) {
			return false
		}
		if err := w.ping(ctx); err != nil {
			if ok > 0 || loggedUp {
				log.Printf("Postgres recovery watcher: Postgres unreachable again (%v); waiting", err)
				loggedUp, loggedUptime = false, false
			}
			ok = 0
			delay = min(delay*2, w.maxDelay)
			continue
		}
		ok++
		delay = w.interval
		if !loggedUp {
			log.Printf("Postgres recovery watcher: Postgres answered; confirming")
			loggedUp = true
		}
		if ok < w.required {
			continue
		}
		if up := w.now().Sub(w.started); up < w.minUptime {
			if !loggedUptime {
				log.Printf("Postgres recovery watcher: Postgres is back; holding the restart until %s of uptime (flap guard)", w.minUptime)
				loggedUptime = true
			}
			continue
		}
		log.Printf("Postgres recovery watcher: Postgres answered %d pings in a row; restarting the daemon (exit %d)", ok, ExitCodePostgresRecovered)
		return true
	}
}

// watchPostgresRecovery wraps Start's context: when the watcher decides to
// restart, the returned context is cancelled (Start's normal graceful
// shutdown runs) and finish turns Start's nil result into
// ErrRestartForPostgresRecovery.
func (ds *DualServer) watchPostgresRecovery(parent context.Context) (context.Context, func(error) error) {
	if ds.postgresRecovery == nil {
		return parent, func(err error) error { return err }
	}
	ctx, cancel := context.WithCancel(parent)
	restarting := make(chan struct{})
	go func() {
		if ds.postgresRecovery.run(ctx) {
			close(restarting)
			cancel()
		}
	}()
	return ctx, func(err error) error {
		cancel()
		select {
		case <-restarting:
			if err == nil {
				return ErrRestartForPostgresRecovery
			}
		default:
		}
		return err
	}
}
