//go:build !containarium_client

package server

import (
	"context"
	"fmt"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/footprintai/containarium/internal/alert"
	"github.com/footprintai/containarium/internal/app"
	"github.com/footprintai/containarium/pkg/core/incus"
)

// Alerting as late-install families (#3334, on the #3326 helper).
//
// Two families, each with its own readiness entry:
//
//   - containarium.alerts: the alert rule store, the rules manager that
//     syncs them into vmalert, and the webhook delivery store. It exists
//     only when Postgres is configured AND VictoriaMetrics is set; without
//     either it is not configured, which is not pending. The alert RPCs that
//     need the store answer UNAVAILABLE while it is pending. The manager
//     needs an Incus client: failing to get one is a configuration refusal
//     (storeConfigRefusal), not a Postgres failure.
//   - containarium.credential_watch: the credential-expiry watch (#2371),
//     its last-seen state store and its delivery store. It exists only when
//     Postgres and the daemon config store are configured. The watcher
//     starts exactly once, when it has both the installed store and the
//     daemon's serving context (DualServer.Start), and every sweep reads the
//     last-seen state from Postgres before alerting, so a late install does
//     not re-fire alerts already sent.
//
// An alert delivery raised while containarium.alerts is pending is not
// buffered (#3335 Q15): it is logged as one structured line and counted, and
// the install line reports the count.
//
// The threat-detection notifier's delivery store, on the findings pool,
// stays restart-only with the findings path (#3335 Q1).

// openAlertBackendsFunc opens the alert family over a pool.
type openAlertBackendsFunc func(ctx context.Context, pool *pgxpool.Pool) (*alertBackends, error)

// openAlertBackends is the production opener. The Incus client is checked
// first: without it the manager cannot sync rules, which is a configuration
// refusal however long Postgres stays up.
func openAlertBackends(newIncus func() (*incus.Client, error)) openAlertBackendsFunc {
	return func(ctx context.Context, pool *pgxpool.Pool) (*alertBackends, error) {
		ic, err := newIncus()
		if err != nil {
			return nil, &storeConfigRefusal{Err: fmt.Errorf("alert manager needs an Incus client: %w", err)}
		}
		st, err := alert.NewStore(ctx, pool)
		if err != nil {
			return nil, fmt.Errorf("alert store: %w", err)
		}
		ds, err := alert.NewDeliveryStore(ctx, pool)
		if err != nil {
			return nil, fmt.Errorf("alert delivery store: %w", err)
		}
		return &alertBackends{
			rules:      st,
			syncer:     alert.NewManager(st, ic, CoreVictoriaMetricsContainer),
			deliveries: ds,
		}, nil
	}
}

// alertFamilySetup is what NewDualServer hands setupAlertFamily.
type alertFamilySetup struct {
	PostgresDSN        string
	VictoriaMetricsURL string
	WebhookURL         string
	WebhookSecret      string
	CoreServices       *CoreServices
	DaemonConfig       *app.DaemonConfigStore
	// Connect opens the family's startup pool.
	Connect func() (*pgxpool.Pool, error)
	Open    openAlertBackendsFunc
}

// alertFamilyConfigured reports whether the alert family exists at all.
func alertFamilyConfigured(postgresDSN, victoriaMetricsURL string) bool {
	return postgresDSN != "" && victoriaMetricsURL != ""
}

// setupAlertFamily installs the alert family at startup, or registers it
// with r for a late install. It returns the startup pool to close on
// shutdown, or nil. Not configured: nothing is registered and nothing is
// pending.
func setupAlertFamily(r *storeRecovery, cs *ContainerServer, c alertFamilySetup) *pgxpool.Pool {
	if !alertFamilyConfigured(c.PostgresDSN, c.VictoriaMetricsURL) {
		return nil
	}
	cs.configureAlerting(c.WebhookURL, c.WebhookSecret, c.CoreServices, c.DaemonConfig)
	family := alertStoreFamily(r, cs, c.Open)
	pool, err := c.Connect()
	if err != nil {
		r.logf("Warning: Failed to connect to PostgreSQL for alert store: %v", err)
		registerAlertLateInstall(r, cs, family)
		return nil
	}
	b, err := c.Open(context.Background(), pool)
	if err != nil {
		r.logf("Warning: alert store not installed at startup: %v", err)
		pool.Close()
		registerAlertLateInstall(r, cs, family)
		return nil
	}
	installAlertBackends(context.Background(), cs, b, r.logf)
	r.RegisterInstalled(family)
	r.logf("Alert management service enabled")
	return pool
}

func registerAlertLateInstall(r *storeRecovery, cs *ContainerServer, family storeFamily) {
	cs.setAlertsPending()
	r.logf("Warning: alert store not installed: the alert rule and delivery RPCs answer UNAVAILABLE and deliveries are logged, not recorded, until it installs in-process; readiness %s is NOT_SERVING", alertStoreService)
	r.Register(family)
}

// alertStoreFamily is the helper registration: open the family over the
// shared pool and install it. On error nothing is installed.
func alertStoreFamily(r *storeRecovery, cs *ContainerServer, open openAlertBackendsFunc) storeFamily {
	return storeFamily{
		Service: alertStoreService,
		Display: alertStoreDisplay,
		Install: func(ctx context.Context, pool *pgxpool.Pool) error {
			b, err := open(ctx, pool)
			if err != nil {
				return err
			}
			installAlertBackends(ctx, cs, b, r.logf)
			r.logf("Alert management service enabled (installed in-process); %d alert delivery record(s) raised while it was pending were logged, not recorded", cs.unrecordedAlertDeliveries())
			return nil
		},
	}
}

// installAlertBackends swaps b in and runs the initial rule sync, as boot
// always has. A failed sync is logged; the family is installed regardless.
func installAlertBackends(ctx context.Context, cs *ContainerServer, b *alertBackends, logf func(string, ...any)) {
	cs.installAlerts(b)
	if err := b.syncer.SyncRules(ctx); err != nil {
		logf("Warning: Initial alert rules sync failed: %v", err)
	}
}

// credentialWatchRunner is the credential-expiry watcher's lifecycle.
type credentialWatchRunner interface {
	Start(ctx context.Context)
	Stop()
}

var _ credentialWatchRunner = (*alert.CredentialWatcher)(nil)

// credentialWatch starts the watcher exactly once, when it has both the
// watcher (from the startup or the late install) and the daemon's serving
// context (from DualServer.Start), in whichever order they arrive. After
// stop it never starts. A nil *credentialWatch is a no-op.
type credentialWatch struct {
	mu      sync.Mutex
	ctx     context.Context
	runner  credentialWatchRunner
	started bool
	stopped bool
}

// setRunner hands over the watcher; the first one wins.
func (c *credentialWatch) setRunner(w credentialWatchRunner) {
	if c == nil || w == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.runner == nil {
		c.runner = w
	}
	c.maybeStartLocked()
}

// start hands over the daemon's serving context; the first one wins.
func (c *credentialWatch) start(ctx context.Context) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ctx == nil {
		c.ctx = ctx
	}
	c.maybeStartLocked()
}

func (c *credentialWatch) maybeStartLocked() {
	if c.started || c.stopped || c.ctx == nil || c.runner == nil {
		return
	}
	c.started = true
	c.runner.Start(c.ctx)
}

// stop ends a started watcher and prevents a later start.
func (c *credentialWatch) stop() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stopped = true
	if c.started {
		c.runner.Stop()
	}
}

// openCredentialWatchFunc opens the credential-expiry watcher over a pool.
type openCredentialWatchFunc func(ctx context.Context, pool *pgxpool.Pool) (credentialWatchRunner, error)

// openCredentialWatch is the production opener: the last-seen state store
// and the delivery store over pool, and the watcher over prober.
func openCredentialWatch(prober alert.CredentialProber, config *app.DaemonConfigStore) openCredentialWatchFunc {
	return func(ctx context.Context, pool *pgxpool.Pool) (credentialWatchRunner, error) {
		st, err := alert.NewPGCredentialStateStore(ctx, pool)
		if err != nil {
			return nil, fmt.Errorf("credential-expiry watch state store: %w", err)
		}
		d, err := alert.NewDeliveryStore(ctx, pool)
		if err != nil {
			return nil, fmt.Errorf("credential-expiry watch delivery store: %w", err)
		}
		return alert.NewCredentialWatcher(prober, st, alert.NewCredentialWebhookNotifier(config, d)), nil
	}
}

// credentialWatchSetup is what NewDualServer hands setupCredentialWatchFamily.
type credentialWatchSetup struct {
	PostgresDSN  string
	DaemonConfig *app.DaemonConfigStore
	Connect      func() (*pgxpool.Pool, error)
	Open         openCredentialWatchFunc
}

// credentialWatchConfigured reports whether the watch exists at all.
func credentialWatchConfigured(postgresDSN string, daemonConfig *app.DaemonConfigStore) bool {
	return postgresDSN != "" && daemonConfig != nil
}

// setupCredentialWatchFamily installs the watcher into cw at startup, or
// registers it with r for a late install. Either way cw starts it once
// DualServer.Start hands over the serving context. Not configured: nothing
// is registered and nothing is pending.
func setupCredentialWatchFamily(r *storeRecovery, cw *credentialWatch, c credentialWatchSetup) {
	if !credentialWatchConfigured(c.PostgresDSN, c.DaemonConfig) {
		return
	}
	family := credentialWatchFamily(r, cw, c.Open)
	pool, err := c.Connect()
	if err != nil {
		r.logf("Warning: credential-expiry watch Postgres connect failed (%v); the watch starts in-process once Postgres answers; readiness %s is NOT_SERVING", err, credentialWatchService)
		r.Register(family)
		return
	}
	w, err := c.Open(context.Background(), pool)
	if err != nil {
		r.logf("Warning: credential-expiry watch not installed at startup (%v); it is retried in-process; readiness %s is NOT_SERVING", err, credentialWatchService)
		pool.Close()
		r.Register(family)
		return
	}
	cw.setRunner(w)
	r.RegisterInstalled(family)
	r.logf("Credential-expiry watch enabled (every %s)", alert.CredentialWatchInterval)
}

// credentialWatchFamily is the helper registration: open the watcher over
// the shared pool and hand it to cw, which starts it at most once.
func credentialWatchFamily(r *storeRecovery, cw *credentialWatch, open openCredentialWatchFunc) storeFamily {
	return storeFamily{
		Service: credentialWatchService,
		Display: credentialWatchDisplay,
		Install: func(ctx context.Context, pool *pgxpool.Pool) error {
			w, err := open(ctx, pool)
			if err != nil {
				return err
			}
			cw.setRunner(w)
			r.logf("Credential-expiry watch enabled (installed in-process, every %s); it reads each box's last-seen state from Postgres before alerting", alert.CredentialWatchInterval)
			return nil
		},
	}
}
