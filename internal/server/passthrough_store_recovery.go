//go:build !containarium_client

package server

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/footprintai/containarium/pkg/core/network"
)

// The passthrough route store and its sync job as a late-install family
// (#3333, on the #3326 helper). The store is built only on a daemon that
// has a NetworkServer and Postgres configured. With Postgres down at
// startup, every passthrough RPC answers UNAVAILABLE and writes nothing to
// the host's rules (#3335 Q13): a route applied there without the store
// would not be persisted, and the sync job removes it once it starts. Once
// Postgres answers, the helper opens the store and installs it into the
// network server and the container delete cascade, then builds the sync job,
// which starts on the daemon's serving context and stops at its shutdown.

// passthroughSyncRunner is the sync job's lifecycle;
// *network.PassthroughSyncJob implements it.
type passthroughSyncRunner interface {
	Start(ctx context.Context)
	Stop()
}

var _ passthroughSyncRunner = (*network.PassthroughSyncJob)(nil)

// passthroughSync owns the passthrough sync job across a late install. The
// job is built once, from the first store installed, and started once, when
// it has both the job and the daemon's serving context (from
// DualServer.Start), in whichever order they arrive. stop, at the daemon's
// shutdown, stops a started job, and no job is built or started after it.
// The install and Start run on different goroutines. A nil *passthroughSync
// is a no-op.
type passthroughSync struct {
	build func(network.PassthroughStore) passthroughSyncRunner

	mu      sync.Mutex
	job     passthroughSyncRunner
	ctx     context.Context
	started bool
	stopped bool
}

func newPassthroughSync(build func(network.PassthroughStore) passthroughSyncRunner) *passthroughSync {
	return &passthroughSync{build: build}
}

// install builds the job over st; only the first store builds one.
func (p *passthroughSync) install(st network.PassthroughStore) {
	if p == nil || st == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stopped || p.job != nil {
		return
	}
	p.job = p.build(st)
	p.maybeStartLocked()
}

// start hands over the daemon's serving context; the first one wins.
func (p *passthroughSync) start(ctx context.Context) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ctx == nil {
		p.ctx = ctx
	}
	p.maybeStartLocked()
}

func (p *passthroughSync) maybeStartLocked() {
	if p.stopped || p.started || p.job == nil || p.ctx == nil {
		return
	}
	p.started = true
	p.job.Start(p.ctx)
	log.Printf("Passthrough sync job started")
}

// stop stops the job if it was started, and keeps any later install from
// building or starting one. Stop waits for the job's loop, so it runs
// outside the lock.
func (p *passthroughSync) stop() {
	if p == nil {
		return
	}
	p.mu.Lock()
	if p.stopped {
		p.mu.Unlock()
		return
	}
	p.stopped = true
	job, started := p.job, p.started
	p.mu.Unlock()
	if started {
		job.Stop()
	}
}

// passthroughConsumers are the serving paths the passthrough store is
// installed into.
type passthroughConsumers struct {
	network    *NetworkServer
	containers *ContainerServer
	sync       *passthroughSync
}

// install wires st into the delete cascade, the RPCs and the sync job, in
// that order. The cascade goes first because installing it replays the
// deletes remembered while the store was absent: a route added through a live
// RPC for a remembered name while that replay ran would be deleted with the
// old ones (#3441), so the RPCs stay UNAVAILABLE until it finishes. The sync
// job is built last, so its first pass sees neither the replayed rows nor a
// write the RPCs accepted before the store was readable (#3407).
func (c passthroughConsumers) install(ctx context.Context, st network.PassthroughStore) {
	// DeleteContainer cascade-cleans a recipe-deployed box's passthrough
	// routes (#1462), mirroring SetRouteCleanupDeps for HTTP routes.
	replayed, failed := c.containers.installPassthroughStore(ctx, st)
	c.network.SetPassthroughStore(st)
	c.sync.install(st)
	log.Printf("Passthrough store installed: replayed %d remembered delete(s), %d failed", replayed, failed)
}

// passthroughStoreFamily is the helper registration: open the store over
// the shared pool and install it. On error nothing is installed, so the
// RPCs keep answering UNAVAILABLE.
func passthroughStoreFamily(c passthroughConsumers, open func(context.Context, *pgxpool.Pool) (network.PassthroughStore, error)) storeFamily {
	return storeFamily{
		Service: passthroughStoreService,
		Display: passthroughStoreDisplay,
		Install: func(ctx context.Context, pool *pgxpool.Pool) error {
			st, err := open(ctx, pool)
			if err != nil {
				return err
			}
			c.install(ctx, st)
			return nil
		},
	}
}

// registerPassthroughLateInstall hands the store to the helper after its
// startup install did not happen, and logs the degraded state once.
func registerPassthroughLateInstall(r *storeRecovery, c passthroughConsumers, open func(context.Context, *pgxpool.Pool) (network.PassthroughStore, error)) {
	c.network.requirePassthroughStore()
	c.containers.requirePassthroughStore()
	r.logf("Warning: passthrough route store not installed (Postgres unavailable at startup): passthrough route RPCs answer UNAVAILABLE and change nothing until it installs in-process; readiness %s is NOT_SERVING", passthroughStoreService)
	r.Register(passthroughStoreFamily(c, open))
}

// setupPassthroughStore is the startup install, on a daemon with a
// NetworkServer and Postgres configured: connect, open the store and
// install it, or hand it to the helper if either step fails.
func setupPassthroughStore(r *storeRecovery, c passthroughConsumers, connect func() (*pgxpool.Pool, error), open func(context.Context, *pgxpool.Pool) (network.PassthroughStore, error)) {
	c.network.requirePassthroughStore()
	pool, err := connect()
	if err != nil {
		r.logf("Warning: Failed to connect to PostgreSQL for passthrough store: %v", err)
		registerPassthroughLateInstall(r, c, open)
		return
	}
	st, err := open(context.Background(), pool)
	if err != nil {
		r.logf("Warning: Failed to create passthrough store: %v", err)
		pool.Close()
		registerPassthroughLateInstall(r, c, open)
		return
	}
	c.install(context.Background(), st)
	r.RegisterInstalled(passthroughStoreFamily(c, open))
	r.logf("Passthrough route persistence enabled")
}

// passthroughSyncJobBuilder builds the production sync job, which reconciles
// the host's rules from the store every interval.
func passthroughSyncJobBuilder(manager *network.PassthroughManager, interval time.Duration) func(network.PassthroughStore) passthroughSyncRunner {
	return func(st network.PassthroughStore) passthroughSyncRunner {
		return network.NewPassthroughSyncJob(st, manager, interval)
	}
}
