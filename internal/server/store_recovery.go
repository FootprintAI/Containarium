//go:build !containarium_client

package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/footprintai/containarium/internal/policyreadiness"
)

// Late install of Postgres-backed store families after a degraded start
// (#3326, option C of #2824).
//
// Stores are installed once, in NewDualServer, when Postgres answers at boot.
// After a degraded start they stayed off until the daemon restarted; the
// #2483 recovery loop covers only the guardrail and coding-tool egress
// policy stores. storeRecovery is the shared version: a family registers an
// install step, a readiness name and (through storeSlot) an atomic-swap
// target, and ONE pool plus ONE backoff loop serve every pending family. An
// attempt dials Postgres once if the shared pool is not open yet, then runs
// each pending family's install over that pool; a family's install runs
// until it succeeds and never again. Readiness is grpc.health.v1, one entry
// per family: NOT_SERVING until installed, SERVING after, and the entry is
// published to the policyreadiness registry so doctor and the status probe
// list it. The opt-in self-restart watcher (#2824) is held while any family
// is pending, so it cannot restart the daemon under a late install; once
// nothing is pending it is again the fallback for families that do not
// recover in-process.
//
// Migrating a family (#3327 onwards): register the servers unconditionally,
// answer UNAVAILABLE from the stand-in, and hand the install to Register
// when the startup install did not happen — or RegisterInstalled when it did.

// storeFamily is one Postgres-backed store family the helper can install
// after startup.
type storeFamily struct {
	// Service is the grpc.health.v1 name the family's readiness is reported
	// under; it is also its policyreadiness entry.
	Service string
	// Display is the operator-facing name doctor and the status probe print.
	Display string
	// Install opens the family's store over the shared pool and swaps it
	// into the serving path (installInto builds it for a storeSlot). The
	// loop calls it on every attempt until it returns nil, then never again.
	// On error it must leave the stand-in in place.
	Install func(ctx context.Context, pool *pgxpool.Pool) error
}

// storeSlot is a family's atomic-swap target: its server reads the current
// store through Load on every call, so a durable store stored later reaches
// it without re-wiring. Until then it holds the fail-closed stand-in.
type storeSlot[T any] struct {
	cur atomic.Pointer[storeSlotRef[T]]
}

type storeSlotRef[T any] struct{ v T }

// newStoreSlot returns a slot serving standIn.
func newStoreSlot[T any](standIn T) *storeSlot[T] {
	s := &storeSlot[T]{}
	s.Store(standIn)
	return s
}

// Load returns the current store.
func (s *storeSlot[T]) Load() T { return s.cur.Load().v }

// Store swaps v in. Safe while serving.
func (s *storeSlot[T]) Store(v T) { s.cur.Store(&storeSlotRef[T]{v: v}) }

// installInto is the Install step for a family whose serving path reads
// slot: open the durable store over the shared pool and swap it in. On error
// the slot is untouched, so the stand-in keeps answering.
func installInto[T any](slot *storeSlot[T], open func(context.Context, *pgxpool.Pool) (T, error)) func(context.Context, *pgxpool.Pool) error {
	return func(ctx context.Context, pool *pgxpool.Pool) error {
		st, err := open(ctx, pool)
		if err != nil {
			return err
		}
		slot.Store(st)
		return nil
	}
}

type registeredStoreFamily struct {
	storeFamily
	installed bool
}

// storeRecovery is the registry and the retry loop. Register the families
// in NewDualServer, then start Run once; the loop's pool is kept open for the
// stores it installed.
type storeRecovery struct {
	health *health.Server

	// connect opens the shared pool, one attempt (no internal retry).
	connect func(ctx context.Context) (*pgxpool.Pool, error)
	// publish adds a family's readiness entry to the policyreadiness registry.
	publish func(service, display string)

	initial, max time.Duration
	after        func(time.Duration) <-chan time.Time
	logf         func(format string, args ...any)

	mu       sync.Mutex
	families []*registeredStoreFamily // registration order
	pool     *pgxpool.Pool            // the shared pool, once open
}

// newStoreRecovery builds the helper over h. connString is read at dial
// time, because NewDualServer finalizes the DSN after the first families
// would register.
func newStoreRecovery(h *health.Server, connString func() string) *storeRecovery {
	return &storeRecovery{
		health: h,
		connect: func(context.Context) (*pgxpool.Pool, error) {
			return connectToPostgres(connString(), 1, 0)
		},
		publish: policyreadiness.Register,
		initial: policyStoreRetryInitial,
		max:     policyStoreRetryMax,
		after:   time.After,
		logf:    log.Printf,
	}
}

// Register declares a family whose startup install did not happen (the
// startup Postgres check failed, or the install itself did). Its readiness
// is NOT_SERVING until the loop installs it.
func (r *storeRecovery) Register(f storeFamily) { r.add(f, false) }

// RegisterInstalled declares a family startup installed: its readiness is
// SERVING and there is nothing to retry. Same registry, so it is listed with
// the others.
func (r *storeRecovery) RegisterInstalled(f storeFamily) { r.add(f, true) }

func (r *storeRecovery) add(f storeFamily, installed bool) {
	if f.Service == "" {
		panic("store recovery: a family needs a readiness service name")
	}
	if f.Install == nil && !installed {
		panic(fmt.Sprintf("store recovery: family %q has no install step", f.Service))
	}
	r.mu.Lock()
	for _, g := range r.families {
		if g.Service == f.Service {
			r.mu.Unlock()
			panic(fmt.Sprintf("store recovery: family %q registered twice", f.Service))
		}
	}
	r.families = append(r.families, &registeredStoreFamily{storeFamily: f, installed: installed})
	r.mu.Unlock()
	r.publish(f.Service, f.Display)
	r.setHealth(f.Service, installed)
}

func (r *storeRecovery) setHealth(service string, ready bool) {
	st := healthpb.HealthCheckResponse_NOT_SERVING
	if ready {
		st = healthpb.HealthCheckResponse_SERVING
	}
	r.health.SetServingStatus(service, st)
}

// pending reports whether any registered family is not installed yet. The
// self-restart watcher holds on it.
func (r *storeRecovery) pending() bool {
	return len(r.pendingFamilies()) > 0
}

func (r *storeRecovery) pendingFamilies() []*registeredStoreFamily {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*registeredStoreFamily
	for _, f := range r.families {
		if !f.installed {
			out = append(out, f)
		}
	}
	return out
}

func (r *storeRecovery) serviceNames(fams []*registeredStoreFamily) string {
	names := make([]string, 0, len(fams))
	for _, f := range fams {
		names = append(names, f.Service)
	}
	return strings.Join(names, ", ")
}

// Run retries until every registered family is installed or ctx ends.
// startupPool is the pool startup opened, or nil if it could not connect; it
// becomes the shared pool, so no family dials on its own. Start it once, after
// every family has registered.
func (r *storeRecovery) Run(ctx context.Context, startupPool *pgxpool.Pool) {
	if startupPool != nil {
		r.mu.Lock()
		if r.pool == nil {
			r.pool = startupPool
		}
		r.mu.Unlock()
	}
	if !r.pending() {
		return
	}
	wait := r.initial
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.after(wait):
		}
		next := min(wait*2, r.max)
		err := r.attempt(ctx)
		still := r.pendingFamilies()
		if len(still) == 0 {
			r.mu.Lock()
			all := append([]*registeredStoreFamily(nil), r.families...)
			r.mu.Unlock()
			r.logf("Store families recovered in-process: %s (every registered family is installed)", r.serviceNames(all))
			return
		}
		r.logf("Warning: store families pending in-process recovery (%s): %v; next attempt in %s", r.serviceNames(still), err, next)
		wait = next
	}
}

// attempt opens the shared pool if needed (one dial) and runs every pending
// family's install over it. The lock is not held across the dial or the
// installs, so pending() stays cheap for the watcher.
func (r *storeRecovery) attempt(ctx context.Context) error {
	r.mu.Lock()
	pool := r.pool
	r.mu.Unlock()
	if pool == nil {
		p, err := r.connect(ctx)
		if err != nil {
			return fmt.Errorf("connect to Postgres: %w", err)
		}
		r.mu.Lock()
		if r.pool == nil {
			r.pool = p
		} else {
			p.Close() // a startup pool arrived meanwhile; keep one
		}
		pool = r.pool
		r.mu.Unlock()
	}
	var errs []error
	for _, f := range r.pendingFamilies() {
		if err := f.Install(ctx, pool); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", f.Service, err))
			continue
		}
		r.mu.Lock()
		f.installed = true
		r.mu.Unlock()
		r.setHealth(f.Service, true)
		r.logf("Store family %s: Postgres store installed in-process (by retry)", f.Service)
	}
	return errors.Join(errs...)
}
