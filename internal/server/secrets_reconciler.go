package server

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/footprintai/containarium/internal/secrets"
	"github.com/footprintai/containarium/pkg/core/incus"
)

// Phase 4.3 Phase B-3 — file-mode secret reconciler
// (audit C-MED-4 polish).
//
// File-mode secrets live in `/run/secrets/<NAME>` inside
// the container. `/run` is tmpfs on every systemd distro,
// so the directory evaporates whenever the container
// stops. The daemon's canonical start path
// (StartContainer / CreateContainer / RefreshSecrets) re-
// stamps on every transition, so operators using
// `containarium start <user>` are covered.
//
// But: a bare `incus restart` not routed through the
// daemon doesn't trigger the daemon's stamp logic. The
// container comes up with an empty `/run/secrets`, the
// app tries to open its credentials, ENOENT, crash. That's
// the failure this reconciler closes.
//
// Strategy: a ticker that, every interval, asks the
// secrets store for the set of tenants with at least one
// file-mode secret, looks up each tenant's container in
// Incus, and (if Running) re-stamps. The stamp is
// idempotent — writing the same content over the same
// path is fine — so periodic re-stamps cost nothing when
// state is already correct.
//
// Skipped on every tick:
//   - Tenants with no file-mode secrets (env-mode rows
//     don't need this — incus config survives restart).
//   - Containers that are Stopped (the stamp would race
//     with a future start and is wasted work; the start
//     path will re-stamp when it runs).
//
// The reconciler is intentionally simple. It doesn't try
// to deduplicate or track per-container state — the
// idempotency of the stamp is the whole correctness
// argument. If a future profiling pass shows the
// reconciler doing real work, the per-container last-
// observed-running timestamp would be the obvious
// optimization.

const defaultReconcileInterval = 60 * time.Second

// secretsReconciler is the actual ticker. Owned by
// DualServer alongside the autosleep manager — same
// shape, same lifetime.
type secretsReconciler struct {
	store    *secrets.Store
	incus    *incus.Client
	stamp    func(ctx context.Context, username string) (int, error)
	interval time.Duration
	stopCh   chan struct{}
	done     chan struct{}
	stopOnce sync.Once
}

func newSecretsReconciler(store *secrets.Store, ic *incus.Client, stamp func(ctx context.Context, username string) (int, error), interval time.Duration) *secretsReconciler {
	if interval <= 0 {
		interval = defaultReconcileInterval
	}
	return &secretsReconciler{
		store:    store,
		incus:    ic,
		stamp:    stamp,
		interval: interval,
		stopCh:   make(chan struct{}),
		done:     make(chan struct{}),
	}
}

// Start spawns the tick loop. Returns immediately.
func (r *secretsReconciler) Start(ctx context.Context) {
	go r.run(ctx)
	log.Printf("[secrets-reconciler] ticker started (interval=%s)", r.interval)
}

// Stop signals the loop to exit and waits for it.
// Idempotent. Currently unused but mirrors the autosleep
// shape so daemon shutdown can call it cleanly when that
// path is wired.
func (r *secretsReconciler) Stop() {
	r.stopOnce.Do(func() {
		close(r.stopCh)
	})
	<-r.done
}

func (r *secretsReconciler) run(ctx context.Context) {
	defer close(r.done)

	t := time.NewTicker(r.interval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-r.stopCh:
			return
		case <-t.C:
			r.tick(ctx)
		}
	}
}

// tick walks every tenant with file-mode secrets and re-
// stamps if their container is Running. Errors are logged
// and the loop continues — one misbehaving container
// shouldn't halt reconciliation for the rest.
func (r *secretsReconciler) tick(ctx context.Context) {
	if r.store == nil || r.incus == nil || r.stamp == nil {
		return
	}
	users, err := r.store.UsernamesWithFileDelivery(ctx)
	if err != nil {
		log.Printf("[secrets-reconciler] list file-mode tenants: %v", err)
		return
	}
	if len(users) == 0 {
		return // no work
	}

	for _, username := range users {
		containerName := username + "-container"
		info, gerr := r.incus.GetContainer(containerName)
		if gerr != nil {
			// Container may not exist yet (tenant pre-
			// provisioned secrets) or got deleted; skip
			// quietly.
			continue
		}
		if info.State != "Running" {
			continue
		}
		if _, serr := r.stamp(ctx, username); serr != nil {
			log.Printf("[secrets-reconciler] re-stamp %s: %v", username, serr)
		}
	}
}
