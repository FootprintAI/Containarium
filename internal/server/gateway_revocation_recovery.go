//go:build !containarium_client

package server

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/modelgateway"
)

// The three revocation-list consumers that took the store only at startup in
// NewDualServer (#3365, a follow-up to #3328). After a degraded start the
// revocation family installs late, and with it:
//
//   - the model gateway's jti check reads the installed store through a
//     per-call adapter (liveGatewayRevocations), the same pattern as the
//     secrets store's per-call reads (#3327);
//   - the gateway's owner cutoffs, kept in memory during the window, are
//     copied into Postgres keeping the latest cutoff per owner, then the
//     durable store is swapped in (liveOwnerRevocations);
//   - the expired-row cleanup loop starts, once, as soon as it has both the
//     store and the daemon's serving context (revocationCleanup).
//
// Decision: Q10 on #3335.

// liveGatewayRevocations is the model gateway's jti checker when the
// revocation list installs late. It reads the current store on every call, so
// a store installed after the gateway was built is consulted with no restart.
// Until then no token is revoked: the answer the gateway gives with no checker
// at all, so the window is no worse than before.
type liveGatewayRevocations struct {
	slot *storeSlot[auth.RevocationStore]
}

var _ modelgateway.RevocationChecker = (*liveGatewayRevocations)(nil)

func newLiveGatewayRevocations() *liveGatewayRevocations {
	return &liveGatewayRevocations{slot: newStoreSlot[auth.RevocationStore](nil)}
}

func (l *liveGatewayRevocations) install(st auth.RevocationStore) { l.slot.Store(st) }

// IsRevoked implements modelgateway.RevocationChecker.
func (l *liveGatewayRevocations) IsRevoked(ctx context.Context, jti string) (bool, error) {
	st := l.slot.Load()
	if st == nil {
		return false, nil
	}
	return st.IsRevoked(ctx, jti)
}

// ownerRevocationStore is both halves of an owner-revocation store: the
// gateway's read (RevokedBefore) and the write RevokeByKeyOwner asserts for.
type ownerRevocationStore interface {
	modelgateway.OwnerRevocationChecker
	RevokeOwner(ctx context.Context, keyOwner string, at time.Time, reason string) error
}

var (
	_ ownerRevocationStore = (*auth.PgOwnerRevocationStore)(nil)
	_ ownerRevocationStore = (*modelgateway.MemOwnerRevocations)(nil)
)

// ownerCutoffCarryOverReason is the reason stored with a cutoff copied from
// memory: the in-memory store does not keep the original one.
const ownerCutoffCarryOverReason = "recorded in memory while Postgres was unavailable; carried into Postgres when the store installed"

// liveOwnerRevocations is the gateway's owner-revocation store when the
// revocation list installs late: the in-memory store during the window, the
// durable store once it installs.
type liveOwnerRevocations struct {
	// mu serializes writes with install, so a cutoff recorded while the
	// window's cutoffs are copied lands either in memory before the copy or
	// in the durable store after the swap, never in a store nobody reads.
	// Reads take no lock: they load the slot.
	mu     sync.Mutex
	window *modelgateway.MemOwnerRevocations // written only under mu
	slot   *storeSlot[ownerRevocationStore]
}

var _ ownerRevocationStore = (*liveOwnerRevocations)(nil)

func newLiveOwnerRevocations() *liveOwnerRevocations {
	w := modelgateway.NewMemOwnerRevocations()
	return &liveOwnerRevocations{window: w, slot: newStoreSlot[ownerRevocationStore](w)}
}

// RevokedBefore implements modelgateway.OwnerRevocationChecker.
func (l *liveOwnerRevocations) RevokedBefore(ctx context.Context, keyOwner string) (time.Time, error) {
	return l.slot.Load().RevokedBefore(ctx, keyOwner)
}

// RevokeOwner records a cutoff in the current store.
func (l *liveOwnerRevocations) RevokeOwner(ctx context.Context, keyOwner string, at time.Time, reason string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.slot.Load().RevokeOwner(ctx, keyOwner, at, reason)
}

// install copies every cutoff recorded in memory during the window into
// durable, then swaps durable in. durable keeps the later cutoff per owner
// (auth.PgOwnerRevocationStore's conditional upsert), so a cutoff already in
// Postgres from before the outage is never narrowed. On error nothing is
// swapped and the in-memory store keeps serving with its cutoffs; a retry
// copies them again, which is idempotent.
func (l *liveOwnerRevocations) install(ctx context.Context, durable ownerRevocationStore) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoffs := l.window.Cutoffs()
	for _, c := range cutoffs {
		if err := durable.RevokeOwner(ctx, c.KeyOwner, c.RevokedBefore, ownerCutoffCarryOverReason); err != nil {
			return 0, fmt.Errorf("carry the in-memory cutoff for key owner %q into Postgres: %w", c.KeyOwner, err)
		}
	}
	l.slot.Store(durable)
	return len(cutoffs), nil
}

// gatewayRevocations is the model gateway's side of the revocation family.
type gatewayRevocations struct {
	jti        *liveGatewayRevocations
	owners     *liveOwnerRevocations
	openOwners func(context.Context, *pgxpool.Pool) (ownerRevocationStore, error)
}

func newGatewayRevocations(openOwners func(context.Context, *pgxpool.Pool) (ownerRevocationStore, error)) *gatewayRevocations {
	return &gatewayRevocations{jti: newLiveGatewayRevocations(), owners: newLiveOwnerRevocations(), openOwners: openOwners}
}

// install opens the owner store over the shared pool, carries the window's
// cutoffs into it, and then points the jti checker at st. Any error leaves
// the jti checker unset, so the whole family install is retried.
func (g *gatewayRevocations) install(ctx context.Context, pool *pgxpool.Pool, st auth.RevocationStore) (int, error) {
	owners, err := g.openOwners(ctx, pool)
	if err != nil {
		return 0, fmt.Errorf("model-gateway owner revocation store: %w", err)
	}
	n, err := g.owners.install(ctx, owners)
	if err != nil {
		return 0, err
	}
	g.jti.install(st)
	return n, nil
}

// openOwnerRevocationStore opens the Postgres owner-revocation store. It
// returns a true nil interface on error, never a nil pointer inside one.
func openOwnerRevocationStore(ctx context.Context, pool *pgxpool.Pool) (ownerRevocationStore, error) {
	st, err := auth.NewPgOwnerRevocationStore(ctx, pool)
	if err != nil {
		return nil, err
	}
	return st, nil
}

// revocationCleaner prunes expired revocation rows.
type revocationCleaner interface {
	CleanupExpired(ctx context.Context, now time.Time) (int64, error)
}

var _ revocationCleaner = (*auth.PgRevocationStore)(nil)

// revocationCleanup starts the expired-row cleanup loop exactly once, when it
// has both the store (from the startup install or the late install) and the
// serving context (from DualServer.Start), in whichever order they arrive.
// Every field is atomic: the late install and Start run on different
// goroutines. A nil *revocationCleanup is a no-op.
type revocationCleanup struct {
	run     func(context.Context, revocationCleaner)
	ctx     atomic.Pointer[cleanupContext]
	store   atomic.Pointer[cleanupStore]
	started atomic.Bool
}

type cleanupContext struct{ ctx context.Context }

type cleanupStore struct{ st revocationCleaner }

func newRevocationCleanup(run func(context.Context, revocationCleaner)) *revocationCleanup {
	return &revocationCleanup{run: run}
}

// setStore hands over the store; the first one wins.
func (c *revocationCleanup) setStore(st revocationCleaner) {
	if c == nil || st == nil {
		return
	}
	c.store.CompareAndSwap(nil, &cleanupStore{st: st})
	c.maybeStart()
}

// start hands over the serving context; the first one wins.
func (c *revocationCleanup) start(ctx context.Context) {
	if c == nil {
		return
	}
	c.ctx.CompareAndSwap(nil, &cleanupContext{ctx: ctx})
	c.maybeStart()
}

// maybeStart runs the loop once both halves are in. Whichever setter stores
// second sees both, and the CompareAndSwap lets only one caller through.
func (c *revocationCleanup) maybeStart() {
	cx, st := c.ctx.Load(), c.store.Load()
	if cx == nil || st == nil {
		return
	}
	if !c.started.CompareAndSwap(false, true) {
		return
	}
	go c.run(cx.ctx, st.st)
}
