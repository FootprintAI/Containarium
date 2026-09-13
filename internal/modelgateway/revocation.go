package modelgateway

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// Token revocation — the kill-switch for an issued gateway token.
//
// MintToken has always stamped a `jti` into every gateway token; until now
// nothing consulted it. That left the gateway's credential contract
// two-thirds implemented: tokens are scoped and expiring, but not revocable,
// so a leaked one was usable until its TTL ran out. For a skill box that is
// thirty minutes. For a recipe box (`recipeGatewayTokenTTL`) it is a year, and
// that TTL was chosen on the explicit assumption that revocation was the
// kill-switch — so this is the check that assumption needs.
//
// The interface is declared here, narrow and local, so this package keeps no
// dependency on internal/auth. The daemon satisfies it with the same
// revocation store it already wires for platform JWTs: that store is keyed on
// jti alone and is issuer-agnostic, so `containarium token revoke --jti <id>`
// kills a gateway token with no new verb, RPC, or schema.

// RevocationChecker reports whether a token id has been revoked.
//
// Implementations must be safe for concurrent use — this is consulted on every
// proxied model call.
type RevocationChecker interface {
	// IsRevoked returns true if the given jti has been revoked. An empty jti
	// must return (false, nil).
	IsRevoked(ctx context.Context, jti string) (bool, error)
}

// revocationLookupTimeout bounds a single revocation lookup so a slow database
// cannot stall the model path. Mirrors auth.TokenManager.ValidateToken.
const revocationLookupTimeout = 500 * time.Millisecond

// isRevoked reports whether this token has been killed.
//
// Fails OPEN — on a lookup error the call is allowed, with a warning. That
// matches the platform JWT path and is the right trade for a kill-switch
// rather than a primary gate.
//
// What survives a fail-open, precisely: the token's signature, issuer, expiry
// and provider binding are already checked when this runs, and the
// allowed-model ceiling is applied further down the same request — failing
// open resumes handleModel, it does not skip to the proxy. So a database
// outage degrades us to exactly the protection we had before this check
// existed, instead of taking every tenant's model traffic down with the
// database.
//
// An empty jti short-circuits without a lookup: tokens minted before jti
// existed carry none, and asking the store about "" is a pointless round trip.
func (g *Gateway) isRevoked(ctx context.Context, jti string) bool {
	if g.cfg.Revocations == nil || jti == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, revocationLookupTimeout)
	defer cancel()

	revoked, err := g.cfg.Revocations.IsRevoked(ctx, jti)
	if err != nil {
		log.Printf("model-gateway: revocation lookup failed for jti=%s: %v (allowing; the revocation list is a kill-switch, not the primary gate)", jti, err)
		return false
	}
	return revoked
}

// MemRevocations is a mutex-guarded in-memory RevocationChecker for a
// standalone gateway with no Postgres store behind it (see cmd/model-gateway
// serve, #1820). It also implements the same Revoke(ctx, jti, expiresAt,
// reason) shape as auth.RevocationStore / runlease.Revoker — declared
// locally as the unexported `revoker` interface in admin.go, so this package
// still keeps no dependency on internal/auth or internal/runlease — which is
// what lets POST /__gateway/revoke (admin.go) drive it directly.
//
// The daemon keeps using PgRevocationStore; this exists only for the
// standalone binary and for tests. Every entry carries the expiry the caller
// recorded, and a lazy sweep drops it once that expiry passes: a token past
// its own exp is already refused by VerifyToken's exp check regardless of
// this store, so keeping the entry around after that point buys nothing and
// only grows the map for a long-lived process.
type MemRevocations struct {
	mu        sync.Mutex
	m         map[string]memRevocation
	now       func() time.Time // overridable in tests; defaults to time.Now
	lastSweep time.Time        // guarded by mu; zero means "never swept yet"
}

type memRevocation struct {
	expiresAt time.Time
	reason    string
}

// memRevocationsSweepInterval throttles the full-map sweep (see
// maybeSweepLocked) to at most once per this long, rather than once per
// call. IsRevoked sits on the hot path of every proxied model call
// (gateway.go's handleModel), so an O(len(r.m)) scan under the single mutex
// on every single call would scale per-call latency with the number of
// outstanding revocations on a busy gateway. A minute of staleness on
// reclaiming expired entries costs nothing in correctness — see
// maybeSweepLocked.
const memRevocationsSweepInterval = time.Minute

// NewMemRevocations builds an empty MemRevocations.
func NewMemRevocations() *MemRevocations {
	return &MemRevocations{m: map[string]memRevocation{}, now: time.Now}
}

// IsRevoked implements RevocationChecker. An empty jti is never revoked and
// costs no map access, matching Gateway.isRevoked's own short-circuit.
func (r *MemRevocations) IsRevoked(_ context.Context, jti string) (bool, error) {
	if jti == "" {
		return false, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.maybeSweepLocked()
	_, revoked := r.m[jti]
	return revoked, nil
}

// Revoke records jti as revoked until expiresAt. Matches
// auth.RevocationStore.Revoke / runlease.Revoker's signature so the same
// call sites (runlease.End, the admin HTTP handler) work against either
// implementation.
func (r *MemRevocations) Revoke(_ context.Context, jti string, expiresAt time.Time, reason string) error {
	if jti == "" {
		return fmt.Errorf("modelgateway: revoke: empty jti")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.maybeSweepLocked()
	r.m[jti] = memRevocation{expiresAt: expiresAt, reason: reason}
	return nil
}

// maybeSweepLocked drops every entry whose recorded expiry has passed, but
// at most once per memRevocationsSweepInterval. Caller must hold r.mu.
//
// Correctness doesn't depend on sweeping promptly: a token past its own exp
// is already refused by VerifyToken's exp check regardless of this store, so
// an expired-but-not-yet-swept entry can only ever make IsRevoked answer
// "revoked" for a token nothing would accept anyway. Throttling the sweep
// only delays reclaiming map space for entries nobody can exploit, which is
// the trade that keeps the hot path O(1) instead of O(len(r.m)) on every
// call.
//
// A zero expiresAt (a caller that never set one) is treated as "never
// expires" rather than "always expired" — deleting it here would silently
// undo the revocation on the very next sweep.
func (r *MemRevocations) maybeSweepLocked() {
	now := r.now()
	if !r.lastSweep.IsZero() && now.Sub(r.lastSweep) < memRevocationsSweepInterval {
		return
	}
	r.lastSweep = now
	for jti, rec := range r.m {
		if !rec.expiresAt.IsZero() && now.After(rec.expiresAt) {
			delete(r.m, jti)
		}
	}
}
