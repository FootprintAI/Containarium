package modelgateway

import (
	"context"
	"log"
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
