package modelgateway

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Per-owner key resolution — whose upstream key a proxied call spends.
//
// The gateway used to hold exactly one real key per provider for the whole
// daemon (Config.ProviderKeys). That is right for a single-operator install and
// wrong the moment one daemon serves several owners, each paying for their own
// upstream: the key that gets injected has to be a property of the *token*, not
// of the process.
//
// So a token may carry a `key_owner` claim, and the gateway resolves
// (key_owner, provider) -> real key through an injected KeyResolver, falling
// back to the daemon-global key when the owner has none. A token WITHOUT the
// claim never reaches the resolver and resolves exactly as it did before, which
// is what keeps every already-issued skill-box and recipe-box token working.
//
// The owner namespaces are deliberately prefixed. A self-hosted daemon's
// usernames are arbitrary user-chosen strings and cloud org ids are UUIDs drawn
// from the same string space; without a discriminator a username crafted to
// match a target org's id would resolve to that org's key under the same
// lookup. `user:` / `org:` makes the two spaces disjoint by construction.

// Key-owner namespace prefixes. Load-bearing, not decorative — see above.
const (
	// KeyOwnerUserPrefix namespaces a self-hosted daemon's local username.
	KeyOwnerUserPrefix = "user:"
	// KeyOwnerOrgPrefix namespaces a cloud organization id.
	KeyOwnerOrgPrefix = "org:"
)

// UserKeyOwner is the key_owner for a self-hosted box owned by username.
func UserKeyOwner(username string) string { return KeyOwnerUserPrefix + username }

// OrgKeyOwner is the key_owner for a box attributed to a cloud organization.
func OrgKeyOwner(orgID string) string { return KeyOwnerOrgPrefix + orgID }

// keyOwnerIDRE is what may follow the namespace prefix: the printable,
// separator-free shapes a username or a UUID takes. It deliberately excludes
// '/', ':' and whitespace so a key_owner can never break out of the namespace
// it is used to build (e.g. the reserved secret-store path the daemon keeps
// per-owner keys under).
var keyOwnerIDRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// ValidateKeyOwner returns nil for a well-formed key_owner: one of the known
// namespace prefixes followed by an id of printable, separator-free characters.
// Callers that mint tokens or store per-owner keys validate here rather than
// each inventing a rule.
func ValidateKeyOwner(keyOwner string) error {
	if keyOwner == "" {
		return fmt.Errorf("modelgateway: key_owner is required")
	}
	for _, prefix := range []string{KeyOwnerUserPrefix, KeyOwnerOrgPrefix} {
		id, ok := strings.CutPrefix(keyOwner, prefix)
		if !ok {
			continue
		}
		if !keyOwnerIDRE.MatchString(id) {
			return fmt.Errorf("modelgateway: key_owner %q: id after %q must match %s", keyOwner, prefix, keyOwnerIDRE)
		}
		return nil
	}
	return fmt.Errorf("modelgateway: key_owner %q must start with %q or %q", keyOwner, KeyOwnerUserPrefix, KeyOwnerOrgPrefix)
}

// KeyResolver returns the REAL upstream key for one key owner and provider.
//
// Implementations are injected through Config; the gateway never reads a key
// out of the environment itself after construction. The daemon satisfies this
// with its existing encrypted secrets store, which keeps per-owner keys under a
// reserved namespace that no tenant can list and no delivery mode ever ships to
// a box.
//
// Implementations must be safe for concurrent use — this is consulted on the
// hot path of every proxied model call whose token carries a key_owner.
type KeyResolver interface {
	// KeyFor returns the key for (keyOwner, provider) and whether one exists.
	// It must return ("", false) rather than an error for "no key here": the
	// gateway's fallback to the daemon-global key is a normal outcome, not a
	// failure worth failing a request over.
	KeyFor(ctx context.Context, keyOwner, provider string) (key string, ok bool)
}

// KeyResolverFunc adapts a function to KeyResolver.
type KeyResolverFunc func(ctx context.Context, keyOwner, provider string) (string, bool)

// KeyFor implements KeyResolver.
func (f KeyResolverFunc) KeyFor(ctx context.Context, keyOwner, provider string) (string, bool) {
	return f(ctx, keyOwner, provider)
}

// resolveKey picks the real upstream key for one call.
//
// Precedence, per the design ("workspace on your own inference key", component
// 1): the token's own owner first, the daemon-global key second.
//
//  1. no key_owner claim -> Config.ProviderKeys only. The resolver is not even
//     asked, so a legacy token behaves bit-for-bit as before.
//  2. key_owner + a resolver that has a key -> that key.
//  3. key_owner + no key for that owner -> Config.ProviderKeys, logged. The
//     design specifies this fallback; it is also the case worth noticing,
//     because an owner whose key was removed would otherwise silently spend
//     the platform's. The mint path refusing to issue a key_owner token
//     without a key (FootprintAI/Containarium#1726) is what keeps case 3 from
//     happening in normal operation.
//  4. neither -> ("", false), and handleModel refuses the call without ever
//     touching an upstream.
func (g *Gateway) resolveKey(ctx context.Context, claims *GatewayClaims, provider string) (string, bool) {
	if claims.KeyOwner != "" && g.cfg.KeyResolver != nil {
		if key, ok := g.cfg.KeyResolver.KeyFor(ctx, claims.KeyOwner, provider); ok && key != "" {
			return key, true
		}
		if global := g.cfg.ProviderKeys[provider]; global != "" {
			g.cfg.Logger.Printf("model-gateway: key_owner=%s has no %s key; falling back to the daemon-global key (this call is billed to the operator, not the owner)",
				claims.KeyOwner, provider)
			return global, true
		}
		return "", false
	}
	key := g.cfg.ProviderKeys[provider]
	return key, key != ""
}

// OwnerRevocationChecker reports the instant before which every gateway token
// issued for one key owner is dead.
//
// This is the "the customer removed their key" kill-switch, and it is a
// different question from the per-jti list in revocation.go: there is no
// registry of the tokens issued for an owner to walk, and a long-lived recipe
// token may have been minted a year ago. A cutoff answers it in one lookup —
// and, unlike a boolean flag per owner, it does not need an un-revoke verb: a
// token minted AFTER the cutoff (the owner added a new key) is valid again on
// its own.
//
// Implementations must be safe for concurrent use.
type OwnerRevocationChecker interface {
	// RevokedBefore returns the cutoff for keyOwner. A token whose iat is at
	// or before it is revoked. The zero time means nothing is revoked for this
	// owner; an empty keyOwner must return the zero time and no error.
	RevokedBefore(ctx context.Context, keyOwner string) (time.Time, error)
}

// ownerRevoker is the write half, kept separate from the read half exactly like
// admin.go's revoker: a Config may hold a read-only checker, and
// RevokeByKeyOwner then says so instead of silently doing nothing.
type ownerRevoker interface {
	RevokeOwner(ctx context.Context, keyOwner string, at time.Time, reason string) error
}

// RevokeByKeyOwner kills every gateway token issued for keyOwner up to now, so
// the next call each of them makes is refused. Tokens minted after this returns
// are unaffected — that is what lets an owner re-register a key without an
// un-revoke verb.
//
// Requires Config.OwnerRevocations to be a store that can record revocations
// (MemOwnerRevocations, or the daemon's durable equivalent); with a read-only
// or absent store this returns an error rather than pretending to have revoked
// anything.
func (g *Gateway) RevokeByKeyOwner(ctx context.Context, keyOwner, reason string) error {
	if err := ValidateKeyOwner(keyOwner); err != nil {
		return err
	}
	rev, ok := g.cfg.OwnerRevocations.(ownerRevoker)
	if !ok {
		return fmt.Errorf("modelgateway: gateway holds no revocable owner-revocation store")
	}
	return rev.RevokeOwner(ctx, keyOwner, time.Now(), reason)
}

// ownerRevocationLookupTimeout bounds one owner-revocation lookup, mirroring
// revocationLookupTimeout for the per-jti list.
const ownerRevocationLookupTimeout = 500 * time.Millisecond

// isOwnerRevoked reports whether this token is dead because its key owner was
// revoked.
//
// Fails OPEN on a lookup error, for the same reason and with the same
// consequences as isRevoked: signature, issuer, expiry and provider binding
// have all been checked by the time this runs, so a store outage degrades to
// the protection that existed before this check rather than taking every
// tenant's model traffic down with the database.
//
// A token with no key_owner, or a gateway with no owner-revocation store, skips
// the lookup entirely.
func (g *Gateway) isOwnerRevoked(ctx context.Context, claims *GatewayClaims) bool {
	if g.cfg.OwnerRevocations == nil || claims.KeyOwner == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, ownerRevocationLookupTimeout)
	defer cancel()

	cutoff, err := g.cfg.OwnerRevocations.RevokedBefore(ctx, claims.KeyOwner)
	if err != nil {
		log.Printf("model-gateway: owner-revocation lookup failed for key_owner=%s: %v (allowing; the revocation list is a kill-switch, not the primary gate)", claims.KeyOwner, err)
		return false
	}
	if cutoff.IsZero() {
		return false
	}
	// A token with no iat cannot be placed relative to the cutoff. Treat it as
	// revoked: MintTokenWithID has always stamped iat, so the only tokens
	// reaching this branch are hand-made ones, and "I can't tell when this was
	// issued" is not a reason to let a revoked owner's traffic through.
	if claims.IssuedAt == nil {
		return true
	}
	// Not-After rather than Before: iat is truncated to the second when signed,
	// so a token minted in the same second as the revocation reads as issued at
	// or before the cutoff and is killed. Erring toward the kill-switch here is
	// the right side to be wrong on for at most one second.
	return !claims.IssuedAt.After(cutoff)
}

// MemOwnerRevocations is an in-memory OwnerRevocationChecker: the standalone
// gateway binary and the tests use it, and it is the reference shape a durable
// implementation mirrors (RevokeOwner + RevokedBefore, keyed on key_owner
// alone, exactly as MemRevocations is keyed on jti alone).
//
// Entries are never swept: unlike a per-jti revocation, an owner cutoff stays
// meaningful for as long as any token minted before it could still be
// presented, and there is one entry per owner rather than one per token, so the
// map is bounded by the number of owners a daemon serves.
type MemOwnerRevocations struct {
	mu     sync.RWMutex
	cutoff map[string]time.Time
}

// NewMemOwnerRevocations builds an empty MemOwnerRevocations.
func NewMemOwnerRevocations() *MemOwnerRevocations {
	return &MemOwnerRevocations{cutoff: map[string]time.Time{}}
}

// RevokedBefore implements OwnerRevocationChecker.
func (m *MemOwnerRevocations) RevokedBefore(_ context.Context, keyOwner string) (time.Time, error) {
	if keyOwner == "" {
		return time.Time{}, nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cutoff[keyOwner], nil
}

// RevokeOwner records at as keyOwner's cutoff, keeping the latest one if
// several revocations land — a revocation must never narrow.
func (m *MemOwnerRevocations) RevokeOwner(_ context.Context, keyOwner string, at time.Time, _ string) error {
	if keyOwner == "" {
		return fmt.Errorf("modelgateway: revoke owner: empty key_owner")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if prev, ok := m.cutoff[keyOwner]; ok && prev.After(at) {
		return nil
	}
	m.cutoff[keyOwner] = at
	return nil
}
