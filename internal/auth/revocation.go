package auth

import (
	"context"
	"time"
)

// Phase 1.2 — JWT revocation list (audit A-MED-1).
//
// HMAC JWTs we issue carry an `exp` claim that bounds how
// long they're valid. But until exp fires, a stolen token
// is usable — there's no kill-switch. The revocation list
// is the kill-switch: an admin marks a token's `jti`
// revoked, ValidateToken checks the list, and the token
// is rejected from that point on regardless of remaining
// lifetime.
//
// Storage is intentionally narrow: a single table keyed on
// jti, with the token's original exp so we can prune expired
// rows (a jti past its exp can't authenticate anyway, so the
// row stops being useful). The interface lives here so tests
// can stub it without pulling in pgx.

// RevocationStore looks up and records revoked token IDs.
//
// Implementations must be safe for concurrent use — the
// daemon calls IsRevoked on every authenticated request.
type RevocationStore interface {
	// IsRevoked returns true if the given jti has been
	// revoked. An empty jti returns (false, nil) — tokens
	// minted before Phase 1.2 don't carry a jti and the
	// revocation check is a no-op for them. (Phase 1.6
	// short-lived tokens will narrow the window where that
	// fallback matters.)
	IsRevoked(ctx context.Context, jti string) (bool, error)

	// Revoke marks a jti as revoked. `expiresAt` is the
	// token's original exp claim — it lets us prune the row
	// later. `reason` is free-form, for the audit trail
	// (e.g. "user_logout", "admin_revoke", "compromise").
	//
	// Revoking the same jti twice is idempotent; the existing
	// reason is preserved on conflict (the first revocation
	// is the canonical record).
	Revoke(ctx context.Context, jti string, expiresAt time.Time, reason string) error

	// RevokeClaim is Revoke, but reports whether THIS call was the one
	// that inserted the row (claimed=true) versus the jti was already
	// revoked by an earlier call (claimed=false, no error). Both cases
	// leave the row in the same idempotent state as Revoke.
	//
	// This is the primitive that lets a caller distinguish "I am the
	// first and only holder of this single-use credential" from "this
	// credential has already been spent" atomically — the insert IS the
	// check, so two concurrent callers racing the same jti can't both
	// observe claimed=true. The refresh-token rotation path uses this
	// to close a mint-then-revoke race: revoking is the claim, and only
	// the caller that wins it may mint the replacement pair.
	RevokeClaim(ctx context.Context, jti string, expiresAt time.Time, reason string) (claimed bool, err error)

	// RevokeFamily marks an entire refresh-token rotation family
	// compromised: every token that ever carried this family id — past
	// or future — is rejected from this point on, regardless of
	// whether its own jti was individually revoked. `reason` is
	// free-form, for the audit trail.
	//
	// This is the response to a RevokeClaim(claimed=false): if a
	// refresh token's jti was already spent, the token has now been
	// presented twice (a concurrent racer or a genuine theft-and-replay
	// — the two are indistinguishable from here), and the only safe
	// response is to kill the whole chain rather than guess which
	// presenter was legitimate.
	RevokeFamily(ctx context.Context, familyID string, reason string) error

	// IsFamilyRevoked returns true if RevokeFamily was ever called for
	// this family id. Checked by the refresh-exchange path in addition
	// to the per-jti IsRevoked check, so a still-valid, never-before-used
	// token from an already-compromised family is still rejected.
	IsFamilyRevoked(ctx context.Context, familyID string) (bool, error)

	// CleanupExpired removes revocation rows whose token
	// expiry is in the past. Returns the number of rows
	// pruned. Callers loop until the count is 0 (or until
	// they hit their own time budget).
	CleanupExpired(ctx context.Context, now time.Time) (int64, error)

	// List returns revocation rows in reverse-chronological
	// order (most recently revoked first), bounded by
	// params.Limit. `params.IncludeExpired` toggles whether
	// rows whose expires_at has already passed are returned
	// — operators investigating a leak may want them; the
	// default (false) only returns "still kill-switching
	// something" rows.
	//
	// This is the admin-enumeration path; not on the
	// authenticated-request hot path.
	List(ctx context.Context, params ListRevocationsParams) ([]Revocation, error)
}

// Revocation is one row of the revocation list, exposed to
// callers via List. Mirrors the schema; no encryption /
// transformation needed.
type Revocation struct {
	JTI       string
	ExpiresAt time.Time
	RevokedAt time.Time
	Reason    string
}

// ListRevocationsParams configures a List call.
type ListRevocationsParams struct {
	// Limit caps the returned rows. 0 → 100 default; max
	// 1000 (enforced at the SQL layer too).
	Limit int

	// IncludeExpired returns rows whose expires_at is in
	// the past. Default false — operators investigating a
	// leak usually only want active revocations. Forensic
	// queries asking "did we ever revoke this jti?" set it
	// to true.
	IncludeExpired bool

	// JTIPrefix narrows the result to jtis starting with
	// this prefix. Empty disables the filter. Useful when
	// an operator only remembers part of a leaked jti.
	JTIPrefix string
}
