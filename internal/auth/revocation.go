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

	// CleanupExpired removes revocation rows whose token
	// expiry is in the past. Returns the number of rows
	// pruned. Callers loop until the count is 0 (or until
	// they hit their own time budget).
	CleanupExpired(ctx context.Context, now time.Time) (int64, error)
}
