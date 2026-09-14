package modelgateway

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

// RevokeRequest is the wire shape of POST /__gateway/revoke. It lives here
// (not in cmd/model-gateway) so both sides of the wire build/parse the exact
// same JSON without a new import cycle: cmd/model-gateway already imports
// this package for GatewayClaims/MintToken, so its `revoke --jti` subcommand
// marshals this same struct rather than hand-building a request body that
// could drift from what the server decodes (see TestRevokeRequest_JSONShape,
// the golden shared by both).
type RevokeRequest struct {
	JTI string `json:"jti"`
	// ExpiresAt is RFC3339, and optional: empty (or omitted) means the
	// revocation never expires, mirroring MemRevocations' own treatment of a
	// zero time.Time (revocation.go). This is the safe default for a caller
	// that doesn't know the token's real expiry — e.g. cmd/model-gateway's
	// `revoke --jti` without --expires-at — since a wrong-but-plausible guess
	// (like "now+24h") would let MemRevocations' sweep silently un-revoke a
	// token whose real TTL runs longer, exactly the recipe-box case this
	// feature exists for (#1820 review).
	ExpiresAt string `json:"expires_at,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// revoker is the subset of a revocation store the admin endpoint needs to
// actually revoke, as opposed to RevocationChecker's read-only IsRevoked.
// Declared locally — like RevocationChecker in revocation.go — so this
// package keeps no dependency on internal/auth or internal/runlease. Both
// MemRevocations and the daemon's internal/auth.PgRevocationStore already
// implement this exact method shape (auth.RevocationStore.Revoke /
// runlease.Revoker), so either can sit behind Config.Revocations and be
// driven by this endpoint with no adapter.
type revoker interface {
	Revoke(ctx context.Context, jti string, expiresAt time.Time, reason string) error
}

// maxRevokeBody bounds the request body this handler will read. The payload
// is three short strings; anything past a few KB is a misbehaving or hostile
// client, not a legitimate revoke call.
const maxRevokeBody = 4 << 10

// handleAdminRevoke implements POST /__gateway/revoke. Gateway.Handler only
// registers this at all when Config.AdminToken is non-empty (see gateway.go)
// — reaching this function at all means an operator opted in.
//
// Order matters for what each failure reveals: method, then auth, then body
// shape. An unauthorized caller learns nothing about whether the JSON they
// didn't send would have been valid.
func (g *Gateway) handleAdminRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !adminBearerOK(r, g.cfg.AdminToken) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req RevokeRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxRevokeBody)).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.JTI == "" {
		http.Error(w, "bad request: jti is required", http.StatusBadRequest)
		return
	}
	// An empty expires_at means "never expires" (see RevokeRequest's doc
	// comment) — the zero time.Time, not an error. Only a non-empty value
	// that fails to parse is a bad request.
	var expiresAt time.Time
	if req.ExpiresAt != "" {
		var err error
		expiresAt, err = time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			http.Error(w, "bad request: expires_at: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	// A revocable store is a runtime concern, not a route-registration one:
	// AdminToken and Revocations are independent Config fields, so a
	// misconfigured operator (admin token set, no store, or a store that
	// only reads) gets a clear 500 here rather than a nil-pointer panic or a
	// silently-ignored revoke.
	rev, ok := g.cfg.Revocations.(revoker)
	if !ok {
		http.Error(w, "gateway holds no revocable store", http.StatusInternalServerError)
		return
	}
	if err := rev.Revoke(r.Context(), req.JTI, expiresAt, req.Reason); err != nil {
		http.Error(w, "revoke failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// adminBearerOK reports whether r carries "Authorization: Bearer <want>",
// comparing the presented token against want in constant time. want=="" (no
// admin token configured) always fails closed — callers only ever reach this
// with a non-empty want because Handler doesn't register the route
// otherwise, but a stray call from elsewhere must not treat "no token
// configured" as "any token matches".
//
// The length check ahead of subtle.ConstantTimeCompare leaks only the
// presented token's length, not which of its bytes matched — the property
// that actually matters for a bearer-token guess. ConstantTimeCompare itself
// requires equal-length inputs (it documents undefined-length behavior
// otherwise); comparing lengths first, plainly, is the standard way to reach
// it safely rather than padding or hashing both sides first.
func adminBearerOK(r *http.Request, want string) bool {
	if want == "" {
		return false
	}
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, prefix) {
		return false
	}
	got := strings.TrimPrefix(h, prefix)
	if len(got) != len(want) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}
