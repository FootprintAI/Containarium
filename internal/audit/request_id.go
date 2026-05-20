package audit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
)

// Phase 4.6 — per-request correlation IDs (audit doc).
//
// Every audited request gets an X-Request-ID that's:
//   - Echoed in the response header so clients (and external
//     log aggregators) can correlate their view with the
//     daemon's audit row.
//   - Available on the request context for any handler that
//     wants to include it in error responses, peer-forwarded
//     RPC headers, or its own log lines.
//   - Stored in the audit row's Detail field (request_id=<id>)
//     so a single grep across audit_logs surfaces every
//     request from a given correlation ID.
//
// If the inbound request already carries an X-Request-ID — for
// example a reverse-proxy assigned one — we preserve it.
// Otherwise we generate a fresh 128-bit hex string (cryptographic
// rand, plenty to avoid collisions over the audit table's
// retention window).

const RequestIDHeader = "X-Request-ID"

type requestIDKey struct{}

// RequestIDFromContext returns the request ID set by the audit
// middleware. Empty string if no ID was attached (e.g. a request
// that bypassed the middleware).
func RequestIDFromContext(ctx context.Context) string {
	if id, ok := ctx.Value(requestIDKey{}).(string); ok {
		return id
	}
	return ""
}

// ContextWithRequestID attaches `id` to the context. Exposed for
// tests and for handlers that synthesize their own context for
// background work but want to keep the correlation chain.
func ContextWithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// extractOrGenerateRequestID returns the X-Request-ID the caller
// supplied, after sanity-checking shape, or a fresh one. The
// shape check guards against an attacker putting a giant header
// value through to bloat the audit row.
func extractOrGenerateRequestID(r *http.Request) string {
	if got := r.Header.Get(RequestIDHeader); got != "" && validRequestID(got) {
		return got
	}
	return newRequestID()
}

func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand.Read shouldn't fail; if it does, return a
		// constant so the request still goes through — the
		// correlation is degraded, not the request.
		return "0000000000000000-degenerate"
	}
	return hex.EncodeToString(b[:])
}

// validRequestID accepts hex/dash/underscore strings up to 128
// chars. Conservative on purpose — a UUID, a hex digest, or a
// short tag all fit. Anything more exotic gets replaced.
func validRequestID(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := (c >= '0' && c <= '9') ||
			(c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') ||
			c == '-' || c == '_'
		if !ok {
			return false
		}
	}
	return true
}
