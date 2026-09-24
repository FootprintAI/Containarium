package auth

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"google.golang.org/grpc/metadata"
)

// AuthMiddleware handles authentication for HTTP and gRPC requests
type AuthMiddleware struct {
	tokenManager *TokenManager

	// failureLimiter rate-limits failed JWT validations per
	// source IP. nil disables (used in tests). Production wiring
	// always provides one — see NewAuthMiddleware. Audit C-MED-3.
	failureLimiter *AuthFailureLimiter
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(tokenManager *TokenManager) *AuthMiddleware {
	return &AuthMiddleware{
		tokenManager:   tokenManager,
		failureLimiter: NewAuthFailureLimiter(),
	}
}

// unauthPaths are HTTP endpoints that MUST skip the Bearer
// token check on the API surface — the endpoint's own
// payload IS the credential.
//
// /v1/tokens/refresh (Phase 1.6 part B): the request body
// carries the refresh token. Requiring an access token in
// the header on top would be silly — the whole point is
// that the client doesn't have a fresh access token yet.
var unauthPaths = map[string]bool{
	"/v1/tokens/refresh": true,
}

// SessionCookieName is the cookie that carries a JWT for
// browser navigation contexts that can't supply the
// Authorization header (notably <iframe src=...> — see
// issue #338). Bearer header still wins when both are
// present; the cookie is a strict fallback.
//
// The cookie value is the raw JWT — identical wire format
// to what would have been in `Authorization: Bearer ...`,
// so the same ValidateAccessToken path applies and the
// same Phase 1.6 refresh-token rejection holds.
const SessionCookieName = "containarium_session"

// HTTPMiddleware is HTTP middleware for REST endpoints
// It validates Bearer tokens and adds authentication info to the context
func (am *AuthMiddleware) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Phase 1.6 part B — skip auth for refresh
		// exchange. The refresh-token in the body is the
		// credential; the handler validates it.
		if unauthPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}

		// Extract token. Preference order:
		//   1. Authorization: Bearer <jwt> header (API, CLI, MCP — primary)
		//   2. containarium_session cookie       (browser iframe — issue #338)
		//
		// Browsers can't attach Authorization headers to <iframe src=...>
		// loads or top-level navigations, so the daemon's reverse proxies
		// (/grafana/, /alertmanager/, …) were unreachable from the
		// embedded webui. Accepting the JWT via cookie restores that path
		// without weakening API auth: bearer still wins, and the cookie
		// MUST be set explicitly by the webui via POST /v1/auth/session
		// — there's no implicit cookie minting.
		token := ""
		if authHeader := r.Header.Get("Authorization"); authHeader != "" {
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				http.Error(w, `{"error": "invalid authorization header format, expected 'Bearer <token>'", "code": 401}`, http.StatusUnauthorized)
				return
			}
			token = parts[1]
		} else if c, err := r.Cookie(SessionCookieName); err == nil && c.Value != "" {
			token = c.Value
		} else {
			http.Error(w, `{"error": "missing authorization header", "code": 401}`, http.StatusUnauthorized)
			return
		}

		// Validate token. The error returned by ValidateToken is
		// intentionally generic ("invalid token") so we don't leak
		// reconnaissance details (algorithm name, expiry vs.
		// signature failure, etc.) to clients. See finding A-MED-7.
		//
		// Phase 1.6 — ValidateAccessToken rejects tokens with
		// `tt: "refresh"`. A stolen refresh token can be exchanged
		// at the (future) /v1/tokens/refresh endpoint but cannot
		// authenticate to any API surface. Pre-1.6 tokens (no tt
		// claim) are treated as access by ValidateAccessToken for
		// backwards compat.
		claims, err := am.tokenManager.ValidateAccessToken(token)
		if err != nil {
			// Audit C-MED-3: per-IP token-bucket on failed
			// validations. Successful auth doesn't consume
			// tokens — only failures count, so legitimate
			// users at any rate stay unthrottled. Attacker
			// spraying invalid tokens gets 429 after the
			// burst.
			ip := clientIPFromRequest(r)
			if ip != "" && !am.failureLimiter.Allow(ip, time.Now()) {
				http.Error(w, `{"error": "too many failed authentication attempts; try again later", "code": 429}`, http.StatusTooManyRequests)
				return
			}
			http.Error(w, `{"error": "invalid token", "code": 401}`, http.StatusUnauthorized)
			return
		}

		// Add claims to context
		ctx := ContextWithClaims(r.Context(), claims)

		// Add to gRPC metadata for gateway forwarding. Phase
		// 1.7b — propagate the optional `scopes` claim too;
		// empty/missing scopes claim is omitted from the
		// metadata so RequireScope sees "no restriction".
		mdPairs := []string{
			MDKeyUsername, claims.Username,
			MDKeyRoles, strings.Join(claims.Roles, ","),
		}
		if len(claims.Scopes) > 0 {
			mdPairs = append(mdPairs, MDKeyScopes, strings.Join(claims.Scopes, ","))
		}
		// #1677 — propagate the optional `act` delegation claim the same
		// way: this is the exact hop ActFromGRPCContext exists for (see
		// its doc comment) — without this, a delegated token's act would
		// silently vanish for every REST/grpc-gateway caller, the primary
		// API surface, even though ContextWithClaims sets it locally.
		if claims.Act != nil {
			if encoded, err := json.Marshal(claims.Act); err == nil {
				mdPairs = append(mdPairs, MDKeyAct, string(encoded))
			}
		}
		// #1678 — propagate the token's own jti the same way, so audit
		// attribution (the first gRPC-side consumer) can name the acting
		// credential without a new plumbing hop of its own.
		if claims.ID != "" {
			mdPairs = append(mdPairs, MDKeyJTI, claims.ID)
		}
		// #1922 — propagate the optional `run_id` claim the same way, so
		// the tracker broker's write verbs can read the acting run's
		// identity off the verified token rather than a request field.
		if claims.RunID != "" {
			mdPairs = append(mdPairs, MDKeyRunID, claims.RunID)
		}
		// #1922 — propagate the optional `tracker_conn` claim the same way,
		// so the tracker verb RPCs can reject a request naming a different
		// connection than the one this run is bound to.
		if claims.TrackerConn != "" {
			mdPairs = append(mdPairs, MDKeyTrackerConn, claims.TrackerConn)
		}
		md := metadata.Pairs(mdPairs...)
		ctx = metadata.NewOutgoingContext(ctx, md)

		// Continue with modified request
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ValidateToken validates a JWT and returns claims for use
// on an API surface. Phase 1.6 — wraps ValidateAccessToken
// so refresh tokens are rejected. Callers that legitimately
// want any-token semantics (e.g. the refresh-exchange RPC
// validating an incoming refresh token) should call the
// TokenManager directly via ValidateRefreshToken.
//
// The name stays "ValidateToken" because every existing
// callsite is on an API surface where access-only semantics
// are the right policy.
func (am *AuthMiddleware) ValidateToken(token string) (*Claims, error) {
	return am.tokenManager.ValidateAccessToken(token)
}
