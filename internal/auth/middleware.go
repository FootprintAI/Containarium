package auth

import (
	"context"
	"net/http"
	"strings"
	"time"

	"google.golang.org/grpc"
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

// HTTPMiddleware is HTTP middleware for REST endpoints
// It validates Bearer tokens and adds authentication info to the context
func (am *AuthMiddleware) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, `{"error": "missing authorization header", "code": 401}`, http.StatusUnauthorized)
			return
		}

		// Check Bearer prefix
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			http.Error(w, `{"error": "invalid authorization header format, expected 'Bearer <token>'", "code": 401}`, http.StatusUnauthorized)
			return
		}

		token := parts[1]

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
		md := metadata.Pairs(mdPairs...)
		ctx = metadata.NewOutgoingContext(ctx, md)

		// Continue with modified request
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GRPCUnaryInterceptor for gRPC unary calls (preserves mTLS)
// For gRPC, we rely on mTLS authentication, so this is a passthrough
func (am *AuthMiddleware) GRPCUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// For gRPC, rely on mTLS - no token validation
		// Just pass through to the handler
		return handler(ctx, req)
	}
}

// GRPCStreamInterceptor for gRPC streaming calls (preserves mTLS)
// For gRPC, we rely on mTLS authentication, so this is a passthrough
func (am *AuthMiddleware) GRPCStreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		// For gRPC, rely on mTLS - no token validation
		// Just pass through to the handler
		return handler(srv, ss)
	}
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
