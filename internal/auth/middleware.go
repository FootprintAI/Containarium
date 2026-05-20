package auth

import (
	"context"
	"net/http"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// AuthMiddleware handles authentication for HTTP and gRPC requests
type AuthMiddleware struct {
	tokenManager *TokenManager
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(tokenManager *TokenManager) *AuthMiddleware {
	return &AuthMiddleware{
		tokenManager: tokenManager,
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
		claims, err := am.tokenManager.ValidateToken(token)
		if err != nil {
			http.Error(w, `{"error": "invalid token", "code": 401}`, http.StatusUnauthorized)
			return
		}

		// Add claims to context
		ctx := ContextWithClaims(r.Context(), claims)

		// Add to gRPC metadata for gateway forwarding
		md := metadata.Pairs(
			"username", claims.Username,
			"roles", strings.Join(claims.Roles, ","),
		)
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

// ValidateToken validates a JWT token and returns claims
func (am *AuthMiddleware) ValidateToken(token string) (*Claims, error) {
	return am.tokenManager.ValidateToken(token)
}
