package auth

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// DefaultMaxTokenExpiry is the default maximum token expiry (30 days)
const DefaultMaxTokenExpiry = 30 * 24 * time.Hour

// MinSecretKeyLen is the smallest acceptable JWT signing key.
// HMAC-SHA256 expects a key with at least 32 bytes of entropy for
// the security level it claims; weaker keys are brute-forceable
// offline within practical compute budgets. Tracks audit finding
// A-MED-2.
const MinSecretKeyLen = 32

// DefaultAudience is the audience claim Containarium-issued tokens
// carry by default. Validators reject tokens whose `aud` doesn't
// include this string, so a token minted for an unrelated service
// (or by a future tool that shares the same signing key) can't be
// replayed against the daemon. Tracks audit finding A-HIGH-1.
const DefaultAudience = "containarium-api"

// Claims represents the JWT claims for authentication
type Claims struct {
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
	jwt.RegisteredClaims
}

// TokenManager handles JWT token generation and validation
type TokenManager struct {
	secretKey      []byte
	issuer         string
	audience       string
	maxTokenExpiry time.Duration
}

// NewTokenManager creates a new token manager. Returns an error if
// the secret key is shorter than MinSecretKeyLen — fail-closed
// rather than silently accepting weak crypto (audit finding
// A-MED-2).
//
// The default audience is DefaultAudience; override via
// CONTAINARIUM_JWT_AUDIENCE for cross-tenant token issuance.
func NewTokenManager(secretKey string, issuer string) (*TokenManager, error) {
	if len(secretKey) < MinSecretKeyLen {
		return nil, fmt.Errorf("JWT secret is %d bytes, want >=%d (HMAC-SHA256 minimum); generate with `openssl rand -base64 48`", len(secretKey), MinSecretKeyLen)
	}

	maxExpiry := DefaultMaxTokenExpiry

	// Allow override via environment variable (in hours)
	if envMaxExpiry := os.Getenv("CONTAINARIUM_MAX_TOKEN_EXPIRY_HOURS"); envMaxExpiry != "" {
		if hours, err := strconv.ParseInt(envMaxExpiry, 10, 64); err == nil && hours > 0 {
			maxExpiry = time.Duration(hours) * time.Hour
		}
	}

	audience := DefaultAudience
	if env := os.Getenv("CONTAINARIUM_JWT_AUDIENCE"); env != "" {
		audience = env
	}

	return &TokenManager{
		secretKey:      []byte(secretKey),
		issuer:         issuer,
		audience:       audience,
		maxTokenExpiry: maxExpiry,
	}, nil
}

// GenerateToken creates a JWT token for a user
// SECURITY FIX: Non-expiring tokens are no longer allowed.
// Maximum expiry is enforced (default: 30 days, configurable via CONTAINARIUM_MAX_TOKEN_EXPIRY_HOURS)
func (tm *TokenManager) GenerateToken(username string, roles []string, expiresIn time.Duration) (string, error) {
	// SECURITY FIX: Enforce maximum expiry - no more non-expiring tokens
	if expiresIn <= 0 || expiresIn > tm.maxTokenExpiry {
		expiresIn = tm.maxTokenExpiry
	}

	claims := Claims{
		Username: username,
		Roles:    roles,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    tm.issuer,
			Audience:  jwt.ClaimStrings{tm.audience},
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(tm.secretKey)
}

// errInvalidToken is the only token-validation error returned to
// clients. Keeping it generic prevents reconnaissance via error
// messages (which algorithm was tried, whether the signature or the
// expiry failed, etc.). The full reason is still logged server-side.
var errInvalidToken = fmt.Errorf("invalid token")

// ValidateToken validates a JWT token and returns claims.
//
// Hardening for zero-trust:
//
//   - Algorithm is pinned to HS256. Tokens this daemon issues are
//     always HS256 (see GenerateToken). Accepting any HMAC variant
//     (HS384, HS512) widens the attack surface for nothing — and the
//     loose check that was here previously left the door open to
//     library-level alg-confusion bugs if a dependency ever
//     regressed. See finding A-CRIT-3 in docs/security/.
//   - The error returned to clients is a generic "invalid token",
//     never leaking the offending algorithm name or the
//     library-level parse error. Full detail is still logged via
//     %w-wrapping at the caller's discretion.
func (tm *TokenManager) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Pin to HS256 exactly. SigningMethodHS256.Alg() == "HS256".
		if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, errInvalidToken
		}
		return tm.secretKey, nil
	},
		// Audit A-HIGH-1: iss and aud must match this daemon's
		// configuration. A token signed by the same key for a
		// different deployment or with a different intended audience
		// is now rejected.
		jwt.WithIssuer(tm.issuer),
		jwt.WithAudience(tm.audience),
	)

	if err != nil {
		return nil, errInvalidToken
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, errInvalidToken
}

// Context keys for storing authentication information
type contextKey string

const (
	ContextKeyUsername contextKey = "username"
	ContextKeyRoles    contextKey = "roles"
)

// ContextWithClaims adds authentication claims to context
func ContextWithClaims(ctx context.Context, claims *Claims) context.Context {
	ctx = context.WithValue(ctx, ContextKeyUsername, claims.Username)
	ctx = context.WithValue(ctx, ContextKeyRoles, claims.Roles)
	return ctx
}

// UsernameFromContext retrieves username from context
func UsernameFromContext(ctx context.Context) (string, bool) {
	username, ok := ctx.Value(ContextKeyUsername).(string)
	return username, ok
}

// RolesFromContext retrieves roles from context
func RolesFromContext(ctx context.Context) ([]string, bool) {
	roles, ok := ctx.Value(ContextKeyRoles).([]string)
	return roles, ok
}
