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
	maxTokenExpiry time.Duration
}

// NewTokenManager creates a new token manager
func NewTokenManager(secretKey string, issuer string) *TokenManager {
	maxExpiry := DefaultMaxTokenExpiry

	// Allow override via environment variable (in hours)
	if envMaxExpiry := os.Getenv("CONTAINARIUM_MAX_TOKEN_EXPIRY_HOURS"); envMaxExpiry != "" {
		if hours, err := strconv.ParseInt(envMaxExpiry, 10, 64); err == nil && hours > 0 {
			maxExpiry = time.Duration(hours) * time.Hour
		}
	}

	return &TokenManager{
		secretKey:      []byte(secretKey),
		issuer:         issuer,
		maxTokenExpiry: maxExpiry,
	}
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
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(tm.secretKey)
}

// ValidateToken validates a JWT token and returns claims
func (tm *TokenManager) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return tm.secretKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
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
