package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
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

// Claims represents the JWT claims for authentication.
//
// Phase 1.7 — `Scopes` is the OAuth2-style scope list for
// least-privilege tokens (typically agent-facing tokens).
// `omitempty` keeps pre-1.7 tokens identical on the wire;
// HasScope treats a nil/missing scopes array as "no
// restriction" for backwards compat.
//
// Phase 1.6 — `TokenType` (claim `tt`) distinguishes access
// tokens (used for API auth) from refresh tokens (used only
// to exchange for new access tokens). `omitempty` keeps
// pre-1.6 tokens identical on the wire; an empty / missing
// tt is interpreted as TokenTypeAccess (backwards compat).
// API auth (HTTP middleware) calls ValidateAccessToken,
// which refuses any token whose tt is explicitly
// "refresh" — so a stolen refresh token can't make API
// calls even though it has a valid signature.
type Claims struct {
	Username  string   `json:"username"`
	Roles     []string `json:"roles"`
	Scopes    []string `json:"scopes,omitempty"`
	TokenType string   `json:"tt,omitempty"`
	jwt.RegisteredClaims
}

// Token-type constants for the `tt` claim.
const (
	TokenTypeAccess  = "access"
	TokenTypeRefresh = "refresh"
)

// DefaultRefreshTokenExpiry is the cap for refresh-token
// lifetime when a caller passes zero. Long enough for a
// CLI / agent session, short enough that a leaked token
// has bounded blast radius. Capped at the same
// maxTokenExpiry as access tokens — operators can shorten
// either via CONTAINARIUM_MAX_TOKEN_EXPIRY_HOURS.
const DefaultRefreshTokenExpiry = 30 * 24 * time.Hour

// DefaultAccessTokenExpiry is the default for access tokens
// minted via GenerateAccessToken when caller passes 0.
// Short by design — that's the whole point of Phase 1.6;
// the refresh token does the long-lived work.
const DefaultAccessTokenExpiry = 15 * time.Minute

// TokenManager handles JWT token generation and validation
type TokenManager struct {
	secretKey      []byte
	issuer         string
	audience       string
	maxTokenExpiry time.Duration

	// Phase 1.2 — optional revocation list. nil = check
	// disabled (tests, minimal deployments). Production
	// wires a Postgres-backed PgRevocationStore here.
	revocationStore RevocationStore
}

// SetRevocationStore enables the revocation-list check on
// ValidateToken. Pass nil to disable. Typically wired once
// at daemon startup after the Postgres pool is ready.
func (tm *TokenManager) SetRevocationStore(store RevocationStore) {
	tm.revocationStore = store
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

// GenerateToken creates a JWT token for a user.
//
// SECURITY FIX: Non-expiring tokens are no longer allowed.
// Maximum expiry is enforced (default: 30 days, configurable
// via CONTAINARIUM_MAX_TOKEN_EXPIRY_HOURS).
//
// Phase 1.2: every token now carries a `jti` claim — a
// cryptographic-random 128-bit ID base64url-encoded. The
// jti is the key the revocation list operates on, so a
// token's lifetime can be cut short by writing one row.
//
// Phase 1.7: the variadic `scopes` parameter sets the
// least-privilege `scopes` claim. Pass nothing (or nil)
// for a no-restriction token — matches pre-1.7 behavior.
// Pass a list to mint a least-privilege token, e.g. for
// an LLM agent that should only see read APIs.
func (tm *TokenManager) GenerateToken(username string, roles []string, expiresIn time.Duration, scopes ...string) (string, error) {
	// Backwards-compatible shim. New code should call
	// GenerateAccessToken / GenerateRefreshToken directly.
	// Existing callers (CLI, daemon system tokens) keep
	// minting access tokens with their current call sites
	// because tt defaults to "" → access semantics.
	return tm.generate(username, roles, scopes, "", expiresIn)
}

// GenerateAccessToken mints a short-lived access token.
// Phase 1.6 — pass 0 for the daemon default
// (DefaultAccessTokenExpiry). Carries `tt: "access"`;
// ValidateAccessToken on the API surface enforces it.
func (tm *TokenManager) GenerateAccessToken(username string, roles []string, expiresIn time.Duration, scopes ...string) (string, error) {
	if expiresIn <= 0 {
		expiresIn = DefaultAccessTokenExpiry
	}
	return tm.generate(username, roles, scopes, TokenTypeAccess, expiresIn)
}

// GenerateRefreshToken mints a long-lived refresh token.
// Pass 0 for the daemon default (DefaultRefreshTokenExpiry).
// Carries `tt: "refresh"`; ValidateAccessToken on the API
// surface REJECTS this token, so a stolen refresh token
// can't make API calls. Use ValidateRefreshToken when
// implementing the exchange RPC (Phase 1.6 part B).
func (tm *TokenManager) GenerateRefreshToken(username string, roles []string, expiresIn time.Duration, scopes ...string) (string, error) {
	if expiresIn <= 0 {
		expiresIn = DefaultRefreshTokenExpiry
	}
	return tm.generate(username, roles, scopes, TokenTypeRefresh, expiresIn)
}

// generate is the shared implementation. tt may be the
// empty string for the legacy GenerateToken path; it
// stays omitempty on the wire so pre-1.6 token shapes are
// byte-identical for existing test fixtures.
func (tm *TokenManager) generate(username string, roles, scopes []string, tt string, expiresIn time.Duration) (string, error) {
	// SECURITY FIX: Enforce maximum expiry - no more non-expiring tokens
	if expiresIn <= 0 || expiresIn > tm.maxTokenExpiry {
		expiresIn = tm.maxTokenExpiry
	}

	jti, err := newJTI()
	if err != nil {
		return "", fmt.Errorf("generate jti: %w", err)
	}

	var scopesClaim []string
	if len(scopes) > 0 {
		scopesClaim = scopes
	}

	claims := Claims{
		Username:  username,
		Roles:     roles,
		Scopes:    scopesClaim,
		TokenType: tt,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
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

// newJTI returns a base64url-encoded 128-bit cryptographic
// random ID. 128 bits is enough that collisions never happen
// in practice (birthday-bound ~2^64 issuances), and base64url
// keeps the encoded form URL-safe and JWT-friendly.
func newJTI() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
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

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errInvalidToken
	}

	// Phase 1.2 — revocation list check. We use a short
	// background timeout so a slow DB doesn't stall the
	// auth path. A DB outage fails *open* by design
	// (revocation is a kill-switch, not the primary auth
	// gate); a noisy log makes the failure visible without
	// taking the daemon down. Tokens issued before this
	// release lack a jti — IsRevoked short-circuits on
	// empty input.
	if tm.revocationStore != nil && claims.ID != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		revoked, rerr := tm.revocationStore.IsRevoked(ctx, claims.ID)
		if rerr != nil {
			log.Printf("WARNING: revocation lookup failed for jti=%s: %v (allowing token; revocation list is the kill-switch, not the primary gate)", claims.ID, rerr)
		} else if revoked {
			return nil, errInvalidToken
		}
	}

	return claims, nil
}

// ValidateAccessToken validates a token AND enforces that
// the `tt` claim is either empty (pre-1.6 token, treated as
// access for backwards compat) or "access". A token marked
// "refresh" is REJECTED — it must not be usable for API
// calls. Wire this in the HTTP middleware once the daemon
// is ready to start enforcing the access/refresh split.
//
// Returns the same generic errInvalidToken on any failure
// (signature, expiry, type mismatch) — no reconnaissance
// detail leaks to the client.
func (tm *TokenManager) ValidateAccessToken(tokenString string) (*Claims, error) {
	claims, err := tm.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}
	if claims.TokenType != "" && claims.TokenType != TokenTypeAccess {
		return nil, errInvalidToken
	}
	return claims, nil
}

// ValidateRefreshToken validates a token AND enforces that
// `tt == "refresh"`. Used by the refresh-exchange RPC
// (Phase 1.6 part B). Rejects access tokens and pre-1.6
// tokens — only an explicit refresh token can be
// exchanged.
func (tm *TokenManager) ValidateRefreshToken(tokenString string) (*Claims, error) {
	claims, err := tm.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}
	if claims.TokenType != TokenTypeRefresh {
		return nil, errInvalidToken
	}
	return claims, nil
}

// RevokeToken adds the given claims' jti to the revocation
// list, using its exp claim as the cleanup horizon. Typically
// called from logout / admin-revoke flows after the claims
// have already been validated.
//
// Returns an error if the store is unconfigured (the caller
// is asking to revoke when there's no revocation list — that
// would silently no-op, which is dangerous).
func (tm *TokenManager) RevokeToken(ctx context.Context, claims *Claims, reason string) error {
	if tm.revocationStore == nil {
		return fmt.Errorf("revocation store not configured")
	}
	if claims == nil || claims.ID == "" {
		return fmt.Errorf("token has no jti — cannot revoke (pre-Phase-1.2 token?)")
	}
	exp := time.Time{}
	if claims.ExpiresAt != nil {
		exp = claims.ExpiresAt.Time
	}
	return tm.revocationStore.Revoke(ctx, claims.ID, exp, reason)
}

// Context keys for storing authentication information
type contextKey string

const (
	ContextKeyUsername contextKey = "username"
	ContextKeyRoles    contextKey = "roles"
	ContextKeyScopes   contextKey = "scopes" // Phase 1.7b
)

// ContextWithClaims adds authentication claims to context
func ContextWithClaims(ctx context.Context, claims *Claims) context.Context {
	ctx = context.WithValue(ctx, ContextKeyUsername, claims.Username)
	ctx = context.WithValue(ctx, ContextKeyRoles, claims.Roles)
	if claims.Scopes != nil {
		ctx = context.WithValue(ctx, ContextKeyScopes, claims.Scopes)
	}
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

// ScopesFromContext retrieves the JWT `scopes` claim from
// context. Returns (nil, false) when no scopes were carried —
// callers should treat as "no restriction" (the Phase 1.7
// backwards-compat path). Phase 1.7b.
func ScopesFromContext(ctx context.Context) ([]string, bool) {
	scopes, ok := ctx.Value(ContextKeyScopes).([]string)
	return scopes, ok
}
