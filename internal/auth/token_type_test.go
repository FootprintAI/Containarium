package auth

import (
	"strings"
	"testing"
	"time"
)

// Phase 1.6 part A — `tt` claim + ValidateAccessToken /
// ValidateRefreshToken semantics.

func newTT(t *testing.T) *TokenManager {
	t.Helper()
	tm, err := NewTokenManager("test-secret-must-be-at-least-32-bytes-long-ok", "test")
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	return tm
}

// --- Generator output ---

func TestGenerateAccessToken_HasAccessTT(t *testing.T) {
	tm := newTT(t)
	tok, err := tm.GenerateAccessToken("alice", []string{"user"}, time.Hour)
	if err != nil {
		t.Fatalf("GenerateAccessToken: %v", err)
	}
	claims, err := tm.ValidateToken(tok)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if claims.TokenType != TokenTypeAccess {
		t.Fatalf("tt = %q, want %q", claims.TokenType, TokenTypeAccess)
	}
}

func TestGenerateRefreshToken_HasRefreshTT(t *testing.T) {
	tm := newTT(t)
	tok, err := tm.GenerateRefreshToken("alice", []string{"user"}, time.Hour)
	if err != nil {
		t.Fatalf("GenerateRefreshToken: %v", err)
	}
	claims, err := tm.ValidateToken(tok)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if claims.TokenType != TokenTypeRefresh {
		t.Fatalf("tt = %q, want %q", claims.TokenType, TokenTypeRefresh)
	}
}

func TestGenerateToken_LegacyHasEmptyTT(t *testing.T) {
	// The legacy GenerateToken path is the backwards-compat
	// shim. Its output must NOT set tt — that way the wire
	// format is byte-identical to pre-1.6 tokens.
	tm := newTT(t)
	tok, err := tm.GenerateToken("alice", []string{"user"}, time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	claims, err := tm.ValidateToken(tok)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if claims.TokenType != "" {
		t.Fatalf("legacy tt = %q, want empty", claims.TokenType)
	}
}

// --- ValidateAccessToken ---

func TestValidateAccessToken_AcceptsAccessToken(t *testing.T) {
	tm := newTT(t)
	tok, _ := tm.GenerateAccessToken("alice", []string{"user"}, time.Hour)
	if _, err := tm.ValidateAccessToken(tok); err != nil {
		t.Fatalf("access token should pass; got %v", err)
	}
}

func TestValidateAccessToken_AcceptsLegacyToken(t *testing.T) {
	// Pre-1.6 tokens have no tt. ValidateAccessToken treats
	// the empty string as access (backwards compat).
	tm := newTT(t)
	tok, _ := tm.GenerateToken("alice", []string{"user"}, time.Hour)
	if _, err := tm.ValidateAccessToken(tok); err != nil {
		t.Fatalf("legacy token should pass ValidateAccessToken; got %v", err)
	}
}

func TestValidateAccessToken_RejectsRefreshToken(t *testing.T) {
	tm := newTT(t)
	tok, _ := tm.GenerateRefreshToken("alice", []string{"user"}, time.Hour)
	_, err := tm.ValidateAccessToken(tok)
	if err == nil {
		t.Fatal("refresh token must be rejected on the API surface")
	}
	if !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("error should be generic; got %v", err)
	}
}

// --- ValidateRefreshToken ---

func TestValidateRefreshToken_AcceptsRefreshToken(t *testing.T) {
	tm := newTT(t)
	tok, _ := tm.GenerateRefreshToken("alice", []string{"user"}, time.Hour)
	claims, err := tm.ValidateRefreshToken(tok)
	if err != nil {
		t.Fatalf("refresh token should pass; got %v", err)
	}
	if claims.TokenType != TokenTypeRefresh {
		t.Fatalf("tt = %q", claims.TokenType)
	}
}

func TestValidateRefreshToken_RejectsAccessToken(t *testing.T) {
	tm := newTT(t)
	tok, _ := tm.GenerateAccessToken("alice", []string{"user"}, time.Hour)
	_, err := tm.ValidateRefreshToken(tok)
	if err == nil {
		t.Fatal("access token must be rejected at the refresh path")
	}
}

func TestValidateRefreshToken_RejectsLegacyToken(t *testing.T) {
	// Legacy tokens (no tt) are NOT refresh tokens. The
	// exchange path must refuse them — only an explicitly
	// minted refresh can be exchanged.
	tm := newTT(t)
	tok, _ := tm.GenerateToken("alice", []string{"user"}, time.Hour)
	_, err := tm.ValidateRefreshToken(tok)
	if err == nil {
		t.Fatal("legacy token must NOT be treated as a refresh token")
	}
}

// --- TTL defaults ---

func TestGenerateAccessToken_DefaultsToShortExpiry(t *testing.T) {
	tm := newTT(t)
	tok, _ := tm.GenerateAccessToken("alice", []string{"user"}, 0) // 0 → default
	claims, err := tm.ValidateToken(tok)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	lifetime := claims.ExpiresAt.Sub(claims.IssuedAt.Time)
	if lifetime != DefaultAccessTokenExpiry {
		t.Fatalf("access default lifetime = %v, want %v", lifetime, DefaultAccessTokenExpiry)
	}
}

func TestGenerateRefreshToken_DefaultsToLongExpiry(t *testing.T) {
	tm := newTT(t)
	tok, _ := tm.GenerateRefreshToken("alice", []string{"user"}, 0)
	claims, err := tm.ValidateToken(tok)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	lifetime := claims.ExpiresAt.Sub(claims.IssuedAt.Time)
	if lifetime != DefaultRefreshTokenExpiry {
		t.Fatalf("refresh default lifetime = %v, want %v", lifetime, DefaultRefreshTokenExpiry)
	}
}
