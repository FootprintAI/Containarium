package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Phase 1.3 — minimum JWT secret length (audit A-MED-2).

func TestNewTokenManager_RejectsShortSecret(t *testing.T) {
	if _, err := NewTokenManager("too-short", "test-issuer"); err == nil {
		t.Fatal("9-byte secret must be rejected")
	}
	if _, err := NewTokenManager("", "test-issuer"); err == nil {
		t.Fatal("empty secret must be rejected")
	}
	// 31 bytes — one below the boundary.
	if _, err := NewTokenManager(string(make([]byte, MinSecretKeyLen-1)), "test-issuer"); err == nil {
		t.Fatal("31-byte secret must be rejected")
	}
}

func TestNewTokenManager_AcceptsMinLengthSecret(t *testing.T) {
	// Exactly MinSecretKeyLen bytes — should succeed.
	tm, err := NewTokenManager(string(make([]byte, MinSecretKeyLen)), "test-issuer")
	if err != nil {
		t.Fatalf("MinSecretKeyLen-byte secret must be accepted: %v", err)
	}
	if tm == nil {
		t.Fatal("nil manager with nil error")
	}
}

// Phase 1.1 — JWT iss + aud validation (audit A-HIGH-1).

func TestValidateToken_RejectsWrongIssuer(t *testing.T) {
	// Both managers share the same secret + audience, but issue
	// under different `iss` values. A token from `tm1` must not
	// validate under `tm2`'s validator.
	const secret = "a-secret-that-is-at-least-32-bytes-long!!"
	tm1, err := NewTokenManager(secret, "containarium-prod")
	if err != nil {
		t.Fatalf("tm1: %v", err)
	}
	tm2, err := NewTokenManager(secret, "containarium-staging")
	if err != nil {
		t.Fatalf("tm2: %v", err)
	}

	tok, err := tm1.GenerateToken("alice", []string{"user"}, time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if _, err := tm2.ValidateToken(tok); err == nil {
		t.Fatal("token signed by tm1 (containarium-prod) must not validate under tm2 (containarium-staging)")
	}
}

func TestValidateToken_RejectsWrongAudience(t *testing.T) {
	// Both managers share the same secret + issuer; only audience
	// differs. Without aud enforcement, a token minted for an
	// unrelated audience could be replayed against the daemon.
	const secret = "a-secret-that-is-at-least-32-bytes-long!!"
	t.Setenv("CONTAINARIUM_JWT_AUDIENCE", "containarium-api")
	tm, err := NewTokenManager(secret, "containarium-test")
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}

	// Mint a token by hand carrying a foreign audience but the
	// expected issuer + secret — the only thing wrong is `aud`.
	claims := Claims{
		Username: "alice",
		Roles:    []string{"user"},
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "containarium-test",
			Audience:  jwt.ClaimStrings{"some-other-service"},
		},
	}
	tokObj := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokStr, err := tokObj.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if _, err := tm.ValidateToken(tokStr); err == nil {
		t.Fatal("token with foreign audience must not validate")
	}
}

func TestGenerateToken_StampsIssAndAud(t *testing.T) {
	const secret = "a-secret-that-is-at-least-32-bytes-long!!"
	tm, err := NewTokenManager(secret, "containarium-test")
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}

	tok, err := tm.GenerateToken("alice", []string{"user"}, time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	claims, err := tm.ValidateToken(tok)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if claims.Issuer != "containarium-test" {
		t.Fatalf("Issuer = %q, want containarium-test", claims.Issuer)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != DefaultAudience {
		t.Fatalf("Audience = %v, want [%s]", claims.Audience, DefaultAudience)
	}
}

func TestValidateToken_AudienceOverrideFromEnv(t *testing.T) {
	const secret = "a-secret-that-is-at-least-32-bytes-long!!"
	t.Setenv("CONTAINARIUM_JWT_AUDIENCE", "containarium-edge")

	tm, err := NewTokenManager(secret, "containarium-test")
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	tok, err := tm.GenerateToken("alice", []string{"user"}, time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	claims, err := tm.ValidateToken(tok)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if claims.Audience[0] != "containarium-edge" {
		t.Fatalf("Audience override not applied: got %v", claims.Audience)
	}
}
