package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Regression coverage for Phase 0.3 (finding A-CRIT-3): the JWT
// validator must reject any algorithm other than HS256.
//
// The pre-hardening code accepted any HMAC variant — a future
// library or dependency bug could have escalated that to a full
// signature-bypass (alg=none, alg=RS256-with-public-key-as-HMAC-key,
// etc.). With the pin in place those vectors are closed at the
// validator, regardless of what the underlying library tolerates.

func mintToken(t *testing.T, method jwt.SigningMethod, secret interface{}) string {
	t.Helper()
	claims := Claims{
		Username: "alice",
		Roles:    []string{"user"},
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "containarium-test",
			Audience:  jwt.ClaimStrings{DefaultAudience},
		},
	}
	tok := jwt.NewWithClaims(method, claims)
	s, err := tok.SignedString(secret)
	if err != nil {
		t.Fatalf("sign with %s: %v", method.Alg(), err)
	}
	return s
}

func TestValidateToken_AcceptsHS256(t *testing.T) {
	tm, _ := NewTokenManager("a-secret-that-is-at-least-32-bytes-long!!", "containarium-test")
	tok := mintToken(t, jwt.SigningMethodHS256, []byte("a-secret-that-is-at-least-32-bytes-long!!"))

	claims, err := tm.ValidateToken(tok)
	if err != nil {
		t.Fatalf("HS256 must be accepted: %v", err)
	}
	if claims.Username != "alice" {
		t.Fatalf("username = %q, want alice", claims.Username)
	}
}

func TestValidateToken_RejectsHS512(t *testing.T) {
	tm, _ := NewTokenManager("a-secret-that-is-at-least-32-bytes-long!!", "containarium-test")
	// Signed with the SAME secret but a different alg — the library
	// would accept it under the old "any HMAC" rule.
	tok := mintToken(t, jwt.SigningMethodHS512, []byte("a-secret-that-is-at-least-32-bytes-long!!"))

	_, err := tm.ValidateToken(tok)
	if err == nil {
		t.Fatal("HS512 token must be rejected — only HS256 is accepted")
	}
}

func TestValidateToken_RejectsHS384(t *testing.T) {
	tm, _ := NewTokenManager("a-secret-that-is-at-least-32-bytes-long!!", "containarium-test")
	tok := mintToken(t, jwt.SigningMethodHS384, []byte("a-secret-that-is-at-least-32-bytes-long!!"))

	_, err := tm.ValidateToken(tok)
	if err == nil {
		t.Fatal("HS384 token must be rejected")
	}
}

func TestValidateToken_RejectsRS256(t *testing.T) {
	tm, _ := NewTokenManager("a-secret-that-is-at-least-32-bytes-long!!", "containarium-test")

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	tok := mintToken(t, jwt.SigningMethodRS256, priv)

	if _, err := tm.ValidateToken(tok); err == nil {
		t.Fatal("RS256 token must be rejected — pinned to HS256")
	}
}

func TestValidateToken_RejectsNone(t *testing.T) {
	tm, _ := NewTokenManager("a-secret-that-is-at-least-32-bytes-long!!", "containarium-test")

	claims := Claims{
		Username: "attacker",
		Roles:    []string{"admin"},
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	s, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign with none: %v", err)
	}

	if _, err := tm.ValidateToken(s); err == nil {
		t.Fatal("alg=none token must be rejected")
	}
}

func TestValidateToken_ErrorIsGeneric(t *testing.T) {
	// Defense against reconnaissance — the error returned to clients
	// must not leak the algorithm name, expiry-vs-signature reason,
	// or library-level parse detail.
	tm, _ := NewTokenManager("a-secret-that-is-at-least-32-bytes-long!!", "containarium-test")
	tok := mintToken(t, jwt.SigningMethodHS512, []byte("a-secret-that-is-at-least-32-bytes-long!!"))

	_, err := tm.ValidateToken(tok)
	if err == nil {
		t.Fatal("expected an error for HS512")
	}
	msg := err.Error()
	for _, leak := range []string{"HS512", "HS384", "alg", "signing method", "RSA", "none"} {
		if strings.Contains(msg, leak) {
			t.Fatalf("error message must not leak %q; got %q", leak, msg)
		}
	}
}
