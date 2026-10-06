package anonbox

import (
	"errors"
	"strings"
	"testing"
	"time"
)

var tokenNow = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func sampleToken() ClaimToken {
	return ClaimToken{BoxName: "anon-1a2b3c4d-container", FPHash: "ff00ff00", ExpiresAt: tokenNow.Add(4 * time.Hour), TokenID: "0123456789abcdef0123456789abcdef"}
}

func TestClaimToken_RoundTrip(t *testing.T) {
	s, err := MintClaimToken("secret-A", sampleToken())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(s, "v1.anon-1a2b3c4d-container.ff00ff00.") || strings.Count(s, ".") != 5 {
		t.Errorf("token shape = %s", s)
	}
	got, err := VerifyClaimToken("secret-A", s, tokenNow)
	if err != nil {
		t.Fatal(err)
	}
	if got != sampleToken() {
		t.Errorf("round-trip = %+v, want %+v", got, sampleToken())
	}
	// Parse alone yields the same fields and never checks the signature.
	p, err := ParseClaimToken(s)
	if err != nil || p != sampleToken() {
		t.Errorf("parse = %+v (%v)", p, err)
	}
}

func TestClaimToken_Tamper(t *testing.T) {
	good, _ := MintClaimToken("secret-A", sampleToken())
	parts := strings.Split(good, ".")
	swap := func(i int, v string) string {
		c := append([]string{}, parts...)
		c[i] = v
		return strings.Join(c, ".")
	}
	tests := []struct {
		name   string
		token  string
		secret string
		want   error
	}{
		{"wrong secret", good, "secret-B", ErrTokenSignature},
		{"empty secret", good, "", ErrTokenSignature},
		{"other box", swap(1, "anon-ffffffff-container"), "secret-A", ErrTokenSignature},
		{"other fp", swap(2, "00ff00ff"), "secret-A", ErrTokenSignature},
		{"later expiry", swap(3, "9999999999"), "secret-A", ErrTokenSignature},
		{"other token id", swap(4, "deadbeef"), "secret-A", ErrTokenSignature},
		{"flipped mac", swap(5, strings.Repeat("0", 64)), "secret-A", ErrTokenSignature},
		{"wrong version", swap(0, "v2"), "secret-A", ErrTokenMalformed},
		{"too few fields", strings.Join(parts[:5], "."), "secret-A", ErrTokenMalformed},
		{"garbage", "hello", "secret-A", ErrTokenMalformed},
		{"non-numeric exp", swap(3, "soon"), "secret-A", ErrTokenMalformed},
		{"empty", "", "secret-A", ErrTokenMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := VerifyClaimToken(tt.secret, tt.token, tokenNow)
			if !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestClaimToken_Expiry(t *testing.T) {
	s, _ := MintClaimToken("secret-A", sampleToken())
	if _, err := VerifyClaimToken("secret-A", s, tokenNow.Add(4*time.Hour)); !errors.Is(err, ErrTokenExpired) {
		t.Errorf("at expiry: err = %v, want expired", err)
	}
	if _, err := VerifyClaimToken("secret-A", s, tokenNow.Add(4*time.Hour-time.Second)); err != nil {
		t.Errorf("just before expiry: %v", err)
	}
	// A tampered token that is also expired reports the signature, not the
	// expiry, so a forger learns nothing.
	bad := strings.TrimSuffix(s, "0") + "1"
	if _, err := VerifyClaimToken("secret-A", bad, tokenNow.Add(5*time.Hour)); !errors.Is(err, ErrTokenSignature) {
		t.Errorf("tampered+expired: err = %v, want signature", err)
	}
}

func TestClaimToken_MintRefusals(t *testing.T) {
	if _, err := MintClaimToken("", sampleToken()); err == nil {
		t.Error("empty secret must be refused")
	}
	tk := sampleToken()
	tk.BoxName = "has.dot"
	if _, err := MintClaimToken("s", tk); err == nil {
		t.Error("a '.' in a field must be refused")
	}
	if _, err := MintClaimToken("s", ClaimToken{}); err == nil {
		t.Error("empty fields must be refused")
	}
}

func TestClaimToken_SecretIsPerBox(t *testing.T) {
	// Two boxes, two secrets: a token for one never verifies under the
	// other's secret even with identical other fields.
	a := sampleToken()
	b := sampleToken()
	b.BoxName = "anon-ffffffff-container"
	sa, _ := MintClaimToken("secret-for-a", a)
	if _, err := VerifyClaimToken("secret-for-b", sa, tokenNow); !errors.Is(err, ErrTokenSignature) {
		t.Errorf("cross-box verify: %v", err)
	}
}
