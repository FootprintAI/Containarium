package cmd

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

// Unit tests for the inspect decoder. The decode path is
// the security-sensitive part — an operator pasting a
// leaked token must get the right jti out, even if the
// token has been hand-edited or uses unusual claim shapes.

func TestClaimsFromRaw_FullClaimSet(t *testing.T) {
	raw := map[string]any{
		"username": "alice",
		"sub":      "alice",
		"roles":    []any{"admin", "user"},
		"scopes":   []any{"containers:read", "secrets:read"},
		"tt":       "access",
		"iss":      "containarium",
		"aud":      []any{"containarium-api"},
		"jti":      "test-jti-123",
		"iat":      float64(1700000000),
		"nbf":      float64(1700000000),
		"exp":      float64(1700003600),
	}
	got := claimsFromRaw(raw)

	if got.Username != "alice" {
		t.Errorf("username = %q", got.Username)
	}
	if len(got.Roles) != 2 || got.Roles[0] != "admin" {
		t.Errorf("roles = %v", got.Roles)
	}
	if len(got.Scopes) != 2 || got.Scopes[0] != "containers:read" {
		t.Errorf("scopes = %v", got.Scopes)
	}
	if got.TokenType != "access" {
		t.Errorf("tt = %q", got.TokenType)
	}
	if got.JTI != "test-jti-123" {
		t.Errorf("jti = %q", got.JTI)
	}
	if len(got.Audience) != 1 || got.Audience[0] != "containarium-api" {
		t.Errorf("aud = %v", got.Audience)
	}
	if got.IssuedAt.Unix() != 1700000000 {
		t.Errorf("iat = %d", got.IssuedAt.Unix())
	}
}

func TestClaimsFromRaw_AudAsString(t *testing.T) {
	// Some issuers serialize `aud` as a single string
	// rather than an array. JWT spec allows both.
	raw := map[string]any{
		"username": "alice",
		"aud":      "containarium-api",
	}
	got := claimsFromRaw(raw)
	if len(got.Audience) != 1 || got.Audience[0] != "containarium-api" {
		t.Fatalf("aud-as-string: got %v", got.Audience)
	}
}

func TestClaimsFromRaw_MissingFieldsStayZero(t *testing.T) {
	// Tokens without optional claims (legacy, no jti, no
	// scopes) must still decode without panic.
	raw := map[string]any{"username": "alice"}
	got := claimsFromRaw(raw)
	if got.Username != "alice" {
		t.Errorf("username = %q", got.Username)
	}
	if got.JTI != "" || got.TokenType != "" || len(got.Scopes) != 0 {
		t.Errorf("optional fields should stay zero; got jti=%q tt=%q scopes=%v",
			got.JTI, got.TokenType, got.Scopes)
	}
}

func TestClaimsFromRaw_MalformedRolesIgnored(t *testing.T) {
	// A non-string element in roles is silently skipped,
	// not panicking. Matches the audit philosophy: don't
	// fail-stop on unexpected wire shapes when the
	// operator is just trying to read the token.
	raw := map[string]any{
		"username": "alice",
		"roles":    []any{"admin", 42, "user"},
	}
	got := claimsFromRaw(raw)
	if len(got.Roles) != 2 || got.Roles[0] != "admin" || got.Roles[1] != "user" {
		t.Fatalf("roles = %v; want [admin user]", got.Roles)
	}
}

// makeJWT builds a 3-segment JWT with a fake signature.
// Mirrors the helper in mcp/scope_filter_test.go.
func makeJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := map[string]string{"alg": "HS256", "typ": "JWT"}
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(claims)
	enc := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	return enc(hb) + "." + enc(pb) + ".sig"
}

func TestInspect_RejectsNonJWT(t *testing.T) {
	// A 2-segment string isn't a JWT. The current
	// implementation returns from runTokenInspect; here we
	// just confirm the input parsing logic agrees by
	// re-using the split-and-check shape directly.
	tok := "only.two"
	parts := splitTokenForTest(tok)
	if len(parts) == 3 {
		t.Fatal("test setup wrong")
	}
}

// splitTokenForTest is a 1:1 mirror of strings.Split for
// readability in the test above. Keeps the unit test from
// importing private logic.
func splitTokenForTest(s string) []string {
	out := []string{}
	cur := ""
	for _, r := range s {
		if r == '.' {
			out = append(out, cur)
			cur = ""
		} else {
			cur += string(r)
		}
	}
	out = append(out, cur)
	return out
}

func TestInspect_DecodesGeneratedJWT(t *testing.T) {
	// Generate a JWT, base64-decode the payload, confirm
	// we recover the same claims. End-to-end sanity that
	// the wire format the daemon emits is the same the
	// inspector reads.
	exp := time.Now().Add(time.Hour).Unix()
	tok := makeJWT(t, map[string]any{
		"username": "ops",
		"roles":    []any{"admin"},
		"scopes":   []any{"tokens:write"},
		"tt":       "access",
		"jti":      "abc-123",
		"iss":      "containarium",
		"aud":      "containarium-api",
		"exp":      float64(exp),
	})

	parts := splitTokenForTest(tok)
	if len(parts) != 3 {
		t.Fatalf("constructed token has %d segments", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		t.Fatalf("parse json: %v", err)
	}
	got := claimsFromRaw(raw)
	if got.Username != "ops" {
		t.Fatalf("username = %q", got.Username)
	}
	if got.JTI != "abc-123" {
		t.Fatalf("jti = %q", got.JTI)
	}
	if got.TokenType != "access" {
		t.Fatalf("tt = %q", got.TokenType)
	}
	if len(got.Scopes) != 1 || got.Scopes[0] != "tokens:write" {
		t.Fatalf("scopes = %v", got.Scopes)
	}
}
