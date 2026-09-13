package auth

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/tokenid"
)

// decodeJWTPayload base64url-decodes and JSON-unmarshals the middle segment
// of a JWT, so a test can assert on the exact wire shape (key presence, not
// just the Go struct's zero value) rather than trusting round-trip decoding
// to catch an omitempty regression.
func decodeJWTPayload(t *testing.T, tok string) map[string]any {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments, want 3: %q", len(parts), tok)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return payload
}

// #1815 — GenerateDelegatedTokenWithID returns the minted jti/expiry
// alongside the signed token, so the issuer of a skill-run credential can
// revoke exactly what it issued.

// TestMintedID_IsTypeAliasForTokenid pins the "auth.MintedID is a type
// alias" AC at compile time: this only compiles if MintedID is declared as
// `type MintedID = tokenid.MintedID`, not a distinct defined type — a
// distinct type would require an explicit conversion here.
func TestMintedID_IsTypeAliasForTokenid(t *testing.T) {
	var fromTokenid tokenid.MintedID = tokenid.MintedID{JTI: "x", ExpiresAt: time.Unix(0, 0)}
	var viaAlias MintedID = fromTokenid
	var backToTokenid tokenid.MintedID = viaAlias
	if backToTokenid.JTI != "x" {
		t.Fatalf("round trip through the alias lost data: %+v", backToTokenid)
	}
}

func TestGenerateDelegatedTokenWithID_ReturnsJTIMatchingClaims(t *testing.T) {
	tm := newTestTokenManager(t)

	tok, id, err := tm.GenerateDelegatedTokenWithID("agent-hello", []string{"agent"}, time.Hour, nil, "")
	if err != nil {
		t.Fatalf("GenerateDelegatedTokenWithID: %v", err)
	}
	if id.JTI == "" {
		t.Fatal("MintedID.JTI is empty")
	}

	claims, err := tm.ValidateToken(tok)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if claims.ID != id.JTI {
		t.Errorf("claims.ID = %q, want MintedID.JTI %q", claims.ID, id.JTI)
	}
	if claims.ExpiresAt == nil {
		t.Fatal("claims.ExpiresAt is nil")
	}
	// JWT numeric dates are whole seconds (RFC 7519 §2), so compare at second
	// precision rather than requiring exact nanosecond equality.
	if claims.ExpiresAt.Time.Unix() != id.ExpiresAt.Unix() {
		t.Errorf("claims.ExpiresAt = %v, want MintedID.ExpiresAt %v", claims.ExpiresAt.Time, id.ExpiresAt)
	}
}

func TestGenerateDelegatedTokenWithID_RunIDClaim(t *testing.T) {
	cases := []struct {
		name  string
		runID string
	}{
		{"empty omits the claim from the wire", ""},
		{"simple run id round-trips", "run-1"},
		{"alphanumeric run id round-trips", "0123abcXYZ"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tm := newTestTokenManager(t)
			tok, _, err := tm.GenerateDelegatedTokenWithID("agent-hello", []string{"agent"}, time.Hour, nil, tc.runID)
			if err != nil {
				t.Fatalf("GenerateDelegatedTokenWithID: %v", err)
			}

			if tc.runID == "" {
				// omitempty: the claim must not appear on the wire at all,
				// not merely decode to "". Check the raw decoded payload.
				payload := decodeJWTPayload(t, tok)
				if _, present := payload["run_id"]; present {
					t.Fatalf("run_id present on the wire for an empty run id: %v", payload)
				}
			}

			claims, err := tm.ValidateToken(tok)
			if err != nil {
				t.Fatalf("ValidateToken: %v", err)
			}
			if claims.RunID != tc.runID {
				t.Errorf("claims.RunID = %q, want %q", claims.RunID, tc.runID)
			}
		})
	}
}

// TestGenerateToken_RunIDOmittedKeepsWireShape proves the omitempty on
// run_id: a token minted via the ordinary (non-run-bound) paths carries no
// run_id key at all, so every pre-#1815 wire-shape fixture stays byte
// identical.
func TestGenerateToken_RunIDOmittedKeepsWireShape(t *testing.T) {
	tm := newTestTokenManager(t)
	tok, err := tm.GenerateToken("alice", []string{"user"}, time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	payload := decodeJWTPayload(t, tok)
	if _, present := payload["run_id"]; present {
		t.Fatalf("run_id present on the wire for GenerateToken: %v", payload)
	}
}
