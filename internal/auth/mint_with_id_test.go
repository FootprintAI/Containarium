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
	// A function typed in terms of the alias, fed a tokenid.MintedID value
	// and returning one, with no conversion anywhere in between — only
	// compiles if MintedID and tokenid.MintedID are the identical type.
	roundTrip := func(m MintedID) tokenid.MintedID { return m }
	got := roundTrip(tokenid.MintedID{JTI: "x", ExpiresAt: time.Unix(0, 0)})
	if got.JTI != "x" {
		t.Fatalf("round trip through the alias lost data: %+v", got)
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
	// MintedID.ExpiresAt must be exactly the signed exp, not a pre-truncation
	// approximation of it.
	if !id.ExpiresAt.Equal(claims.ExpiresAt.Time) {
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

// TestGenerateDelegatedTokenWithRun_RunBindingClaims (#2268): every field
// of the RunBinding lands in its own claim and round-trips; an empty field
// stays off the wire entirely.
func TestGenerateDelegatedTokenWithRun_RunBindingClaims(t *testing.T) {
	tm := newTestTokenManager(t)
	run := RunBinding{RunID: "run-1", TrackerConn: "default", Tenant: "alice"}
	tok, _, err := tm.GenerateDelegatedTokenWithRun("agent-product-define", nil, time.Hour, &Actor{Subject: "alice"}, run, ScopeTrackerWrite)
	if err != nil {
		t.Fatalf("GenerateDelegatedTokenWithRun: %v", err)
	}
	claims, err := tm.ValidateToken(tok)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if claims.RunID != "run-1" || claims.TrackerConn != "default" || claims.RunTenant != "alice" {
		t.Fatalf("claims = run_id %q tracker_conn %q run_tenant %q, want run-1/default/alice", claims.RunID, claims.TrackerConn, claims.RunTenant)
	}
	if claims.Username != "agent-product-define" {
		t.Fatalf("subject = %q, want the box, not the tenant", claims.Username)
	}

	// An empty binding is identical on the wire to a plain delegated token.
	tok, _, err = tm.GenerateDelegatedTokenWithRun("agent-product-define", nil, time.Hour, nil, RunBinding{}, ScopeTrackerWrite)
	if err != nil {
		t.Fatalf("GenerateDelegatedTokenWithRun(empty): %v", err)
	}
	payload := decodeJWTPayload(t, tok)
	for _, k := range []string{"run_id", "tracker_conn", "run_tenant"} {
		if _, present := payload[k]; present {
			t.Errorf("%s present on the wire for an empty RunBinding: %v", k, payload)
		}
	}
}

// TestGenerateToken_RunTenantOmittedKeepsWireShape: no mint path other
// than the run one can put a run_tenant on a token — in particular not the
// delegate exchange (GenerateDelegatedToken), so the claim cannot be
// laundered from a run token onto a derived credential.
func TestGenerateToken_RunTenantOmittedKeepsWireShape(t *testing.T) {
	tm := newTestTokenManager(t)
	plain, err := tm.GenerateToken("alice", []string{"user"}, time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	delegated, err := tm.GenerateDelegatedToken("bob", nil, time.Hour, &Actor{Subject: "agent-product-define"}, ScopeTrackerWrite)
	if err != nil {
		t.Fatalf("GenerateDelegatedToken: %v", err)
	}
	for name, tok := range map[string]string{"GenerateToken": plain, "GenerateDelegatedToken": delegated} {
		if _, present := decodeJWTPayload(t, tok)["run_tenant"]; present {
			t.Errorf("run_tenant present on the wire for %s", name)
		}
	}
}
