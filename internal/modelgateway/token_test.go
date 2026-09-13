package modelgateway

import (
	"testing"
	"time"
)

// #1815 — MintTokenWithID returns the minted jti/expiry alongside the
// signed token, mirroring internal/auth.GenerateDelegatedTokenWithID, so the
// daemon can revoke exactly the gateway token it issued for a run.

func TestMintTokenWithID_RoundTrips(t *testing.T) {
	secret := []byte("shared-secret")
	c := GatewayClaims{Tenant: "acme", Provider: "anthropic", RunID: "run-1"}

	tok, id, err := MintTokenWithID(secret, c, time.Hour)
	if err != nil {
		t.Fatalf("MintTokenWithID: %v", err)
	}
	if id.JTI == "" {
		t.Fatal("MintedID.JTI is empty")
	}

	claims, err := VerifyToken(secret, tok)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
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
	if claims.RunID != "run-1" {
		t.Errorf("claims.RunID = %q, want run-1", claims.RunID)
	}
	if claims.Tenant != "acme" || claims.Provider != "anthropic" {
		t.Errorf("claims mismatch: %+v", claims)
	}
}

func TestMintTokenWithID_ValidationErrorsPropagate(t *testing.T) {
	secret := []byte("shared-secret")

	if _, _, err := MintTokenWithID(secret, GatewayClaims{Provider: "anthropic"}, time.Hour); err == nil {
		t.Error("expected error for missing tenant")
	}
	if _, _, err := MintTokenWithID(secret, GatewayClaims{Tenant: "acme"}, time.Hour); err == nil {
		t.Error("expected error for missing provider")
	}
}

// TestMintToken_StillWraps proves MintToken is now a thin wrapper over
// MintTokenWithID: same claims land on the wire, same validation errors, and
// (unlike MintTokenWithID) it still returns only the signed string.
func TestMintToken_StillWraps(t *testing.T) {
	secret := []byte("shared-secret")
	c := GatewayClaims{Tenant: "acme", Provider: "anthropic", SkillID: "hello-agent", RunID: "run-2"}

	tok, err := MintToken(secret, c, time.Hour)
	if err != nil {
		t.Fatalf("MintToken: %v", err)
	}
	tokID, id, err := MintTokenWithID(secret, c, time.Hour)
	if err != nil {
		t.Fatalf("MintTokenWithID: %v", err)
	}
	_ = tokID // separately minted token; jtis differ by design (fresh random each mint)

	claims, err := VerifyToken(secret, tok)
	if err != nil {
		t.Fatalf("VerifyToken(MintToken result): %v", err)
	}
	if claims.ID == "" {
		t.Fatal("MintToken's token carries no jti")
	}
	if claims.Tenant != "acme" || claims.Provider != "anthropic" || claims.SkillID != "hello-agent" || claims.RunID != "run-2" {
		t.Errorf("claims mismatch: %+v", claims)
	}

	// Same validation behavior as MintTokenWithID.
	if _, err := MintToken(secret, GatewayClaims{Provider: "anthropic"}, time.Hour); err == nil {
		t.Error("expected error for missing tenant")
	}
	if _, _, err := MintTokenWithID(secret, GatewayClaims{Provider: "anthropic"}, time.Hour); err == nil {
		t.Error("expected error for missing tenant (MintTokenWithID)")
	}
	_ = id
}
