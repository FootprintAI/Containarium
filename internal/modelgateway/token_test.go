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
	// MintedID.ExpiresAt must be exactly the signed exp, not a pre-truncation
	// approximation of it.
	if !id.ExpiresAt.Equal(claims.ExpiresAt.Time) {
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

	// Two independent mints for the same claims get distinct jtis: each mint
	// draws fresh randomness, so MintToken's wrapped call and this direct
	// MintTokenWithID call must not collide.
	claimsFromWithID, err := VerifyToken(secret, tokID)
	if err != nil {
		t.Fatalf("VerifyToken(MintTokenWithID result): %v", err)
	}
	if claimsFromWithID.ID != id.JTI {
		t.Errorf("claimsFromWithID.ID = %q, want MintedID.JTI %q", claimsFromWithID.ID, id.JTI)
	}
	if claims.ID == id.JTI {
		t.Errorf("MintToken and MintTokenWithID minted the same jti %q for two separate calls", claims.ID)
	}
}
