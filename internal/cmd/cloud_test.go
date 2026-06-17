package cmd

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/auth"
)

func TestMintDriverToken(t *testing.T) {
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "jwt.secret")
	// A secret of adequate length (the token manager rejects short secrets).
	secret := "this-is-a-sufficiently-long-jwt-signing-secret-0123456789"
	if err := os.WriteFile(secretPath, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("mints a token the host's own daemon would accept", func(t *testing.T) {
		tok, err := mintDriverToken(secretPath, 24*time.Hour)
		if err != nil {
			t.Fatalf("mintDriverToken: %v", err)
		}
		// The token validates against the SAME secret (what the host daemon uses).
		tm, err := auth.NewTokenManager(secret, "containarium")
		if err != nil {
			t.Fatal(err)
		}
		claims, err := tm.ValidateToken(tok)
		if err != nil {
			t.Fatalf("token should validate against the host secret: %v", err)
		}
		hasAdmin := false
		for _, r := range claims.Roles {
			if r == "admin" {
				hasAdmin = true
			}
		}
		if !hasAdmin {
			t.Errorf("driver token should carry the admin role, got %v", claims.Roles)
		}
	})

	t.Run("missing secret file errors", func(t *testing.T) {
		if _, err := mintDriverToken(filepath.Join(dir, "nope"), time.Hour); err == nil {
			t.Fatal("want error for missing secret file")
		}
	})

	t.Run("empty path errors", func(t *testing.T) {
		if _, err := mintDriverToken("  ", time.Hour); err == nil {
			t.Fatal("want error for empty path")
		}
	})

	t.Run("empty secret errors", func(t *testing.T) {
		empty := filepath.Join(dir, "empty.secret")
		if err := os.WriteFile(empty, []byte("  \n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := mintDriverToken(empty, time.Hour); err == nil {
			t.Fatal("want error for empty secret")
		}
	})
}
