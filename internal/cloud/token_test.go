package cloud

import (
	"github.com/footprintai/containarium/internal/auth"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestDriverTokenSupportsProtectedCloudAttribution(t *testing.T) {
	secret := "isolated-driver-token-test-signing-key"
	file := filepath.Join(t.TempDir(), "signing-secret")
	if err := os.WriteFile(file, []byte(secret), 0600); err != nil {
		t.Fatal(err)
	}
	token, err := MintDriverToken(file, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := auth.NewTokenManager(secret, "containarium")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := manager.ValidateToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(claims.Roles, auth.RoleAdmin) || !slices.Contains(claims.Scopes, auth.ScopeWildcard) {
		t.Fatal("cloud driver token cannot reach admin-gated attribution")
	}
}
