package gateway

import (
	"testing"

	"github.com/footprintai/containarium/internal/auth"
)

// TestAuthorizeTenantWSAccess covers the tenant check shared by both
// WebSocket routes this gateway serves (/terminal and /console-attach).
// Replaces the old TestAuthRequiredForTerminal placeholder
// (security_test.go), which only logged what the code was supposed to do
// rather than asserting it — the gap that let #1754 (any authenticated
// tenant could open a shell into any other tenant's container via
// /terminal) go unnoticed.
func TestAuthorizeTenantWSAccess(t *testing.T) {
	cases := []struct {
		name      string
		claims    *auth.Claims
		requested string
		wantErr   bool
	}{
		{"nil claims", nil, "alice", true},
		{"own tenant", &auth.Claims{Username: "alice"}, "alice", false},
		{"wrong tenant", &auth.Claims{Username: "mallory"}, "alice", true},
		{"admin, different username", &auth.Claims{Username: "root-op", Roles: []string{auth.RoleAdmin}}, "alice", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := authorizeTenantWSAccess(c.claims, c.requested)
			if c.wantErr && err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !c.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
