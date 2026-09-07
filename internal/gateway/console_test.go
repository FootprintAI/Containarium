package gateway

import (
	"testing"

	"github.com/footprintai/containarium/internal/auth"
)

func TestParseConsoleUsername(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"/v1/containers/alice/console-attach", "alice"},
		{"v1/containers/alice/console-attach", "alice"},
		{"/v1/containers/alice/console-attach/", "alice"},
		{"/v1/containers/alice/terminal", ""},
		{"/v1/containers/alice/console-attach/extra", ""},
		{"/v1/containers//console-attach", ""},
		{"/v1/containers", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := parseConsoleUsername(c.path); got != c.want {
			t.Errorf("parseConsoleUsername(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}

func TestAuthorizeConsoleAccess(t *testing.T) {
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
			err := authorizeConsoleAccess(c.claims, c.requested)
			if c.wantErr && err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !c.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
