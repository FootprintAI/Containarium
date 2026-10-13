package sentinel

import (
	"testing"

	"github.com/footprintai/containarium/internal/gateway"
	"github.com/footprintai/containarium/internal/sentinel/sshauthz"
)

var _ sshauthz.BackendResolver = (*KeyStore)(nil)

func TestBackendForLogin(t *testing.T) {
	for _, tc := range []struct {
		name, login, want string
		known             bool
	}{
		{"known", "alice", "a", true},
		{"duplicate follows Apply precedence", "shared", "a", true},
		{"other backend", "bob", "b", true},
		{"unknown", "missing", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ks := NewKeyStore()
			ks.backends["b"] = &backendKeys{users: []gateway.UserKeys{{Username: "bob"}, {Username: "shared"}}}
			ks.backends["a"] = &backendKeys{users: []gateway.UserKeys{{Username: "alice"}, {Username: "shared"}}}
			got, known := ks.BackendForLogin(tc.login)
			if got != tc.want || known != tc.known {
				t.Fatalf("got (%q,%v), want (%q,%v)", got, known, tc.want, tc.known)
			}
		})
	}
}

func TestBackendForLoginRemoval(t *testing.T) {
	ks := NewKeyStore()
	ks.backends["a"] = &backendKeys{users: []gateway.UserKeys{{Username: "alice"}}}
	ks.RemoveBackend("a")
	if id, known := ks.BackendForLogin("alice"); known || id != "" {
		t.Fatal("removed route resolved")
	}
}
