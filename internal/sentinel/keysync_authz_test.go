package sentinel

import (
	"fmt"
	"path/filepath"
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

func TestKeyStorePublishesAuthzDaemonPorts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authz-routes.json")
	ks := NewKeyStore()
	ks.authzRoutesFile = path
	for _, port := range []int{8080, 9090} {
		if err := ks.publishAuthzRoutes([]userRoute{
			{username: "alice", backendID: "a", backendIP: "127.0.0.1", httpPort: port, sshPort: 2222},
			{username: "bob", backendID: "b", backendIP: "::1", httpPort: 8081, sshPort: 22},
		}); err != nil {
			t.Fatal(err)
		}
		r := sshauthz.FileBackendResolver{Path: path}
		if id, ok := r.BackendForLogin("alice"); !ok || id != "a" {
			t.Fatal("wrong route identity")
		}
		if u, err := r.BackendURL("a"); err != nil || u != fmt.Sprintf("http://127.0.0.1:%d", port) {
			t.Fatalf("daemon port confused with SSH port: %q %v", u, err)
		}
		if u, err := r.BackendURL("b"); err != nil || u != "http://[::1]:8081" {
			t.Fatalf("IPv6 URL: %q %v", u, err)
		}
	}
	if err := ks.publishAuthzRoutes(nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := (sshauthz.FileBackendResolver{Path: path}).BackendForLogin("alice"); ok {
		t.Fatal("removed route retained")
	}
}
