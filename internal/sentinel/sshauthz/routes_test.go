package sshauthz_test

import (
	"os"
	"path/filepath"
	"testing"

	authz "github.com/footprintai/containarium/internal/sentinel/sshauthz"
)

func TestFileBackendResolverReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.json")
	r := authz.FileBackendResolver{Path: path}
	if _, ok := r.BackendForLogin("alice"); ok {
		t.Fatal("missing snapshot resolved")
	}
	for _, id := range []string{"a", "b"} {
		if err := authz.WriteRoutes(path, authz.Routes{Logins: map[string]string{"alice": id}, BackendURLs: map[string]string{id: "http://127.0.0.1:8080"}}); err != nil {
			t.Fatal(err)
		}
		if got, ok := r.BackendForLogin("alice"); !ok || got != id {
			t.Fatalf("stale route %q", got)
		}
		if u, err := r.BackendURL(id); err != nil || u != "http://127.0.0.1:8080" {
			t.Fatalf("%q %v", u, err)
		}
	}
	if _, ok := r.BackendForLogin("unknown"); ok {
		t.Fatal("unknown resolved")
	}
	if _, err := r.BackendURL("missing"); err == nil {
		t.Fatal("missing URL not reported")
	}
	if err := os.WriteFile(path, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.BackendForLogin("alice"); ok {
		t.Fatal("parse failure retained stale routing")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.BackendForLogin("alice"); ok {
		t.Fatal("deleted route retained")
	}
}
