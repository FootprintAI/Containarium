package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveAnonClaimKeys(t *testing.T) {
	f := filepath.Join(t.TempDir(), "keys")
	if err := os.WriteFile(f, []byte("# comment\nssh-ed25519 AAAA1 a\n\n  ssh-ed25519 AAAA2 b  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := resolveAnonClaimKeys([]string{" ssh-rsa AAAA0 z ", "", "@" + f})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ssh-rsa AAAA0 z", "ssh-ed25519 AAAA1 a", "ssh-ed25519 AAAA2 b"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if _, err := resolveAnonClaimKeys([]string{"@" + filepath.Join(t.TempDir(), "missing")}); err == nil {
		t.Error("missing key file must error")
	}
}
