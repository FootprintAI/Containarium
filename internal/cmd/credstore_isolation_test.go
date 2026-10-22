package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/credentials"
)

// #2922: no test in this package may resolve the developer's real
// credential store. TestMain points HOME at a throwaway directory for the
// whole run, so even a test that forgets withTempHome cannot read it.
func TestCredentialStoreIsIsolated(t *testing.T) {
	path, err := credentials.DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(path, filepath.Clean(os.TempDir())+string(filepath.Separator)) {
		t.Fatalf("credential store %q is outside the temp dir: tests would read real credentials", path)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatalf("credential store %q already exists before any test seeded it", path)
	}
}

// A failing assertion must not print the stored token, even a seeded one.
func TestTokenFingerprint_NeverContainsToken(t *testing.T) {
	const secret = "ctnr_synthetic.secret-value"
	fp := tokenFingerprint(secret)
	if strings.Contains(fp, secret) || strings.Contains(fp, "secret-value") {
		t.Fatalf("fingerprint %q leaks the token", fp)
	}
	if tokenFingerprint(secret) != fp {
		t.Fatal("fingerprint is not deterministic")
	}
	if tokenFingerprint("other") == fp {
		t.Fatal("different tokens share a fingerprint")
	}
	if got := tokenFingerprint(""); got != "<empty>" {
		t.Fatalf("empty token fingerprint = %q, want <empty>", got)
	}
}

// withTempHome must also clear flag globals up front: a token left behind by
// an earlier test (or resolved from a real store) must not survive into it.
func TestWithTempHome_ResetsGlobalsAtStart(t *testing.T) {
	authToken = "leaked-from-earlier-test"
	serverAddr = "https://leaked.example.com"
	withTempHome(t)
	if authToken != "" || serverAddr != "" {
		t.Fatalf("globals survived withTempHome: authToken set=%t serverAddr=%q", authToken != "", serverAddr)
	}
}

// isolateCredentialStore points every home-derived path at a throwaway
// directory for the whole test binary and clears the CONTAINARIUM_* env, so
// no test can resolve the developer's real credential store, server or token
// whether or not it remembers to call withTempHome (#2922). The returned
// func removes the directory.
func isolateCredentialStore() func() {
	home, err := os.MkdirTemp("", "cmd-test-home-")
	if err != nil {
		panic(err)
	}
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); strings.HasPrefix(k, "CONTAINARIUM_") {
			os.Unsetenv(k)
		}
	}
	os.Setenv("HOME", home)
	os.Setenv("USERPROFILE", home)
	os.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	// The root command's flag defaults were read from the environment in
	// init(), before this ran.
	authToken, serverAddr = "", ""
	return func() { os.RemoveAll(home) }
}

// tokenFingerprint is what a failing assertion prints in place of a token:
// a short hash, enough to tell two tokens apart, never the secret itself.
func tokenFingerprint(tok string) string {
	if tok == "" {
		return "<empty>"
	}
	sum := sha256.Sum256([]byte(tok))
	return "sha256:" + hex.EncodeToString(sum[:4])
}
