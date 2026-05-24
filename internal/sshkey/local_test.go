package sshkey

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// withTempHome returns a tempdir that callers should pass as
// LocateOpts.HomeDir. We do not Setenv HOME here because the only
// production caller paths through the LocateOpts.HomeDir override —
// keeping the test hermetic.
func withTempHome(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

// seedPubKey drops a placeholder public key file at ~/.ssh/<name>
// under home. The contents are a freshly-generated ed25519 key, so
// ssh.ParseAuthorizedKey accepts them; we reuse Generate to keep the
// helper short.
func seedPubKey(t *testing.T, home, name string) string {
	t.Helper()
	// Use Generate against a fresh tempdir to get a syntactically-valid
	// key, then copy the .pub into the target home.
	stage := t.TempDir()
	_, pub, err := Generate(LocateOpts{HomeDir: stage}, false)
	if err != nil {
		t.Fatalf("seed: Generate: %v", err)
	}
	dir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("seed: mkdir: %v", err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(pub+"\n"), 0o644); err != nil {
		t.Fatalf("seed: write: %v", err)
	}
	return p
}

func TestGenerate_WritesBothKeysWithCorrectModes(t *testing.T) {
	home := withTempHome(t)
	pubPath, pub, err := Generate(LocateOpts{HomeDir: home}, false)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if !strings.HasSuffix(pubPath, "/containarium_ed25519.pub") {
		t.Errorf("pubPath = %q, want suffix containarium_ed25519.pub", pubPath)
	}
	if !strings.HasPrefix(pub, "ssh-ed25519 ") {
		t.Errorf("pub = %q, want ssh-ed25519 prefix", pub)
	}

	priv := strings.TrimSuffix(pubPath, ".pub")
	if _, err := os.Stat(priv); err != nil {
		t.Fatalf("private key not written: %v", err)
	}

	// POSIX perm checks only — Windows has no notion of 0600.
	if runtime.GOOS == "windows" {
		return
	}
	if st, _ := os.Stat(priv); st.Mode().Perm() != 0o600 {
		t.Errorf("private mode = %o, want 0600", st.Mode().Perm())
	}
	if st, _ := os.Stat(pubPath); st.Mode().Perm() != 0o644 {
		t.Errorf("public mode = %o, want 0644", st.Mode().Perm())
	}
}

func TestGenerate_RefusesClobberWithoutForce(t *testing.T) {
	home := withTempHome(t)
	if _, _, err := Generate(LocateOpts{HomeDir: home}, false); err != nil {
		t.Fatalf("Generate first: %v", err)
	}
	_, _, err := Generate(LocateOpts{HomeDir: home}, false)
	if err == nil {
		t.Fatal("expected error on second Generate without force")
	}
	if !errors.Is(err, os.ErrExist) {
		t.Errorf("err = %v, want ErrExist", err)
	}
}

func TestGenerate_ForceOverwrites(t *testing.T) {
	home := withTempHome(t)
	_, pub1, err := Generate(LocateOpts{HomeDir: home}, false)
	if err != nil {
		t.Fatalf("Generate 1: %v", err)
	}
	_, pub2, err := Generate(LocateOpts{HomeDir: home}, true)
	if err != nil {
		t.Fatalf("Generate 2 (force): %v", err)
	}
	if pub1 == pub2 {
		t.Fatal("force regenerate produced identical key — should be a fresh keypair")
	}
}

func TestLocate_PicksEd25519First(t *testing.T) {
	home := withTempHome(t)
	rsaPath := seedPubKey(t, home, FallbackPublicKeyPath)
	edPath := seedPubKey(t, home, DefaultPublicKeyPath)

	pubPath, pub, err := Locate(LocateOpts{HomeDir: home})
	if err != nil {
		t.Fatalf("Locate: %v", err)
	}
	if pubPath != edPath {
		t.Errorf("Locate picked %q, want ed25519 path %q", pubPath, edPath)
	}
	if pub == "" {
		t.Error("Locate returned empty key contents")
	}
	_ = rsaPath
}

func TestLocate_FallsBackToRSA(t *testing.T) {
	home := withTempHome(t)
	rsaPath := seedPubKey(t, home, FallbackPublicKeyPath)

	pubPath, _, err := Locate(LocateOpts{HomeDir: home})
	if err != nil {
		t.Fatalf("Locate: %v", err)
	}
	if pubPath != rsaPath {
		t.Errorf("Locate picked %q, want %q", pubPath, rsaPath)
	}
}

func TestLocate_NoKeys_ReturnsErrNotExist(t *testing.T) {
	home := withTempHome(t)
	_, _, err := Locate(LocateOpts{HomeDir: home})
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v, want ErrNotExist", err)
	}
}

func TestLocateOrGenerate_GeneratesOnEmpty(t *testing.T) {
	home := withTempHome(t)
	pubPath, pub, generated, err := LocateOrGenerate(LocateOpts{HomeDir: home})
	if err != nil {
		t.Fatalf("LocateOrGenerate: %v", err)
	}
	if !generated {
		t.Error("expected generated=true on empty home")
	}
	if !strings.HasSuffix(pubPath, "/containarium_ed25519.pub") {
		t.Errorf("pubPath = %q", pubPath)
	}
	if !strings.HasPrefix(pub, "ssh-ed25519 ") {
		t.Errorf("pub = %q", pub)
	}
}

func TestLocateOrGenerate_FindsExisting(t *testing.T) {
	home := withTempHome(t)
	seedPubKey(t, home, DefaultPublicKeyPath)

	_, _, generated, err := LocateOrGenerate(LocateOpts{HomeDir: home})
	if err != nil {
		t.Fatalf("LocateOrGenerate: %v", err)
	}
	if generated {
		t.Error("expected generated=false when ed25519 exists")
	}
}

func TestFingerprint_MatchesSSHKeygenForm(t *testing.T) {
	home := withTempHome(t)
	_, pub, err := Generate(LocateOpts{HomeDir: home}, false)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	fp, err := Fingerprint(pub)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	if !strings.HasPrefix(fp, "SHA256:") {
		t.Errorf("fingerprint = %q, want SHA256: prefix", fp)
	}
	if strings.HasSuffix(fp, "=") {
		t.Errorf("fingerprint %q still has base64 padding", fp)
	}
	// Deterministic: same input → same output.
	fp2, err := Fingerprint(pub)
	if err != nil {
		t.Fatalf("Fingerprint 2: %v", err)
	}
	if fp != fp2 {
		t.Errorf("Fingerprint not deterministic: %q vs %q", fp, fp2)
	}
}

func TestFingerprint_RejectsGarbage(t *testing.T) {
	if _, err := Fingerprint("not a key"); err == nil {
		t.Fatal("expected error on garbage input")
	}
}

func TestReadPublicKey_ReadsAndValidates(t *testing.T) {
	home := withTempHome(t)
	path := seedPubKey(t, home, DefaultPublicKeyPath)

	got, err := ReadPublicKey(path)
	if err != nil {
		t.Fatalf("ReadPublicKey: %v", err)
	}
	if !strings.HasPrefix(got, "ssh-ed25519 ") {
		t.Errorf("got = %q", got)
	}
}

func TestReadPublicKey_RejectsMalformed(t *testing.T) {
	home := withTempHome(t)
	dir := filepath.Join(home, ".ssh")
	_ = os.MkdirAll(dir, 0o700)
	bad := filepath.Join(dir, "bad.pub")
	if err := os.WriteFile(bad, []byte("garbage data"), 0o644); err != nil {
		t.Fatalf("write bad: %v", err)
	}
	if _, err := ReadPublicKey(bad); err == nil {
		t.Fatal("expected error on malformed key")
	}
}

func TestReadPublicKey_EmptyPathErrors(t *testing.T) {
	if _, err := ReadPublicKey(""); err == nil {
		t.Fatal("expected error on empty path")
	}
}

func TestDefaultKeyName(t *testing.T) {
	cases := []struct {
		user, host, want string
	}{
		{"alice", "laptop", "alice@laptop"},
		{"", "laptop", "laptop"},
		{"alice", "", "alice"},
		{"", "", "containarium-cli"},
		{"  ", "  ", "containarium-cli"},
	}
	for _, tc := range cases {
		if got := DefaultKeyName(tc.user, tc.host); got != tc.want {
			t.Errorf("DefaultKeyName(%q,%q) = %q, want %q", tc.user, tc.host, got, tc.want)
		}
	}
}

func TestLocate_RejectsEmbeddedNewlineKey(t *testing.T) {
	home := withTempHome(t)
	// Drop a malformed key with an embedded newline.
	dir := filepath.Join(home, ".ssh")
	_ = os.MkdirAll(dir, 0o700)
	path := filepath.Join(dir, DefaultPublicKeyPath)
	if err := os.WriteFile(path, []byte("ssh-ed25519 AAA\ninjected"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_, _, err := Locate(LocateOpts{HomeDir: home})
	if err == nil {
		t.Fatal("expected error on key with embedded newline")
	}
}
