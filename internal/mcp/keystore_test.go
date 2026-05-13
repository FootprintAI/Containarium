package mcp

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSaveEphemeralPrivateKey_WritesFileWithCorrectMode(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("CONTAINARIUM_KEYS_DIR", tmp)

	keyText := []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nfakekeybytes\n-----END OPENSSH PRIVATE KEY-----\n")

	got, err := saveEphemeralPrivateKey("alice", keyText)
	if err != nil {
		t.Fatalf("saveEphemeralPrivateKey err = %v", err)
	}
	if got != filepath.Join(tmp, "alice") {
		t.Errorf("path = %q, want %q", got, filepath.Join(tmp, "alice"))
	}

	contents, err := os.ReadFile(got)
	if err != nil {
		t.Fatalf("readback err = %v", err)
	}
	if string(contents) != string(keyText) {
		t.Errorf("file contents differ:\nwant %q\ngot  %q", keyText, contents)
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(got)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Errorf("file mode = %o, want 0600 (the agent's later ssh -i will reject otherwise)", mode)
		}
	}
}

func TestSaveEphemeralPrivateKey_CreatesParentDir(t *testing.T) {
	tmp := t.TempDir()
	// Use a nested path that doesn't exist yet; the helper must mkdir -p.
	nested := filepath.Join(tmp, "does", "not", "exist", "yet")
	t.Setenv("CONTAINARIUM_KEYS_DIR", nested)

	if _, err := saveEphemeralPrivateKey("bob", []byte("k")); err != nil {
		t.Fatalf("saveEphemeralPrivateKey err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(nested, "bob")); err != nil {
		t.Errorf("expected file at nested path, stat err = %v", err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(nested)
		if err != nil {
			t.Fatalf("stat parent dir: %v", err)
		}
		if mode := info.Mode().Perm(); mode != 0o700 {
			t.Errorf("parent dir mode = %o, want 0700", mode)
		}
	}
}

func TestSaveEphemeralPrivateKey_OverwritesExisting(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("CONTAINARIUM_KEYS_DIR", tmp)

	// First save — stale key.
	if _, err := saveEphemeralPrivateKey("carol", []byte("OLD")); err != nil {
		t.Fatalf("first save: %v", err)
	}
	// Second save — fresh key. Last-create wins. We're idempotent on the
	// rare retry path; we're authoritative when the daemon hands us a new
	// ephemeral key (the old one is no longer authorized server-side).
	if _, err := saveEphemeralPrivateKey("carol", []byte("NEW")); err != nil {
		t.Fatalf("second save: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(tmp, "carol"))
	if err != nil {
		t.Fatalf("readback: %v", err)
	}
	if string(got) != "NEW" {
		t.Errorf("contents = %q, want %q", got, "NEW")
	}
}

func TestEphemeralKeyDir_PrefersExplicitOverride(t *testing.T) {
	t.Setenv("CONTAINARIUM_KEYS_DIR", "/custom/path")
	t.Setenv("HOME", "/some/home")
	if got := ephemeralKeyDir(); got != "/custom/path" {
		t.Errorf("override ignored: got %q, want /custom/path", got)
	}
}

func TestEphemeralKeyDir_FallsBackToHome(t *testing.T) {
	t.Setenv("CONTAINARIUM_KEYS_DIR", "")
	t.Setenv("HOME", "/some/home")
	want := "/some/home/.containarium/keys"
	if got := ephemeralKeyDir(); got != want {
		t.Errorf("home fallback wrong: got %q, want %q", got, want)
	}
}

func TestEphemeralKeyDir_EmptyWhenNothingConfigured(t *testing.T) {
	t.Setenv("CONTAINARIUM_KEYS_DIR", "")
	t.Setenv("HOME", "")
	if got := ephemeralKeyDir(); got != "" {
		t.Errorf("expected empty when HOME and override both unset, got %q", got)
	}
}

func TestSaveEphemeralPrivateKey_ReturnsErrorWhenNoDir(t *testing.T) {
	t.Setenv("CONTAINARIUM_KEYS_DIR", "")
	t.Setenv("HOME", "")
	_, err := saveEphemeralPrivateKey("noone", []byte("k"))
	if err == nil {
		t.Fatal("expected error when no key dir is available, got nil")
	}
	if !strings.Contains(err.Error(), "no key directory") {
		t.Errorf("error %q should mention 'no key directory' so the response text is actionable", err)
	}
}
