package sshsession

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// This fixture mirrors the exact shape internal/sentinel/keysync.go's
// renderSSHPiperConfig writes.
const testConfigYAML = `version: "1.0"
pipes:
  - from:
      - username: "boxuser"
        authorized_keys:
          - /etc/sshpiper/users/boxuser/authorized_keys
    to:
      host: 192.0.2.5:20022
      username: "boxuser"
      ignore_hostkey: true
      private_key: /etc/sshpiper/upstream_key
  - from:
      - username: "otheruser"
        authorized_keys:
          - /etc/sshpiper/users/otheruser/authorized_keys
        trusted_user_ca_keys:
          - /etc/sshpiper/trusted_user_ca_keys
    to:
      host: 192.0.2.9:22
      username: "otheruser"
      ignore_hostkey: true
      private_key: /etc/sshpiper/upstream_key
`

func TestTargetResolver_Resolve(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(testConfigYAML), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	r := NewTargetResolver(path)

	if got := r.Resolve("boxuser"); got != "192.0.2.5:20022" {
		t.Errorf("Resolve(boxuser) = %q, want 192.0.2.5:20022", got)
	}
	if got := r.Resolve("otheruser"); got != "192.0.2.9:22" {
		t.Errorf("Resolve(otheruser) = %q, want 192.0.2.9:22", got)
	}
	if got := r.Resolve("nosuchuser"); got != "" {
		t.Errorf("Resolve(nosuchuser) = %q, want empty", got)
	}
}

func TestTargetResolver_MissingFileIsBestEffort(t *testing.T) {
	r := NewTargetResolver(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if got := r.Resolve("boxuser"); got != "" {
		t.Errorf("Resolve on missing file = %q, want empty (not an error)", got)
	}
}

func TestTargetResolver_PicksUpChanges(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(testConfigYAML), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	r := NewTargetResolver(path)
	if got := r.Resolve("boxuser"); got != "192.0.2.5:20022" {
		t.Fatalf("initial Resolve(boxuser) = %q", got)
	}

	updated := `version: "1.0"
pipes:
  - from:
      - username: "boxuser"
    to:
      host: 192.0.2.99:20022
`
	// Force a distinct mtime so the resolver's cache-invalidation check
	// (which compares os.Stat mtimes) reliably detects the change instead
	// of racing the filesystem's mtime resolution.
	future := time.Now().Add(time.Minute)
	if err := os.WriteFile(path, []byte(updated), 0o600); err != nil {
		t.Fatalf("rewrite fixture: %v", err)
	}
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	if got := r.Resolve("boxuser"); got != "192.0.2.99:20022" {
		t.Errorf("Resolve(boxuser) after update = %q, want 192.0.2.99:20022", got)
	}
}
