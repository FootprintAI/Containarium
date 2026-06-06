package secrets

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The gcp KMS backend must re-read its token file so a refresh sidecar's
// rotations take effect without a daemon restart (the prior bug froze the
// token at startup → 401 after ~1h). #300.
func TestGCPKMS_TokenFileReReadAndRefresh(t *testing.T) {
	dir := t.TempDir()
	tf := filepath.Join(dir, "token")
	if err := os.WriteFile(tf, []byte("tok1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	g, err := NewGCPKMS(GCPConfig{
		KeyName:   "projects/p/locations/l/keyRings/r/cryptoKeys/k",
		TokenFile: tf,
	})
	if err != nil {
		t.Fatalf("NewGCPKMS: %v", err)
	}

	if got, err := g.token(); err != nil || got != "tok1" {
		t.Fatalf("token() = %q, %v; want tok1", got, err)
	}

	// Rotate the file; within the TTL the cached value is still served.
	if err := os.WriteFile(tf, []byte("tok2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, _ := g.token(); got != "tok1" {
		t.Fatalf("token() = %q within TTL; want cached tok1", got)
	}

	// Expire the cache → the next read picks up the rotation (no restart).
	g.tokMu.Lock()
	g.cachedAt = time.Now().Add(-time.Hour)
	g.tokMu.Unlock()
	if got, err := g.token(); err != nil || got != "tok2" {
		t.Fatalf("token() after expiry = %q, %v; want tok2", got, err)
	}
}

func TestGCPKMS_StaticTokenStillWorks(t *testing.T) {
	g, err := NewGCPKMS(GCPConfig{
		KeyName: "projects/p/locations/l/keyRings/r/cryptoKeys/k",
		Token:   "static-tok",
	})
	if err != nil {
		t.Fatalf("NewGCPKMS: %v", err)
	}
	if got, _ := g.token(); got != "static-tok" {
		t.Fatalf("token() = %q; want static-tok", got)
	}
}
