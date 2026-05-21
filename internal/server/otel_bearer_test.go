package server

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Phase 2.5 follow-up — OTel bearer load/create primitive.

func resetBearerCache(t *testing.T) {
	t.Helper()
	otelBearerOnce = sync.Once{}
	otelBearerValue = ""
	otelBearerError = nil
}

func clearOTelEnv(t *testing.T) {
	t.Helper()
	t.Setenv(otelBearerEnvOverride, "")
	t.Setenv(otelBearerEnvFile, "")
}

func TestLoadOrCreateOTelBearer_EnvOverride(t *testing.T) {
	resetBearerCache(t)
	clearOTelEnv(t)
	t.Setenv(otelBearerEnvOverride, "from-env")
	v, err := LoadOrCreateOTelBearer()
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if v != "from-env" {
		t.Fatalf("v = %q; want from-env", v)
	}
}

func TestLoadOrCreateOTelBearer_FileSource(t *testing.T) {
	resetBearerCache(t)
	clearOTelEnv(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "bearer")
	if err := os.WriteFile(p, []byte("from-file\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Setenv(otelBearerEnvFile, p)

	v, err := LoadOrCreateOTelBearer()
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if v != "from-file" {
		t.Fatalf("v = %q; want from-file", v)
	}
}

func TestLoadOrCreateOTelBearer_RejectsInsecureFile(t *testing.T) {
	resetBearerCache(t)
	clearOTelEnv(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "bearer")
	if err := os.WriteFile(p, []byte("secret"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Setenv(otelBearerEnvFile, p)

	_, err := LoadOrCreateOTelBearer()
	if err == nil {
		t.Fatal("0644 file should be rejected")
	}
	if !strings.Contains(err.Error(), "insecure permissions") {
		t.Fatalf("error should mention insecure permissions; got %v", err)
	}
}

func TestLoadOrCreateOTelBearer_EmptyFileRejected(t *testing.T) {
	resetBearerCache(t)
	clearOTelEnv(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "bearer")
	if err := os.WriteFile(p, []byte(""), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Setenv(otelBearerEnvFile, p)

	_, err := LoadOrCreateOTelBearer()
	if err == nil {
		t.Fatal("empty file should be rejected")
	}
}

func TestLoadOrCreateOTelBearer_CachedAfterFirstCall(t *testing.T) {
	// Once loaded, subsequent calls return the cached value
	// even if the env changes underneath. That's intentional
	// — the daemon and every container start should see the
	// same bearer, and rotating the bearer requires a
	// daemon restart (matches the JWT secret contract).
	resetBearerCache(t)
	clearOTelEnv(t)
	t.Setenv(otelBearerEnvOverride, "first")
	if v, _ := LoadOrCreateOTelBearer(); v != "first" {
		t.Fatalf("first load = %q", v)
	}
	t.Setenv(otelBearerEnvOverride, "second")
	if v, _ := LoadOrCreateOTelBearer(); v != "first" {
		t.Fatalf("second load = %q; should be cached as 'first'", v)
	}
}

func TestGenerateAndPersistBearer_ProducesValidSecret(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bearer")
	v, err := generateAndPersistBearer(p)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(v) < 40 {
		t.Fatalf("generated token too short: %q (len=%d)", v, len(v))
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("persisted file mode = %#o; want 0600", mode)
	}
	// Reading back returns the same value.
	b, _ := os.ReadFile(p)
	if strings.TrimSpace(string(b)) != v {
		t.Fatal("re-read does not match generated value")
	}
}

func TestGenerateAndPersistBearer_TwoCallsGenerateDifferent(t *testing.T) {
	dir := t.TempDir()
	a, err := generateAndPersistBearer(filepath.Join(dir, "a"))
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	b, err := generateAndPersistBearer(filepath.Join(dir, "b"))
	if err != nil {
		t.Fatalf("b: %v", err)
	}
	if a == b {
		t.Fatal("two generations produced the same token — crypto/rand isn't")
	}
}
