package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Phase 4.7 — ResolvePostgresURL / ResolvePostgresPassword.

func clearPGEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		envPostgresURL, envPostgresURLFile,
		envPostgresPassword, envPostgresPasswordFile,
	} {
		t.Setenv(k, "")
	}
}

// --- URL resolution ---

func TestResolvePostgresURL_PrefersFileOverEnv(t *testing.T) {
	clearPGEnv(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "dsn")
	if err := os.WriteFile(p, []byte("postgres://from-file/db\n"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	t.Setenv(envPostgresURL, "postgres://from-env/db")
	t.Setenv(envPostgresURLFile, p)

	dsn, source, err := ResolvePostgresURL()
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if dsn != "postgres://from-file/db" {
		t.Fatalf("dsn = %q; want file value", dsn)
	}
	if !strings.HasPrefix(source, "file:") {
		t.Fatalf("source = %q; want file:", source)
	}
}

func TestResolvePostgresURL_FallsBackToEnv(t *testing.T) {
	clearPGEnv(t)
	t.Setenv(envPostgresURL, "postgres://from-env/db")
	dsn, source, err := ResolvePostgresURL()
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if dsn != "postgres://from-env/db" || source != "env" {
		t.Fatalf("dsn=%q source=%q", dsn, source)
	}
}

func TestResolvePostgresURL_EmptyMeansAutoDetect(t *testing.T) {
	clearPGEnv(t)
	dsn, source, err := ResolvePostgresURL()
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if dsn != "" || source != "auto-detect" {
		t.Fatalf("dsn=%q source=%q; want empty + auto-detect", dsn, source)
	}
}

func TestResolvePostgresURL_RejectsInsecureFilePerms(t *testing.T) {
	clearPGEnv(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "dsn")
	if err := os.WriteFile(p, []byte("postgres://x"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	t.Setenv(envPostgresURLFile, p)
	_, _, err := ResolvePostgresURL()
	if err == nil {
		t.Fatal("0644 file should be rejected")
	}
	if !strings.Contains(err.Error(), "insecure permissions") {
		t.Fatalf("error should mention insecure permissions; got %v", err)
	}
}

func TestResolvePostgresURL_TrimsWhitespace(t *testing.T) {
	clearPGEnv(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "dsn")
	if err := os.WriteFile(p, []byte("  postgres://trimmed/db  \n\n"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	t.Setenv(envPostgresURLFile, p)
	dsn, _, err := ResolvePostgresURL()
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if dsn != "postgres://trimmed/db" {
		t.Fatalf("dsn = %q; want trimmed", dsn)
	}
}

// --- Password resolution ---

func TestResolvePostgresPassword_PrefersFileOverEnv(t *testing.T) {
	clearPGEnv(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "pw")
	if err := os.WriteFile(p, []byte("file-secret\n"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	t.Setenv(envPostgresPassword, "env-secret")
	t.Setenv(envPostgresPasswordFile, p)

	pw, source, err := ResolvePostgresPassword()
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if pw != "file-secret" {
		t.Fatalf("pw = %q; want file value", pw)
	}
	if !strings.HasPrefix(source, "file:") {
		t.Fatalf("source = %q", source)
	}
}

func TestResolvePostgresPassword_FallsBackToEnv(t *testing.T) {
	clearPGEnv(t)
	t.Setenv(envPostgresPassword, "env-secret")
	pw, source, err := ResolvePostgresPassword()
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if pw != "env-secret" || source != "env" {
		t.Fatalf("pw=%q source=%q", pw, source)
	}
}

func TestResolvePostgresPassword_FallsBackToDefault(t *testing.T) {
	clearPGEnv(t)
	pw, source, err := ResolvePostgresPassword()
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if pw != DefaultPostgresPassword {
		t.Fatalf("pw = %q; want default", pw)
	}
	if source != "default" {
		t.Fatalf("source = %q; want default", source)
	}
}

func TestResolvePostgresPassword_RejectsInsecureFilePerms(t *testing.T) {
	clearPGEnv(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "pw")
	if err := os.WriteFile(p, []byte("secret"), 0o640); err != nil {
		t.Fatalf("write file: %v", err)
	}
	t.Setenv(envPostgresPasswordFile, p)
	_, _, err := ResolvePostgresPassword()
	if err == nil {
		t.Fatal("0640 file should be rejected")
	}
}
