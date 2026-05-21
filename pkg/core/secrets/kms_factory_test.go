package secrets

import (
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// Phase 4.1 — KMS backend selector tests.

func clearKMSEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"CONTAINARIUM_KMS_BACKEND",
		"CONTAINARIUM_VAULT_ADDR",
		"CONTAINARIUM_VAULT_TOKEN",
		"CONTAINARIUM_VAULT_TOKEN_FILE",
		"CONTAINARIUM_VAULT_TRANSIT_MOUNT",
		"CONTAINARIUM_VAULT_TRANSIT_KEY",
		"CONTAINARIUM_VAULT_TIMEOUT",
	} {
		t.Setenv(k, "")
	}
}

func mkMaster(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, MasterKeySize)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return k
}

func TestLoadKMSClient_DefaultIsNone(t *testing.T) {
	clearKMSEnv(t)
	c, desc, err := LoadKMSClient(mkMaster(t))
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if c != nil {
		t.Fatalf("expected nil client when backend unset; got %T", c)
	}
	if desc == "" {
		t.Fatal("expected non-empty description for the disabled path")
	}
}

func TestLoadKMSClient_NoneIsExplicitlyDisabled(t *testing.T) {
	clearKMSEnv(t)
	t.Setenv("CONTAINARIUM_KMS_BACKEND", "none")
	c, _, err := LoadKMSClient(mkMaster(t))
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if c != nil {
		t.Fatal("expected nil client")
	}
}

func TestLoadKMSClient_InProcReturnsImpl(t *testing.T) {
	clearKMSEnv(t)
	t.Setenv("CONTAINARIUM_KMS_BACKEND", "inproc")
	c, desc, err := LoadKMSClient(mkMaster(t))
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if _, ok := c.(*InProcKMS); !ok {
		t.Fatalf("expected *InProcKMS; got %T", c)
	}
	if desc == "" {
		t.Fatal("expected description")
	}
}

func TestLoadKMSClient_VaultRequiresAddr(t *testing.T) {
	clearKMSEnv(t)
	t.Setenv("CONTAINARIUM_KMS_BACKEND", "vault")
	// No address set.
	_, _, err := LoadKMSClient(mkMaster(t))
	if err == nil {
		t.Fatal("vault backend without CONTAINARIUM_VAULT_ADDR should error")
	}
}

func TestLoadKMSClient_VaultRequiresKey(t *testing.T) {
	clearKMSEnv(t)
	t.Setenv("CONTAINARIUM_KMS_BACKEND", "vault")
	t.Setenv("CONTAINARIUM_VAULT_ADDR", "http://vault.local:8200")
	t.Setenv("CONTAINARIUM_VAULT_TOKEN", "t")
	_, _, err := LoadKMSClient(mkMaster(t))
	if err == nil {
		t.Fatal("vault backend without CONTAINARIUM_VAULT_TRANSIT_KEY should error")
	}
}

func TestLoadKMSClient_VaultRequiresToken(t *testing.T) {
	clearKMSEnv(t)
	t.Setenv("CONTAINARIUM_KMS_BACKEND", "vault")
	t.Setenv("CONTAINARIUM_VAULT_ADDR", "http://vault.local:8200")
	t.Setenv("CONTAINARIUM_VAULT_TRANSIT_KEY", "k")
	_, _, err := LoadKMSClient(mkMaster(t))
	if err == nil {
		t.Fatal("vault backend without token env or file should error")
	}
}

func TestLoadKMSClient_VaultTokenFromFile(t *testing.T) {
	clearKMSEnv(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "token")
	if err := os.WriteFile(p, []byte("from-file\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Setenv("CONTAINARIUM_KMS_BACKEND", "vault")
	t.Setenv("CONTAINARIUM_VAULT_ADDR", "http://vault.local:8200")
	t.Setenv("CONTAINARIUM_VAULT_TRANSIT_KEY", "k")
	t.Setenv("CONTAINARIUM_VAULT_TOKEN_FILE", p)
	c, desc, err := LoadKMSClient(mkMaster(t))
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if _, ok := c.(*VaultKMS); !ok {
		t.Fatalf("expected *VaultKMS; got %T", c)
	}
	if desc == "" {
		t.Fatal("expected description")
	}
}

func TestLoadKMSClient_VaultTokenFileRejectsInsecurePerms(t *testing.T) {
	clearKMSEnv(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "token")
	if err := os.WriteFile(p, []byte("t"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Setenv("CONTAINARIUM_KMS_BACKEND", "vault")
	t.Setenv("CONTAINARIUM_VAULT_ADDR", "http://vault.local:8200")
	t.Setenv("CONTAINARIUM_VAULT_TRANSIT_KEY", "k")
	t.Setenv("CONTAINARIUM_VAULT_TOKEN_FILE", p)
	_, _, err := LoadKMSClient(mkMaster(t))
	if err == nil {
		t.Fatal("0644 token file should be rejected")
	}
}

func TestLoadKMSClient_UnrecognizedBackendErrors(t *testing.T) {
	clearKMSEnv(t)
	t.Setenv("CONTAINARIUM_KMS_BACKEND", "gibberish")
	_, _, err := LoadKMSClient(mkMaster(t))
	if err == nil {
		t.Fatal("unrecognized backend should error")
	}
}

func TestLoadKMSClient_VaultTimeoutParse(t *testing.T) {
	clearKMSEnv(t)
	t.Setenv("CONTAINARIUM_KMS_BACKEND", "vault")
	t.Setenv("CONTAINARIUM_VAULT_ADDR", "http://vault.local:8200")
	t.Setenv("CONTAINARIUM_VAULT_TRANSIT_KEY", "k")
	t.Setenv("CONTAINARIUM_VAULT_TOKEN", "t")
	t.Setenv("CONTAINARIUM_VAULT_TIMEOUT", "30s")
	if _, _, err := LoadKMSClient(mkMaster(t)); err != nil {
		t.Fatalf("valid duration should parse; got %v", err)
	}

	t.Setenv("CONTAINARIUM_VAULT_TIMEOUT", "not-a-duration")
	if _, _, err := LoadKMSClient(mkMaster(t)); err == nil {
		t.Fatal("malformed duration should error")
	}
}
