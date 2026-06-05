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
		"CONTAINARIUM_GCP_KMS_KEY_NAME",
		"CONTAINARIUM_GCP_KMS_TOKEN",
		"CONTAINARIUM_GCP_KMS_TOKEN_FILE",
		"CONTAINARIUM_GCP_KMS_ENDPOINT",
		"CONTAINARIUM_GCP_KMS_TIMEOUT",
		"CONTAINARIUM_AWS_KMS_REGION",
		"CONTAINARIUM_AWS_KMS_KEY_ID",
		"CONTAINARIUM_AWS_ACCESS_KEY_ID",
		"CONTAINARIUM_AWS_SECRET_ACCESS_KEY",
		"CONTAINARIUM_AWS_SECRET_ACCESS_KEY_FILE",
		"CONTAINARIUM_AWS_SESSION_TOKEN",
		"CONTAINARIUM_AWS_SESSION_TOKEN_FILE",
		"CONTAINARIUM_AWS_KMS_ENDPOINT",
		"CONTAINARIUM_AWS_KMS_TIMEOUT",
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

// --- GCP KMS factory cases ---

const factoryTestKeyName = "projects/p/locations/us-west1/keyRings/r/cryptoKeys/k"

func TestLoadKMSClient_GCPFromEnvSucceeds(t *testing.T) {
	clearKMSEnv(t)
	t.Setenv("CONTAINARIUM_KMS_BACKEND", "gcp")
	t.Setenv("CONTAINARIUM_GCP_KMS_KEY_NAME", factoryTestKeyName)
	t.Setenv("CONTAINARIUM_GCP_KMS_TOKEN", "access-token-xyz")
	c, desc, err := LoadKMSClient(mkMaster(t))
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil GCPKMS client")
	}
	if desc == "" || desc[:3] != "gcp" {
		t.Fatalf("description should announce gcp backend; got %q", desc)
	}
}

func TestLoadKMSClient_GCPRequiresKeyName(t *testing.T) {
	clearKMSEnv(t)
	t.Setenv("CONTAINARIUM_KMS_BACKEND", "gcp")
	t.Setenv("CONTAINARIUM_GCP_KMS_TOKEN", "access-token-xyz")
	if _, _, err := LoadKMSClient(mkMaster(t)); err == nil {
		t.Fatal("missing GCP_KMS_KEY_NAME should error")
	}
}

func TestLoadKMSClient_GCPRequiresToken(t *testing.T) {
	clearKMSEnv(t)
	t.Setenv("CONTAINARIUM_KMS_BACKEND", "gcp")
	t.Setenv("CONTAINARIUM_GCP_KMS_KEY_NAME", factoryTestKeyName)
	if _, _, err := LoadKMSClient(mkMaster(t)); err == nil {
		t.Fatal("missing GCP token should error")
	}
}

func TestLoadKMSClient_GCPTokenFromFile(t *testing.T) {
	clearKMSEnv(t)
	dir := t.TempDir()
	tokPath := filepath.Join(dir, "gcp.token")
	if err := os.WriteFile(tokPath, []byte("access-token-xyz\n"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	t.Setenv("CONTAINARIUM_KMS_BACKEND", "gcp")
	t.Setenv("CONTAINARIUM_GCP_KMS_KEY_NAME", factoryTestKeyName)
	t.Setenv("CONTAINARIUM_GCP_KMS_TOKEN_FILE", tokPath)
	c, _, err := LoadKMSClient(mkMaster(t))
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if c == nil {
		t.Fatal("expected client from token-file path")
	}
}

func TestLoadKMSClient_GCPTokenFileWithBadPerms(t *testing.T) {
	clearKMSEnv(t)
	dir := t.TempDir()
	tokPath := filepath.Join(dir, "gcp.token")
	if err := os.WriteFile(tokPath, []byte("access-token-xyz\n"), 0o644); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	t.Setenv("CONTAINARIUM_KMS_BACKEND", "gcp")
	t.Setenv("CONTAINARIUM_GCP_KMS_KEY_NAME", factoryTestKeyName)
	t.Setenv("CONTAINARIUM_GCP_KMS_TOKEN_FILE", tokPath)
	if _, _, err := LoadKMSClient(mkMaster(t)); err == nil {
		t.Fatal("0644 token file should be rejected (defense-in-depth, same as Vault path)")
	}
}

func TestLoadKMSClient_GCPTimeoutParse(t *testing.T) {
	clearKMSEnv(t)
	t.Setenv("CONTAINARIUM_KMS_BACKEND", "gcp")
	t.Setenv("CONTAINARIUM_GCP_KMS_KEY_NAME", factoryTestKeyName)
	t.Setenv("CONTAINARIUM_GCP_KMS_TOKEN", "access-token-xyz")
	t.Setenv("CONTAINARIUM_GCP_KMS_TIMEOUT", "10s")
	if _, _, err := LoadKMSClient(mkMaster(t)); err != nil {
		t.Fatalf("valid duration should parse; got %v", err)
	}
	t.Setenv("CONTAINARIUM_GCP_KMS_TIMEOUT", "garbage")
	if _, _, err := LoadKMSClient(mkMaster(t)); err == nil {
		t.Fatal("malformed duration should error")
	}
}

// --- AWS KMS factory cases ---

func setAWSBaseEnv(t *testing.T) {
	t.Helper()
	t.Setenv("CONTAINARIUM_KMS_BACKEND", "aws")
	t.Setenv("CONTAINARIUM_AWS_KMS_REGION", "us-west-2")
	t.Setenv("CONTAINARIUM_AWS_KMS_KEY_ID", "alias/containarium-secrets")
	t.Setenv("CONTAINARIUM_AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
}

func TestLoadKMSClient_AWSFromEnvSucceeds(t *testing.T) {
	clearKMSEnv(t)
	setAWSBaseEnv(t)
	t.Setenv("CONTAINARIUM_AWS_SECRET_ACCESS_KEY", "secret-key-xyz")
	c, desc, err := LoadKMSClient(mkMaster(t))
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if _, ok := c.(*AWSKMS); !ok {
		t.Fatalf("expected *AWSKMS; got %T", c)
	}
	if desc == "" || desc[:3] != "aws" {
		t.Fatalf("description should announce aws backend; got %q", desc)
	}
}

func TestLoadKMSClient_AWSRequiresRegion(t *testing.T) {
	clearKMSEnv(t)
	t.Setenv("CONTAINARIUM_KMS_BACKEND", "aws")
	t.Setenv("CONTAINARIUM_AWS_KMS_KEY_ID", "alias/k")
	t.Setenv("CONTAINARIUM_AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
	t.Setenv("CONTAINARIUM_AWS_SECRET_ACCESS_KEY", "secret-key-xyz")
	if _, _, err := LoadKMSClient(mkMaster(t)); err == nil {
		t.Fatal("missing AWS_KMS_REGION should error")
	}
}

func TestLoadKMSClient_AWSRequiresKeyID(t *testing.T) {
	clearKMSEnv(t)
	t.Setenv("CONTAINARIUM_KMS_BACKEND", "aws")
	t.Setenv("CONTAINARIUM_AWS_KMS_REGION", "us-west-2")
	t.Setenv("CONTAINARIUM_AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
	t.Setenv("CONTAINARIUM_AWS_SECRET_ACCESS_KEY", "secret-key-xyz")
	if _, _, err := LoadKMSClient(mkMaster(t)); err == nil {
		t.Fatal("missing AWS_KMS_KEY_ID should error")
	}
}

func TestLoadKMSClient_AWSRequiresAccessKey(t *testing.T) {
	clearKMSEnv(t)
	t.Setenv("CONTAINARIUM_KMS_BACKEND", "aws")
	t.Setenv("CONTAINARIUM_AWS_KMS_REGION", "us-west-2")
	t.Setenv("CONTAINARIUM_AWS_KMS_KEY_ID", "alias/k")
	t.Setenv("CONTAINARIUM_AWS_SECRET_ACCESS_KEY", "secret-key-xyz")
	if _, _, err := LoadKMSClient(mkMaster(t)); err == nil {
		t.Fatal("missing AWS_ACCESS_KEY_ID should error")
	}
}

func TestLoadKMSClient_AWSRequiresSecret(t *testing.T) {
	clearKMSEnv(t)
	setAWSBaseEnv(t)
	// No secret env or file.
	if _, _, err := LoadKMSClient(mkMaster(t)); err == nil {
		t.Fatal("missing AWS secret (env or file) should error")
	}
}

func TestLoadKMSClient_AWSSecretFromFile(t *testing.T) {
	clearKMSEnv(t)
	setAWSBaseEnv(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "aws.secret")
	if err := os.WriteFile(p, []byte("secret-key-xyz\n"), 0o600); err != nil {
		t.Fatalf("write secret file: %v", err)
	}
	t.Setenv("CONTAINARIUM_AWS_SECRET_ACCESS_KEY_FILE", p)
	c, _, err := LoadKMSClient(mkMaster(t))
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if _, ok := c.(*AWSKMS); !ok {
		t.Fatalf("expected *AWSKMS from secret-file path; got %T", c)
	}
}

func TestLoadKMSClient_AWSSecretFileWithBadPerms(t *testing.T) {
	clearKMSEnv(t)
	setAWSBaseEnv(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "aws.secret")
	if err := os.WriteFile(p, []byte("secret-key-xyz\n"), 0o644); err != nil {
		t.Fatalf("write secret file: %v", err)
	}
	t.Setenv("CONTAINARIUM_AWS_SECRET_ACCESS_KEY_FILE", p)
	if _, _, err := LoadKMSClient(mkMaster(t)); err == nil {
		t.Fatal("0644 secret file should be rejected (defense-in-depth, same as Vault/GCP)")
	}
}

func TestLoadKMSClient_AWSSessionTokenFromFile(t *testing.T) {
	clearKMSEnv(t)
	setAWSBaseEnv(t)
	t.Setenv("CONTAINARIUM_AWS_SECRET_ACCESS_KEY", "secret-key-xyz")
	dir := t.TempDir()
	p := filepath.Join(dir, "aws.session")
	if err := os.WriteFile(p, []byte("session-token-abc\n"), 0o600); err != nil {
		t.Fatalf("write session file: %v", err)
	}
	t.Setenv("CONTAINARIUM_AWS_SESSION_TOKEN_FILE", p)
	if _, _, err := LoadKMSClient(mkMaster(t)); err != nil {
		t.Fatalf("session token from file should be accepted; got %v", err)
	}
}

func TestLoadKMSClient_AWSTimeoutParse(t *testing.T) {
	clearKMSEnv(t)
	setAWSBaseEnv(t)
	t.Setenv("CONTAINARIUM_AWS_SECRET_ACCESS_KEY", "secret-key-xyz")
	t.Setenv("CONTAINARIUM_AWS_KMS_TIMEOUT", "10s")
	if _, _, err := LoadKMSClient(mkMaster(t)); err != nil {
		t.Fatalf("valid duration should parse; got %v", err)
	}
	t.Setenv("CONTAINARIUM_AWS_KMS_TIMEOUT", "garbage")
	if _, _, err := LoadKMSClient(mkMaster(t)); err == nil {
		t.Fatal("malformed duration should error")
	}
}
