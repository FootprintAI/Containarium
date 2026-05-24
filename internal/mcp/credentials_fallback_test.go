package mcp

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/footprintai/containarium/internal/credentials"
)

// writeCredsFile is a helper that drops a credentials.json under
// $HOME (which the test t.Setenvs to a temp dir, so DefaultPath()
// resolves there) with the given default server + entries.
func writeCredsFile(t *testing.T, home string, defaultServer string, servers map[string]credentials.ServerCreds) {
	t.Helper()
	t.Setenv("HOME", home)
	cf := credentials.NewCredentialsFile()
	for srv, creds := range servers {
		cf.Set(srv, creds)
	}
	if defaultServer != "" {
		cf.DefaultServer = credentials.NormalizeServer(defaultServer)
	}
	if err := os.MkdirAll(filepath.Join(home, ".containarium"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := credentials.Save(filepath.Join(home, credentials.DefaultRelPath), cf); err != nil {
		t.Fatalf("save: %v", err)
	}
}

func TestLoadConfig_CredentialsFallback_PopulatesToken(t *testing.T) {
	t.Setenv("CONTAINARIUM_JWT_TOKEN", "")
	t.Setenv("CONTAINARIUM_JWT_TOKEN_FILE", "")
	t.Setenv("CONTAINARIUM_SERVER_URL", "https://cloud.example.com")
	home := t.TempDir()
	writeCredsFile(t, home, "https://cloud.example.com", map[string]credentials.ServerCreds{
		"https://cloud.example.com": {Token: "ctnr_abc.secret"},
	})

	c := LoadConfig()
	if c.JWTToken != "ctnr_abc.secret" {
		t.Errorf("JWTToken = %q, want %q (fallback should have populated it)", c.JWTToken, "ctnr_abc.secret")
	}
	if c.ServerURL != "https://cloud.example.com" {
		t.Errorf("ServerURL changed unexpectedly: %q", c.ServerURL)
	}
}

func TestLoadConfig_CredentialsFallback_UsesDefaultServerWhenURLEmpty(t *testing.T) {
	t.Setenv("CONTAINARIUM_JWT_TOKEN", "")
	t.Setenv("CONTAINARIUM_JWT_TOKEN_FILE", "")
	t.Setenv("CONTAINARIUM_SERVER_URL", "")
	home := t.TempDir()
	writeCredsFile(t, home, "https://default.example.com", map[string]credentials.ServerCreds{
		"https://default.example.com": {Token: "default-tok"},
		"https://other.example.com":   {Token: "other-tok"},
	})

	c := LoadConfig()
	if c.JWTToken != "default-tok" {
		t.Errorf("JWTToken = %q, want default-server token %q", c.JWTToken, "default-tok")
	}
	if c.ServerURL != "https://default.example.com" {
		t.Errorf("ServerURL = %q, want default_server propagated to %q", c.ServerURL, "https://default.example.com")
	}
}

func TestLoadConfig_CredentialsFallback_SkippedWhenEnvTokenSet(t *testing.T) {
	t.Setenv("CONTAINARIUM_JWT_TOKEN", "env-tok")
	t.Setenv("CONTAINARIUM_JWT_TOKEN_FILE", "")
	t.Setenv("CONTAINARIUM_SERVER_URL", "https://cloud.example.com")
	home := t.TempDir()
	writeCredsFile(t, home, "https://cloud.example.com", map[string]credentials.ServerCreds{
		"https://cloud.example.com": {Token: "creds-file-tok"},
	})

	c := LoadConfig()
	if c.JWTToken != "env-tok" {
		t.Errorf("JWTToken = %q, want env-tok (env should take precedence over credentials.json)", c.JWTToken)
	}
}

func TestLoadConfig_CredentialsFallback_SkippedWhenEnvTokenFileSet(t *testing.T) {
	t.Setenv("CONTAINARIUM_JWT_TOKEN", "")
	t.Setenv("CONTAINARIUM_JWT_TOKEN_FILE", "/some/file")
	t.Setenv("CONTAINARIUM_SERVER_URL", "https://cloud.example.com")
	home := t.TempDir()
	writeCredsFile(t, home, "https://cloud.example.com", map[string]credentials.ServerCreds{
		"https://cloud.example.com": {Token: "creds-file-tok"},
	})

	c := LoadConfig()
	if c.JWTToken != "" {
		t.Errorf("JWTToken = %q, want empty (JWTTokenFile path overrides credentials.json fallback)", c.JWTToken)
	}
	if c.JWTTokenFile != "/some/file" {
		t.Errorf("JWTTokenFile = %q, want /some/file", c.JWTTokenFile)
	}
}

func TestLoadConfig_CredentialsFallback_MissingFileIsSilent(t *testing.T) {
	t.Setenv("CONTAINARIUM_JWT_TOKEN", "")
	t.Setenv("CONTAINARIUM_JWT_TOKEN_FILE", "")
	t.Setenv("CONTAINARIUM_SERVER_URL", "https://cloud.example.com")
	// HOME points to a fresh tmpdir with no credentials.json.
	t.Setenv("HOME", t.TempDir())

	c := LoadConfig()
	if c.JWTToken != "" {
		t.Errorf("JWTToken = %q, want empty (no credentials file present)", c.JWTToken)
	}
}

func TestLoadConfig_CredentialsFallback_MissingServerEntryIsSilent(t *testing.T) {
	t.Setenv("CONTAINARIUM_JWT_TOKEN", "")
	t.Setenv("CONTAINARIUM_JWT_TOKEN_FILE", "")
	t.Setenv("CONTAINARIUM_SERVER_URL", "https://missing.example.com")
	home := t.TempDir()
	writeCredsFile(t, home, "https://cloud.example.com", map[string]credentials.ServerCreds{
		"https://cloud.example.com": {Token: "wrong-server-tok"},
	})

	c := LoadConfig()
	if c.JWTToken != "" {
		t.Errorf("JWTToken = %q, want empty (no entry for the requested ServerURL)", c.JWTToken)
	}
}
