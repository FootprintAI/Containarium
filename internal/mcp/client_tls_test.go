package mcp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// genTestCAPEM produces a tiny self-signed CA cert in PEM form
// for the CA-pin test below. Throwaway — never used to actually
// verify anything beyond AppendCertsFromPEM parseability.
func genTestCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mcp-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// Phase 2.2 — MCP client refuses plaintext HTTP by default and
// supports CA pinning via env var. Audit C-HIGH-1.

func TestBuildMCPTLSConfig_RefusesHTTPByDefault(t *testing.T) {
	// Override the package-init helper that allows insecure for
	// the rest of the test suite — we want to exercise the strict
	// path here.
	t.Setenv(mcpAllowInsecureEnv, "")
	cfg, err := buildMCPTLSConfig("http://daemon.example.com:8080")
	if err == nil {
		t.Fatal("http:// baseURL must be refused by default")
	}
	if cfg != nil {
		t.Fatal("config should be nil when the URL is refused")
	}
	if !strings.Contains(err.Error(), mcpAllowInsecureEnv) {
		t.Fatalf("error should name the escape-hatch env var: %v", err)
	}
}

func TestBuildMCPTLSConfig_AllowsHTTPWhenOptedIn(t *testing.T) {
	t.Setenv(mcpAllowInsecureEnv, "true")
	cfg, err := buildMCPTLSConfig("http://daemon.example.com:8080")
	if err != nil {
		t.Fatalf("opted-in plaintext must be allowed: %v", err)
	}
	if cfg != nil {
		t.Fatal("plaintext path should return nil TLS config")
	}
}

func TestBuildMCPTLSConfig_HTTPSWithSystemRoots(t *testing.T) {
	t.Setenv(mcpAllowInsecureEnv, "")
	t.Setenv(mcpTrustedCAFileEnv, "")
	cfg, err := buildMCPTLSConfig("https://daemon.example.com:8080")
	if err != nil {
		t.Fatalf("https://+no-CA-pin should be accepted: %v", err)
	}
	if cfg != nil {
		t.Fatal("with no CA pin and no other knobs, returning nil lets http.Transport use system roots")
	}
}

func TestBuildMCPTLSConfig_HTTPSWithCAPin(t *testing.T) {
	tmp := t.TempDir()
	caPath := filepath.Join(tmp, "ca.crt")
	if err := os.WriteFile(caPath, genTestCAPEM(t), 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	t.Setenv(mcpAllowInsecureEnv, "")
	t.Setenv(mcpTrustedCAFileEnv, caPath)

	cfg, err := buildMCPTLSConfig("https://daemon.example.com:8080")
	if err != nil {
		t.Fatalf("CA-pin config should succeed: %v", err)
	}
	if cfg == nil || cfg.RootCAs == nil {
		t.Fatal("expected non-nil config with RootCAs populated")
	}
	if cfg.MinVersion < 0x0303 { // TLS 1.2 = 0x0303
		t.Fatalf("MinVersion should be >= TLS 1.2; got %d", cfg.MinVersion)
	}
}

func TestBuildMCPTLSConfig_CAFileMissing(t *testing.T) {
	t.Setenv(mcpTrustedCAFileEnv, "/nonexistent/ca.crt")
	cfg, err := buildMCPTLSConfig("https://daemon.example.com:8080")
	if err == nil {
		t.Fatal("missing CA file must produce an error")
	}
	if cfg != nil {
		t.Fatal("config must be nil when CA file is bad")
	}
}

func TestNewClient_StoresTLSConfigError(t *testing.T) {
	t.Setenv(mcpAllowInsecureEnv, "")
	c := NewClient("http://daemon.example.com:8080", "test-token")
	if c.tlsConfigErr == nil {
		t.Fatal("Client should carry the TLS config error so doRequest can surface it")
	}
	// And any doRequest must fail with the stashed error.
	_, err := c.doRequest("GET", "/v1/anything", nil)
	if err == nil {
		t.Fatal("doRequest should refuse when tlsConfigErr is set")
	}
	if !strings.Contains(err.Error(), "MCP client refuses") {
		t.Fatalf("error should be the TLS refusal: %v", err)
	}
}
