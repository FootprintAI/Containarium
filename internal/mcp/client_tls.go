package mcp

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// Phase 2.2 — MCP client TLS configuration (audit C-HIGH-1).
//
// The MCP client carries a Bearer JWT on every request. Without
// TLS, that token travels in cleartext and any passive listener on
// the daemon's network path harvests it. Without CA pinning, an
// attacker who can MITM the connection serves a self-signed cert
// for the same hostname and decrypts the traffic regardless.
//
// Two env vars control the policy:
//
//   CONTAINARIUM_MCP_ALLOW_INSECURE=true
//     Permits http:// baseURL. Default (unset) refuses it. Use
//     only for local dev / unit tests; production must be https.
//
//   CONTAINARIUM_MCP_TRUSTED_CA_FILE=/path/to/ca.crt
//     PEM bundle to use as the RootCAs pool. Use with the
//     sentinel-issued CA from Phase 0.5 (the /sentinel/ca
//     response) or a corporate root. Unset → fall back to the
//     system trust store, which is correct for publicly-trusted
//     hostnames and wrong for self-signed certs.

const (
	mcpAllowInsecureEnv = "CONTAINARIUM_MCP_ALLOW_INSECURE"
	mcpTrustedCAFileEnv = "CONTAINARIUM_MCP_TRUSTED_CA_FILE"
)

// buildMCPTLSConfig constructs a *tls.Config for the MCP client's
// http.Transport based on the env knobs above. Returns:
//   - nil, nil      — caller can use the http.Transport zero
//     value (system roots, default TLS). Happens
//     for an https:// URL with no CA pin and
//     no insecure-allow toggle.
//   - cfg, nil      — pinned CA (cfg.RootCAs populated).
//   - nil, error    — scheme is http:// and ALLOW_INSECURE isn't
//     set, OR the CA file is unreadable / not
//     PEM.
func buildMCPTLSConfig(baseURL string) (*tls.Config, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid baseURL %q: %w", baseURL, err)
	}

	if u.Scheme == "http" {
		if !mcpInsecureAllowed() {
			return nil, fmt.Errorf("MCP client refuses http:// baseURL %q (audit C-HIGH-1); set %s=true to opt into plaintext for dev/test",
				baseURL, mcpAllowInsecureEnv)
		}
		// Caller explicitly allowed plaintext; no TLS config
		// needed, returning nil falls back to the http.Transport
		// zero value (no TLS attempted).
		return nil, nil
	}

	caFile := strings.TrimSpace(os.Getenv(mcpTrustedCAFileEnv))
	if caFile == "" {
		// HTTPS with system roots — fine for publicly-trusted
		// certs. Returning nil lets the transport use defaults.
		return nil, nil
	}

	// caFile is the operator-supplied CONTAINARIUM_MCP_TRUSTED_CA_FILE
	// path. gosec emits both G304 and G703 for the same finding —
	// the inline #nosec covers both.
	caBytes, err := os.ReadFile(caFile) // #nosec G304 G703 -- operator config
	if err != nil {
		return nil, fmt.Errorf("read CA bundle %s: %w", caFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBytes) {
		return nil, fmt.Errorf("no PEM certs found in %s; check that the file contains BEGIN CERTIFICATE blocks", caFile)
	}
	return &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}, nil
}

func mcpInsecureAllowed() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(mcpAllowInsecureEnv)))
	return v == "true" || v == "1" || v == "yes"
}
