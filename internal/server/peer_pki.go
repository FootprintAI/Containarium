package server

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/sentinel"
)

// Phase 0.5 — peer-to-peer mTLS bootstrap on the daemon side.
//
// At PeerPool startup the daemon:
//  1. POSTs /sentinel/peer-cert with its own peer ID (HMAC-signed
//     via auth.SignSentinelRequest) and receives a freshly-minted
//     leaf cert + key plus the CA bundle.
//  2. Persists them to a known on-disk path (mode 0600 / 0700) so
//     a daemon restart doesn't burn a fresh issuance.
//  3. Builds an *http.Client pinned to the CA and presenting the
//     leaf cert, ready for peer-to-peer HTTPS calls.
//
// The peer client in peer.go uses the daemon's HTTPS client when
// `CONTAINARIUM_SENTINEL_URL` starts with `https://`. Plain HTTP
// remains the default for backwards compatibility during rollout.
// See docs/security/ZERO-TRUST-AUDIT.md C-CRIT-1.

// peerPKI holds the daemon-side cert material — refreshable.
type peerPKI struct {
	mu      sync.RWMutex
	tlsCert tls.Certificate
	caPool  *x509.CertPool
	caPEM   []byte
	expiry  time.Time
}

// CACertPool returns the trusted CA pool for verifying sentinel +
// peer server certs. Returns nil if no PKI is configured.
func (p *peerPKI) CACertPool() *x509.CertPool {
	if p == nil {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.caPool
}

// ClientCertificate returns the daemon's leaf cert + key for mTLS.
// Returns the zero-value tls.Certificate if no PKI is configured —
// callers can use that to decide whether to present a client cert.
func (p *peerPKI) ClientCertificate() tls.Certificate {
	if p == nil {
		return tls.Certificate{}
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.tlsCert
}

// CACertPEM returns the PEM bytes of the trusted CA, for callers
// that need to log the pin or persist it.
func (p *peerPKI) CACertPEM() []byte {
	if p == nil {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.caPEM
}

// Expiry reports when the current leaf cert expires. Used by the
// renewal loop.
func (p *peerPKI) Expiry() time.Time {
	if p == nil {
		return time.Time{}
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.expiry
}

// replace swaps in fresh cert material atomically. The caller has
// already validated the cert; this just commits.
func (p *peerPKI) replace(cert tls.Certificate, caPool *x509.CertPool, caPEM []byte, expiry time.Time) {
	p.mu.Lock()
	p.tlsCert = cert
	p.caPool = caPool
	p.caPEM = caPEM
	p.expiry = expiry
	p.mu.Unlock()
}

// FetchPeerPKI asks the sentinel to mint a leaf cert for `peerID`
// and returns a populated peerPKI ready for use. Authenticates the
// request with the sentinel HMAC secret. `sentinelBaseURL` is the
// sentinel's HTTP[S] base URL (e.g. https://sentinel:8889).
//
// The request is signed even if the URL is plain http://, so
// rollout deployments can use HTTP for the bootstrap fetch and
// HTTPS for steady-state peer traffic — the bootstrap is HMAC-
// authenticated regardless. (We still recommend HTTPS for the
// bootstrap call too, since the leaf private key travels in the
// body.)
func FetchPeerPKI(ctx interface{}, sentinelBaseURL, peerID string, hmacSecret []byte) (*peerPKI, error) {
	if len(hmacSecret) < auth.SentinelMinSecretLen {
		return nil, fmt.Errorf("sentinel HMAC secret is missing or too short — Phase 0.5 bootstrap requires CONTAINARIUM_SENTINEL_AUTH_SECRET")
	}
	if peerID == "" {
		return nil, fmt.Errorf("peerID is required")
	}

	body, err := json.Marshal(sentinel.PeerCertRequest{PeerID: peerID})
	if err != nil {
		return nil, fmt.Errorf("marshal cert request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, sentinelBaseURL+"/sentinel/peer-cert", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build peer-cert request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	auth.SignSentinelRequest(req, hmacSecret)

	// Bootstrap client: lenient TLS verification because we don't
	// have the CA yet. The HMAC signature on the request body
	// authenticates the caller (only holders of the shared secret
	// can ask for a cert), and the response is JSON containing the
	// CA, which we pin for every subsequent call. This bootstrap
	// hop is the only place InsecureSkipVerify appears in the
	// peer-to-peer path — it cannot be used once the CA is loaded.
	bootstrap := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // bootstrap; pinned CA used for all subsequent calls
				MinVersion:         tls.VersionTLS12,
			},
		},
	}
	resp, err := bootstrap.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST /sentinel/peer-cert: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read peer-cert response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("peer-cert request failed: status=%d body=%s", resp.StatusCode, truncate(string(respBody), 200))
	}

	var parsed sentinel.PeerCertResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, fmt.Errorf("parse peer-cert response: %w", err)
	}
	if parsed.CertPEM == "" || parsed.KeyPEM == "" || parsed.CAPEM == "" {
		return nil, fmt.Errorf("peer-cert response is missing fields")
	}

	tlsCert, err := tls.X509KeyPair([]byte(parsed.CertPEM), []byte(parsed.KeyPEM))
	if err != nil {
		return nil, fmt.Errorf("parse leaf keypair: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM([]byte(parsed.CAPEM)) {
		return nil, fmt.Errorf("CA bundle in response is not parseable")
	}

	// Determine leaf expiry so the renewal loop knows when to swap.
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse leaf cert: %w", err)
	}

	pki := &peerPKI{}
	pki.replace(tlsCert, caPool, []byte(parsed.CAPEM), leaf.NotAfter)

	log.Printf("[peer-pki] received leaf cert for %q, expires %s (in %s)",
		peerID, leaf.NotAfter.Format(time.RFC3339), time.Until(leaf.NotAfter).Round(time.Second))
	return pki, nil
}

// PersistPeerPKI writes the cert/key/CA to disk under `dir` with
// strict modes (0700 dir, 0600 key, 0644 cert + CA). Idempotent
// over re-writes. Errors here are not fatal — the in-memory copy
// already works for the current daemon lifetime — but operators
// usually want them on disk so a restart doesn't burn an
// issuance.
func PersistPeerPKI(dir, peerID, certPEM, keyPEM, caPEM string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	files := []struct {
		name string
		mode os.FileMode
		data []byte
	}{
		{"peer.crt", 0o644, []byte(certPEM)},
		{"peer.key", 0o600, []byte(keyPEM)},
		{"ca.crt", 0o644, []byte(caPEM)},
	}
	for _, f := range files {
		full := filepath.Join(dir, f.name)
		if err := os.WriteFile(full, f.data, f.mode); err != nil {
			return fmt.Errorf("write %s: %w", full, err)
		}
	}
	return nil
}

// truncate caps strings used in error messages so a giant HTML
// 500-page from a misconfigured proxy doesn't blow up the log.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
