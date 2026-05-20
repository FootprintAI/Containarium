package sentinel

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/footprintai/containarium/internal/gateway"
)

// CertStore holds synced TLS certificates from the backend (Caddy/Let's Encrypt).
// It provides SNI-based certificate lookup with a self-signed fallback.
type CertStore struct {
	mu       sync.RWMutex
	certs    map[string]tls.Certificate // domain → parsed cert
	fallback tls.Certificate            // self-signed fallback

	lastSync     time.Time
	lastSyncErr  error
	syncedCount  int
}

// NewCertStore creates a CertStore with a self-signed fallback certificate.
func NewCertStore() *CertStore {
	fallback, err := generateSelfSignedCert()
	if err != nil {
		log.Printf("[certsync] warning: failed to generate fallback cert: %v", err)
	}
	return &CertStore{
		certs:    make(map[string]tls.Certificate),
		fallback: fallback,
	}
}

// Sync fetches certificates from the backend daemon's /certs endpoint.
func (cs *CertStore) Sync(backendIP string, httpPort int) error {
	url := fmt.Sprintf("http://%s:%d/certs", backendIP, httpPort)

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := newSignedRequest(http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("cert sync: build request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		cs.mu.Lock()
		cs.lastSyncErr = err
		cs.mu.Unlock()
		return fmt.Errorf("cert sync GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("cert sync: unexpected status %d from %s", resp.StatusCode, url)
		cs.mu.Lock()
		cs.lastSyncErr = err
		cs.mu.Unlock()
		return err
	}

	var certsResp gateway.CertsResponse
	if err := json.NewDecoder(resp.Body).Decode(&certsResp); err != nil {
		cs.mu.Lock()
		cs.lastSyncErr = err
		cs.mu.Unlock()
		return fmt.Errorf("cert sync: decode response: %w", err)
	}

	newCerts := make(map[string]tls.Certificate, len(certsResp.Certs))
	for _, cp := range certsResp.Certs {
		tlsCert, err := tls.X509KeyPair([]byte(cp.CertPEM), []byte(cp.KeyPEM))
		if err != nil {
			log.Printf("[certsync] warning: failed to parse cert for %s: %v", cp.Domain, err)
			continue
		}
		newCerts[cp.Domain] = tlsCert
	}

	cs.mu.Lock()
	cs.certs = newCerts
	cs.lastSync = time.Now()
	cs.lastSyncErr = nil
	cs.syncedCount = len(newCerts)
	cs.mu.Unlock()

	return nil
}

// GetCertificate implements tls.Config.GetCertificate for SNI-based lookup.
// Priority: exact domain match → wildcard match → self-signed fallback.
func (cs *CertStore) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	serverName := hello.ServerName

	// 1. Exact match
	if cert, ok := cs.certs[serverName]; ok {
		return &cert, nil
	}

	// 2. Wildcard match: for "foo.example.com", try "*.example.com"
	if idx := strings.IndexByte(serverName, '.'); idx >= 0 {
		wildcard := "*" + serverName[idx:]
		if cert, ok := cs.certs[wildcard]; ok {
			return &cert, nil
		}
	}

	// 3. Fallback to self-signed
	return &cs.fallback, nil
}

// RunSyncLoop periodically syncs certificates from the backend.
// Blocks until ctx is cancelled.
func (cs *CertStore) RunSyncLoop(ctx context.Context, backendIP string, httpPort int, interval time.Duration) {
	log.Printf("[certsync] starting sync loop (backend=%s:%d, interval=%s)", backendIP, httpPort, interval)

	// Initial sync attempt
	if err := cs.Sync(backendIP, httpPort); err != nil {
		log.Printf("[certsync] initial sync failed (will retry): %v", err)
	} else {
		cs.mu.RLock()
		count := cs.syncedCount
		cs.mu.RUnlock()
		log.Printf("[certsync] initial sync OK: %d certificates", count)
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("[certsync] sync loop stopped")
			return
		case <-ticker.C:
			if err := cs.Sync(backendIP, httpPort); err != nil {
				log.Printf("[certsync] sync failed: %v", err)
			} else {
				cs.mu.RLock()
				count := cs.syncedCount
				cs.mu.RUnlock()
				log.Printf("[certsync] sync OK: %d certificates", count)
			}
		}
	}
}

// LastSync returns the time of the last successful sync.
func (cs *CertStore) LastSync() time.Time {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cs.lastSync
}

// LastSyncErr returns the error from the last sync attempt, or nil.
func (cs *CertStore) LastSyncErr() error {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cs.lastSyncErr
}

// SyncedCount returns the number of certificates currently synced.
func (cs *CertStore) SyncedCount() int {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cs.syncedCount
}

// HasSyncedCerts returns true if at least one real certificate has been synced.
func (cs *CertStore) HasSyncedCerts() bool {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cs.syncedCount > 0
}
