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

// CertStore holds TLS certificates synced from the backends (Caddy/Let's
// Encrypt) and provides SNI-based lookup with a self-signed fallback.
//
// Each backend has its own certificate set. A sync from a backend replaces
// only that backend's set, and keeps only certificates for domains inside
// the backend's CertScope; the rest are dropped and counted per backend
// (sentinel_cert_sync_rejected_total). The served map merges the sets as
// described on rebuildLocked.
type CertStore struct {
	mu       sync.RWMutex
	sets     map[string]backendCertSet  // backend ID → its accepted certs
	certs    map[string]tls.Certificate // merged: domain → served cert
	rejected map[string]uint64          // backend ID → certs dropped by scope
	// dropGen counts DropBackend calls per backend, so a sync that was
	// already in flight when its backend was dropped does not put the
	// backend's set back.
	dropGen  map[string]uint64
	fallback tls.Certificate // self-signed fallback

	// scopeFor resolves a backend ID to the domains it is registered
	// for. Nil means no backend is registered for anything.
	scopeFor func(backendID string) CertScope

	lastSync    time.Time
	lastSyncErr error
	syncedCount int
}

// backendCertSet is one backend's accepted certificates and the scope they
// were accepted under.
type backendCertSet struct {
	scope CertScope
	certs map[string]tls.Certificate
}

// NewCertStore creates a CertStore with a self-signed fallback certificate.
func NewCertStore() *CertStore {
	fallback, err := generateSelfSignedCert()
	if err != nil {
		log.Printf("[certsync] warning: failed to generate fallback cert: %v", err)
	}
	return &CertStore{
		sets:     make(map[string]backendCertSet),
		certs:    make(map[string]tls.Certificate),
		rejected: make(map[string]uint64),
		dropGen:  make(map[string]uint64),
		fallback: fallback,
	}
}

// SetScopeResolver sets the function that maps a backend ID to the domains
// it is registered for. Call before the first Sync.
func (cs *CertStore) SetScopeResolver(fn func(backendID string) CertScope) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.scopeFor = fn
}

func (cs *CertStore) scopeOf(backendID string) CertScope {
	cs.mu.RLock()
	fn := cs.scopeFor
	cs.mu.RUnlock()
	if fn == nil {
		return CertScope{}
	}
	return fn(backendID)
}

// Sync fetches certificates from backendID's /certs endpoint and replaces
// that backend's set with the ones inside its registered domains. An empty
// or malformed response, or one with nothing inside the backend's domains,
// leaves the store unchanged.
func (cs *CertStore) Sync(backendID, backendIP string, httpPort int) error {
	cs.mu.RLock()
	gen := cs.dropGen[backendID]
	cs.mu.RUnlock()

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

	// An empty response never replaces the store. A backend whose Caddy
	// has not issued anything yet (or whose cert dir is missing) answers
	// with an empty list; treating that as "serve nothing" would drop every
	// certificate the sentinel already holds until the next sync. It is
	// not a failure either, so the store is left exactly as it was.
	if len(certsResp.Certs) == 0 {
		log.Printf("[certsync] %s returned no certificates; keeping the %d already held", url, cs.SyncedCount())
		return nil
	}

	scope := cs.scopeOf(backendID)
	newCerts := make(map[string]tls.Certificate, len(certsResp.Certs))
	parsed, rejected := 0, 0
	for _, cp := range certsResp.Certs {
		tlsCert, err := tls.X509KeyPair([]byte(cp.CertPEM), []byte(cp.KeyPEM))
		if err != nil {
			log.Printf("[certsync] warning: failed to parse cert for %s: %v", cp.Domain, err)
			continue
		}
		parsed++
		domain := strings.ToLower(cp.Domain)
		if scope.match(domain) == 0 {
			rejected++
			log.Printf("[certsync] backend %s sent a certificate for %q, which is not among its registered domains; dropped", backendID, cp.Domain)
			continue
		}
		newCerts[domain] = tlsCert
	}
	if rejected > 0 {
		cs.mu.Lock()
		if cs.dropGen[backendID] == gen {
			cs.rejected[backendID] += uint64(rejected)
		}
		cs.mu.Unlock()
	}

	// Entries were sent but none parsed: the response is malformed, and
	// like a decode error it leaves the store untouched.
	if parsed == 0 {
		err := fmt.Errorf("cert sync: none of the %d certificates from %s parsed", len(certsResp.Certs), url)
		cs.mu.Lock()
		cs.lastSyncErr = err
		cs.mu.Unlock()
		return err
	}
	// Every parsed entry was outside the backend's domains: keep its
	// previous set rather than emptying it.
	if len(newCerts) == 0 {
		err := fmt.Errorf("cert sync: all %d certificates from backend %s are outside its registered domains", rejected, backendID)
		if scope.Empty() {
			err = fmt.Errorf("cert sync: backend %s has no registered domains, so none of its %d certificates are served", backendID, rejected)
		}
		cs.mu.Lock()
		cs.lastSyncErr = err
		cs.mu.Unlock()
		return err
	}

	cs.mu.Lock()
	if cs.dropGen[backendID] != gen {
		cs.mu.Unlock()
		log.Printf("[certsync] backend %s was removed during its sync; discarding the result", backendID)
		return nil
	}
	cs.sets[backendID] = backendCertSet{scope: scope, certs: newCerts}
	cs.rebuildLocked()
	cs.lastSync = time.Now()
	cs.lastSyncErr = nil
	cs.mu.Unlock()

	return nil
}

// DropBackend removes backendID's certificate set, e.g. when its tunnel
// disconnects. Domains it supplied fall back to the next-ranked backend's
// certificate, or to the self-signed fallback. Its rejection series is
// removed too, so /metrics carries series only for current backends.
func (cs *CertStore) DropBackend(backendID string) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.dropGen[backendID]++
	delete(cs.rejected, backendID)
	if _, ok := cs.sets[backendID]; !ok {
		return
	}
	delete(cs.sets, backendID)
	cs.rebuildLocked()
}

// rebuildLocked recomputes the served map from the per-backend sets. For
// each domain, the backend whose scope matches it most strongly is served
// (see CertScope.match): a hostname or alias beats a base domain, and a
// longer base domain beats a shorter one. When the strongest match is held
// by two or more backends, the domain is served by none of them. Caller
// holds cs.mu.
func (cs *CertStore) rebuildLocked() {
	type candidate struct {
		cert     tls.Certificate
		strength int
		tied     bool
	}
	best := make(map[string]candidate)
	for _, set := range cs.sets {
		for domain, cert := range set.certs {
			strength := set.scope.match(domain)
			cur, ok := best[domain]
			switch {
			case !ok || strength > cur.strength:
				best[domain] = candidate{cert: cert, strength: strength}
			case strength == cur.strength:
				cur.tied = true
				best[domain] = cur
			}
		}
	}
	merged := make(map[string]tls.Certificate, len(best))
	for domain, c := range best {
		if c.tied {
			log.Printf("[certsync] %q is supplied by more than one backend with equal precedence; serving none of them", domain)
			continue
		}
		merged[domain] = c.cert
	}
	cs.certs = merged
	cs.syncedCount = len(merged)
}

// RejectedCounts returns, per backend ID, how many certificates have been
// dropped because they named a domain outside that backend's scope.
func (cs *CertStore) RejectedCounts() map[string]uint64 {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	out := make(map[string]uint64, len(cs.rejected))
	for id, n := range cs.rejected {
		out[id] = n
	}
	return out
}

// GetCertificate implements tls.Config.GetCertificate for SNI-based lookup.
// Priority: exact domain match → wildcard match → self-signed fallback.
func (cs *CertStore) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	serverName := strings.ToLower(hello.ServerName)

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
//
// A failed attempt is retried on the fast-retry schedule before falling
// back to the interval. This loop is the reason that schedule exists: at a
// 6h interval, one transient failure used to mean stale certificates for
// most of a day (#953).
func (cs *CertStore) RunSyncLoop(ctx context.Context, backendID, backendIP string, httpPort int, interval time.Duration) {
	log.Printf("[certsync] starting sync loop (backend=%s at %s:%d, interval=%s)", backendID, backendIP, httpPort, interval)

	runSyncLoop(ctx, "certsync", interval, syncRetryDelays(interval), func() error {
		if err := cs.Sync(backendID, backendIP, httpPort); err != nil {
			log.Printf("[certsync] sync failed: %v", err)
			return err
		}
		cs.mu.RLock()
		count := cs.syncedCount
		cs.mu.RUnlock()
		log.Printf("[certsync] sync OK from %s: %d certificates served", backendID, count)
		return nil
	})

	log.Printf("[certsync] sync loop stopped")
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
