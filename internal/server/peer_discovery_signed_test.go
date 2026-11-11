package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/config"
)

const discoverySignSecret = "abcdefghijklmnopqrstuvwxyz0123456789ABCD"

// setDiscoverySecret points the cached daemon secret at v for one test.
func setDiscoverySecret(t *testing.T, v string) {
	t.Helper()
	t.Setenv(config.EnvSentinelAuthSecret, v)
	reset := func() { sentinelHMACSecretOnce = sync.Once{}; sentinelHMACSecret = nil }
	reset()
	t.Cleanup(reset)
}

// #3119: the sentinel only returns pool tags to a signed caller, so discovery
// must sign its request and still end up placing peers by pool.
func TestPeerPoolDiscoverySignsRequestAndKeepsPool(t *testing.T) {
	setDiscoverySecret(t, discoverySignSecret)
	// The handler runs on the httptest server's goroutine; guard what the
	// test goroutine reads back (#3192).
	var (
		mu        sync.Mutex
		verifyErr error
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// discover() also fires background peer-info refreshes at the
		// discovered peer's proxy path on this same server; those are
		// unsigned by design and must not overwrite the discovery verdict.
		if r.URL.Path != "/sentinel/peers" {
			http.NotFound(w, r)
			return
		}
		err := auth.VerifySentinelRequest(r, []byte(discoverySignSecret), time.Now())
		mu.Lock()
		verifyErr = err
		mu.Unlock()
		peer := map[string]any{"id": "tunnel-x", "proxy_path": "/peer/tunnel-x", "healthy": true}
		if err == nil {
			peer["pool"] = "demo" // what the real sentinel does for signed callers
		}
		body, _ := json.Marshal(map[string]any{"peers": []any{peer}})
		auth.SignSentinelResponse(w, []byte(discoverySignSecret), body)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	p := NewPeerPool("local", srv.URL, nil, "")
	p.discover()

	mu.Lock()
	gotErr := verifyErr
	mu.Unlock()
	if gotErr != nil {
		t.Fatalf("discovery request was not validly signed: %v", gotErr)
	}
	if got := p.HealthyPeersInPool("demo"); len(got) != 1 || got[0].ID != "tunnel-x" {
		t.Fatalf("pool placement lost: %+v", got)
	}
}

func TestPeerPoolDiscoveryWithoutSecretSendsNoSignature(t *testing.T) {
	setDiscoverySecret(t, "")
	var (
		mu  sync.Mutex
		hdr string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hdr = r.Header.Get(auth.SentinelHeaderSignature)
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"peers": []any{}})
	}))
	defer srv.Close()
	NewPeerPool("local", srv.URL, nil, "").discover()
	mu.Lock()
	defer mu.Unlock()
	if hdr != "" {
		t.Fatalf("unexpected signature header without a secret: %q", hdr)
	}
}
