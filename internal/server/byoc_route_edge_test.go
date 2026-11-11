package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/footprintai/containarium/internal/app"
)

func byocDNSChallenge() *app.CaddyACMEChallenges {
	return &app.CaddyACMEChallenges{DNS: &app.CaddyDNSChallenge{Provider: map[string]interface{}{"name": "cloudflare"}}}
}

// routeHostingConfigFrom must carry the BYOC mark to the route family (#2262).
func TestRouteHostingConfigFrom_CarriesBYOCBackend(t *testing.T) {
	for _, byoc := range []bool{false, true} {
		cfg := &DualServerConfig{BaseDomain: "example.com", BYOCBackend: byoc}
		if got := routeHostingConfigFrom(cfg, "http://127.0.0.1:2019").BYOCBackend; got != byoc {
			t.Errorf("BYOCBackend = %v, want %v", got, byoc)
		}
	}
}

// A BYOC backend's Caddy set-up drops a wildcard subject left by a start
// before the host was marked and orders no new one, even with DNS-01 (#2262).
func TestCaddyRouteEdgeSetUp_BYOCDropsWildcardAndOrdersNone(t *testing.T) {
	var mu sync.Mutex
	var patched []string // bodies of PATCH/POST/PUT writes to the policies
	mux := http.NewServeMux()
	mux.HandleFunc("/config/apps/tls", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"automation":{"policies":[{"subjects":["*.example.com"]}]}}`)
	})
	mux.HandleFunc("/config/apps/tls/automation/policies", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = io.WriteString(w, `[{"subjects":["*.example.com"]}]`)
			return
		}
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		patched = append(patched, r.Method+" "+string(b))
		mu.Unlock()
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {}) // other best-effort set-up calls
	srv := httptest.NewServer(mux)
	defer srv.Close()

	proxy := app.NewProxyManager(srv.URL, "example.com").WithDNSChallenge(byocDNSChallenge()).WithoutWildcardTLS()
	edge := &caddyRouteEdge{
		cfg:   routeHostingConfig{CaddyAdminURL: srv.URL, BaseDomain: "example.com", BYOCBackend: true},
		proxy: proxy,
		l4:    app.NewL4ProxyManager(srv.URL),
		logf:  t.Logf,
	}
	edge.setUp()

	mu.Lock()
	defer mu.Unlock()
	if len(patched) != 1 || !strings.HasPrefix(patched[0], "PATCH ") {
		t.Fatalf("expected exactly one PATCH removing the wildcard subject, got %v", patched)
	}
	if strings.Contains(patched[0], "*.example.com") {
		t.Errorf("the PATCH still carries the wildcard subject: %s", patched[0])
	}
}
