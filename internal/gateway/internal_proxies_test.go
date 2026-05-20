package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/auth"
)

// Phase 1.10 — /grafana/, /alertmanager/, /guacamole/ reverse
// proxies must require a valid JWT before forwarding. Each
// backend still enforces its own login, but the daemon's token
// is the floor of trust regardless. Audit finding A-MED-6.

const proxyTestSecret = "a-secret-that-is-at-least-32-bytes-long!!"

// newProxyTestGateway builds a GatewayServer with all three
// internal proxies pointing at a single recording backend. The
// backend records every Path it actually receives so we can
// assert auth gating (no record means the auth layer rejected
// the request before forwarding).
func newProxyTestGateway(t *testing.T) (*GatewayServer, *recordingBackend, string) {
	t.Helper()
	backend := &recordingBackend{
		srv: httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Capture the path the backend saw.
			backendPath = r.URL.Path
			_, _ = io.WriteString(w, "backend-ok:"+r.URL.Path)
		})),
	}
	t.Cleanup(backend.srv.Close)

	tm, err := auth.NewTokenManager(proxyTestSecret, "containarium")
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	tok, err := tm.GenerateToken("alice", []string{"admin"}, time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	gs := &GatewayServer{
		authMiddleware:         auth.NewAuthMiddleware(tm),
		grafanaBackendURL:      backend.srv.URL,
		alertmanagerBackendURL: backend.srv.URL,
		guacamoleBackendURL:    backend.srv.URL,
	}
	return gs, backend, tok
}

type recordingBackend struct {
	srv *httptest.Server
}

// backendPath is set by the test backend on every request. The
// helper resets it between cases.
var backendPath string

// buildProxyMux wires the three reverse proxies onto a fresh mux
// using the same code path Start() uses. Extracted so tests
// don't need to spin up the full HTTP server.
func buildProxyMux(t *testing.T, gs *GatewayServer) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mountInternalProxies(mux, gs)
	return mux
}

func TestInternalProxies_RejectUnauthenticated(t *testing.T) {
	gs, _, _ := newProxyTestGateway(t)
	mux := buildProxyMux(t, gs)

	for _, path := range []string{"/grafana/", "/alertmanager/", "/guacamole/"} {
		t.Run(path, func(t *testing.T) {
			backendPath = ""
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", rec.Code)
			}
			if backendPath != "" {
				t.Fatalf("backend reached without auth: saw path %q", backendPath)
			}
		})
	}
}

func TestInternalProxies_ForwardWithValidToken(t *testing.T) {
	gs, _, tok := newProxyTestGateway(t)
	mux := buildProxyMux(t, gs)

	cases := []struct {
		in  string
		out string // path the backend should see (proxies don't strip prefix)
	}{
		{"/grafana/dashboards/home", "/grafana/dashboards/home"},
		{"/alertmanager/api/v2/alerts", "/alertmanager/api/v2/alerts"},
		{"/guacamole/", "/guacamole/"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			backendPath = ""
			req := httptest.NewRequest("GET", tc.in, nil)
			req.Header.Set("Authorization", "Bearer "+tok)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
			}
			if backendPath != tc.out {
				t.Fatalf("backend saw path %q, want %q", backendPath, tc.out)
			}
			if !strings.HasPrefix(rec.Body.String(), "backend-ok:") {
				t.Fatalf("response not from backend: %s", rec.Body.String())
			}
		})
	}
}

func TestInternalProxies_NoSlashRedirectStaysOpen(t *testing.T) {
	// The no-slash → trailing-slash redirect is a plain 301 with no
	// backend access. Leaving it outside the auth wrap lets a
	// browser bounce to the canonical URL without a token before
	// the JWT gate hits.
	gs, _, _ := newProxyTestGateway(t)
	mux := buildProxyMux(t, gs)

	for _, path := range []string{"/grafana", "/alertmanager", "/guacamole"} {
		t.Run(path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
			if rec.Code != http.StatusMovedPermanently {
				t.Fatalf("status = %d, want 301", rec.Code)
			}
			loc := rec.Header().Get("Location")
			if loc != path+"/" {
				t.Fatalf("Location = %q, want %q", loc, path+"/")
			}
		})
	}
}
