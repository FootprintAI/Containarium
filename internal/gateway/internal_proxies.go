package gateway

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
)

// mountInternalProxies wires the Grafana, Alertmanager, and
// Guacamole reverse proxies onto `mux`, gated by the gateway's
// JWT middleware.
//
// Previously each backend was mounted with the comment "no auth —
// <backend> handles its own". Audit finding A-MED-6 noted that
// this is a defense-in-depth gap: each backend's own login is
// configured for the backend's domain model (e.g. Grafana
// dashboards), not for tenant identity, so a leaked internal IP
// gives a network attacker direct access to operator dashboards.
// The daemon's JWT is now the floor of trust regardless of what
// the backend itself enforces.
//
// Browser-side: the web UI injects the Authorization header
// before navigating to these paths (existing pattern for the rest
// of /v1/*). Guacamole's WebSocket-based RDP transport uses the
// same Authorization header during the HTTP Upgrade, which the
// JWT middleware sees before the handshake completes.
//
// Redirect handlers (no slash → trailing slash) stay outside the
// auth wrap because they're plain 301s with no backend access;
// the trailing-slash path then goes through auth on the next
// request.
//
// Extracted into its own function so the wiring is testable
// without spinning up the full HTTP server (see
// internal_proxies_test.go).
func mountInternalProxies(mux *http.ServeMux, gs *GatewayServer) {
	proxies := []struct {
		name       string
		backendURL string
		prefix     string
	}{
		{"Grafana", gs.grafanaBackendURL, "/grafana"},
		{"Alertmanager", gs.alertmanagerBackendURL, "/alertmanager"},
		{"Guacamole", gs.guacamoleBackendURL, "/guacamole"},
	}

	for _, p := range proxies {
		if p.backendURL == "" {
			continue
		}
		target, err := url.Parse(p.backendURL)
		if err != nil {
			log.Printf("Warning: Invalid %s backend URL %q: %v", p.name, p.backendURL, err)
			continue
		}
		rp := httputil.NewSingleHostReverseProxy(target)
		mux.Handle(p.prefix+"/", gs.authMiddleware.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rp.ServeHTTP(w, r)
		})))
		// Redirect /<name> → /<name>/ outside auth.
		prefix := p.prefix
		mux.HandleFunc(prefix, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, prefix+"/", http.StatusMovedPermanently)
		})
		log.Printf("%s reverse proxy enabled (JWT-gated) at %s/ -> %s", p.name, p.prefix, p.backendURL)
	}
}
