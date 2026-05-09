package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// L4ServerName is the Caddy L4 server name for TLS passthrough routing
const L4ServerName = "tls_passthrough"

// l4HTTPFallbackListen is the listen address the HTTP server moves to when L4 is active.
// L4 takes over :443 and proxies non-matching SNI to this address.
const l4HTTPFallbackListen = ":8443"

// l4HTTPFallbackDial is the dial address L4 uses to reach the HTTP server fallback.
const l4HTTPFallbackDial = "localhost:8443"

// L4Route represents a TLS passthrough route (our domain model)
type L4Route struct {
	SNI          string `json:"sni"`
	UpstreamIP   string `json:"upstream_ip"`
	UpstreamPort int    `json:"upstream_port"`
}

// L4ProxyManager manages Caddy L4 (TLS passthrough) routes via the admin API.
// L4 is activated lazily — only when TLS passthrough routes exist in the database.
// Activation uses Caddy's /load endpoint for atomic config replacement.
type L4ProxyManager struct {
	caddyAdminURL string
	httpClient    *http.Client
}

// NewL4ProxyManager creates a new L4 proxy manager.
func NewL4ProxyManager(caddyAdminURL string) *L4ProxyManager {
	return &L4ProxyManager{
		caddyAdminURL: caddyAdminURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// IsL4Active checks if the L4 layer4 app is configured in Caddy
// by looking for the specific tls_passthrough server.
func (m *L4ProxyManager) IsL4Active() bool {
	url := fmt.Sprintf("%s/config/apps/layer4/servers/%s", m.caddyAdminURL, L4ServerName)
	resp, err := m.httpClient.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	body, _ := io.ReadAll(resp.Body)
	trimmed := strings.TrimSpace(string(body))
	return len(trimmed) > 0 && trimmed != "null"
}

// ActivateL4 atomically activates L4 SNI routing on :443.
//
// It reads the full Caddy config, moves the HTTP server from :443 to :8443
// (with tls_connection_policies for TLS on non-standard port), creates the
// L4 app on :443 with a catch-all route that proxies to localhost:8443,
// and atomically applies the config via POST /load.
//
// This is idempotent — if L4 is already active, it returns nil.
func (m *L4ProxyManager) ActivateL4() error {
	if m.IsL4Active() {
		return nil
	}

	config, err := m.getFullConfig()
	if err != nil {
		return fmt.Errorf("failed to get full config: %w", err)
	}

	apps := getMapField(config, "apps")
	if apps == nil {
		return fmt.Errorf("no apps in config")
	}

	// Modify HTTP server: change :443 to :8443 and add tls_connection_policies
	if err := m.moveHTTPServerOff443(apps); err != nil {
		return fmt.Errorf("failed to modify HTTP server: %w", err)
	}

	// Create L4 app with catch-all route to HTTP server
	apps["layer4"] = map[string]interface{}{
		"servers": map[string]interface{}{
			L4ServerName: map[string]interface{}{
				"listen": []interface{}{":443"},
				"routes": []interface{}{
					// Catch-all (no match): proxy to HTTP server on :8443
					map[string]interface{}{
						"handle": []interface{}{
							map[string]interface{}{
								"handler": "proxy",
								"upstreams": []interface{}{
									map[string]interface{}{
										"dial": []interface{}{l4HTTPFallbackDial},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	if err := m.loadConfig(config); err != nil {
		return fmt.Errorf("failed to load config with L4: %w", err)
	}

	log.Printf("[L4ProxyManager] Activated: HTTP moved to %s, L4 owns :443", l4HTTPFallbackListen)
	return nil
}

// DeactivateL4 atomically deactivates L4 routing, restoring HTTP server to :443.
//
// This is idempotent — if L4 is not active, it returns nil.
func (m *L4ProxyManager) DeactivateL4() error {
	if !m.IsL4Active() {
		return nil
	}

	config, err := m.getFullConfig()
	if err != nil {
		return fmt.Errorf("failed to get full config: %w", err)
	}

	apps := getMapField(config, "apps")
	if apps == nil {
		return nil
	}

	// Remove L4 app
	delete(apps, "layer4")

	// Restore HTTP server: change :8443 back to :443 and remove tls_connection_policies
	m.moveHTTPServerTo443(apps)

	if err := m.loadConfig(config); err != nil {
		return fmt.Errorf("failed to load config without L4: %w", err)
	}

	log.Printf("[L4ProxyManager] Deactivated: HTTP restored to :443")
	return nil
}

// EnableL4ProxyProtocol restructures the L4 server to handle a PROXY v2
// header at the front of incoming connections. caddy-l4 has no server-level
// listener_wrappers field (HTTP-only API), so the canonical pattern is:
//
//   - Wrap existing routes inside a subroute under a top-level route whose
//     match list contains the `proxy_protocol` matcher. The matcher consumes
//     the PROXY header from the connection during match phase, so subsequent
//     SNI matchers in the subroute see the underlying TLS bytes cleanly.
//   - Tag every proxy handler with `proxy_protocol: "v2"` so caddy-l4
//     re-emits a PROXY v2 header to its upstream (srv0 or gRPC LXCs)
//     carrying the parsed real client IP.
//   - Add a fallback top-level route with the same routes WITHOUT
//     proxy_protocol emission, so that connections WITHOUT a PROXY header
//     (the sentinel hasn't been flipped yet, or some other direct caller)
//     keep flowing as before. After the sentinel flag flips, the fallback
//     becomes dead code; before it flips, the fallback prevents a deploy-gap
//     outage.
//
// trustedCIDRs is recorded for symmetry with the HTTP-side wrapper but is
// only used by the matcher's allow-list once we add it.
//
// Idempotent: if the outer wrapper is already in place (first route's match
// contains proxy_protocol), this is a no-op. If L4 is not active at all,
// this returns nil silently — RouteSyncJob will activate L4 with passthrough
// routes later, and the daemon should be restarted to re-apply on activation.
func (m *L4ProxyManager) EnableL4ProxyProtocol(trustedCIDRs []string) error {
	if len(trustedCIDRs) == 0 {
		return fmt.Errorf("EnableL4ProxyProtocol: trustedCIDRs must not be empty")
	}
	for _, c := range trustedCIDRs {
		if c == "0.0.0.0/0" || c == "::/0" {
			return fmt.Errorf("EnableL4ProxyProtocol: refusing wildcard CIDR %q", c)
		}
	}

	if !m.IsL4Active() {
		log.Printf("[L4ProxyManager] PROXY protocol requested but L4 not active — will apply when L4 activates")
		return nil
	}

	config, err := m.getFullConfig()
	if err != nil {
		return fmt.Errorf("get full config: %w", err)
	}
	apps := getMapField(config, "apps")
	layer4 := getMapField(apps, "layer4")
	servers := getMapField(layer4, "servers")
	srv := getMapField(servers, L4ServerName)
	if srv == nil {
		return fmt.Errorf("L4 server %q missing from config", L4ServerName)
	}

	routes, _ := srv["routes"].([]interface{})
	if len(routes) == 0 {
		return fmt.Errorf("L4 server has no routes")
	}

	// Idempotency: if the first route already matches on proxy_protocol, skip.
	if first, ok := routes[0].(map[string]interface{}); ok {
		if isProxyProtocolMatchRoute(first) {
			log.Printf("[L4ProxyManager] PROXY protocol already enabled on L4 — no change")
			return nil
		}
	}

	// Build proxy-protocol-aware copies of the routes (same matchers, but
	// each proxy handler gains proxy_protocol: "v2" for outbound emission).
	proxyAware := make([]interface{}, 0, len(routes))
	for _, r := range routes {
		copyRoute := deepCopyRoute(r)
		tagProxyHandlersV2(copyRoute)
		proxyAware = append(proxyAware, copyRoute)
	}

	wrappedRoutes := []interface{}{
		// Outer route 1: PROXY-bearing connections.
		map[string]interface{}{
			"match": []interface{}{
				map[string]interface{}{"proxy_protocol": map[string]interface{}{}},
			},
			"handle": []interface{}{
				map[string]interface{}{
					"handler": "subroute",
					"routes":  proxyAware,
				},
			},
		},
		// Outer route 2: fallback for connections without a PROXY header.
		// Mirrors the original routes verbatim so existing behavior is
		// preserved during the deploy gap (daemon flipped, sentinel still
		// sending raw TCP). Once the sentinel flips, this route is dead code.
		map[string]interface{}{
			"handle": []interface{}{
				map[string]interface{}{
					"handler": "subroute",
					"routes":  routes, // original references, no proxy_protocol emission
				},
			},
		},
	}
	srv["routes"] = wrappedRoutes

	if err := m.loadConfig(config); err != nil {
		return fmt.Errorf("load L4 config with proxy_protocol: %w", err)
	}

	log.Printf("[L4ProxyManager] PROXY protocol enabled: %d routes wrapped in proxy_protocol-matched subroute (with non-PROXY fallback), trusted=%v", len(proxyAware), trustedCIDRs)
	return nil
}

// isProxyProtocolMatchRoute reports whether a route's match list contains the
// proxy_protocol matcher (used to detect "already wrapped" state).
func isProxyProtocolMatchRoute(route map[string]interface{}) bool {
	matches, ok := route["match"].([]interface{})
	if !ok {
		return false
	}
	for _, m := range matches {
		mm, ok := m.(map[string]interface{})
		if !ok {
			continue
		}
		if _, hasPP := mm["proxy_protocol"]; hasPP {
			return true
		}
	}
	return false
}

// deepCopyRoute returns a JSON-roundtripped clone of a route so subsequent
// mutations don't alias the original (used to keep the "proxy-aware" copy
// independent from the fallback copy).
func deepCopyRoute(r interface{}) map[string]interface{} {
	b, _ := json.Marshal(r)
	var out map[string]interface{}
	_ = json.Unmarshal(b, &out)
	return out
}

// tagProxyHandlersV2 walks a route and adds proxy_protocol: "v2" to any
// `proxy` handler. It also recurses into `subroute` handlers' nested routes.
func tagProxyHandlersV2(route map[string]interface{}) {
	handlers, _ := route["handle"].([]interface{})
	for _, h := range handlers {
		handler, ok := h.(map[string]interface{})
		if !ok {
			continue
		}
		switch handler["handler"] {
		case "proxy":
			handler["proxy_protocol"] = "v2"
		case "subroute":
			nested, _ := handler["routes"].([]interface{})
			for _, nr := range nested {
				if nrm, ok := nr.(map[string]interface{}); ok {
					tagProxyHandlersV2(nrm)
				}
			}
		}
	}
}

// toAnySlice converts a []string to []interface{} for embedding in raw config maps.
func toAnySlice(in []string) []interface{} {
	out := make([]interface{}, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}

// AddL4Route adds an SNI-based TLS passthrough route.
// The route is inserted before the catch-all (last) route.
// L4 must be active (call ActivateL4 first).
func (m *L4ProxyManager) AddL4Route(sni, upstreamIP string, port int) error {
	// Remove existing route for this SNI first (idempotent)
	m.RemoveL4Route(sni)

	route := CaddyL4Route{
		Match: []CaddyL4Match{
			{TLS: &CaddyL4TLSMatch{SNI: []string{sni}}},
		},
		Handle: []CaddyL4Handler{
			{
				Handler: "proxy",
				Upstreams: []CaddyL4Upstream{
					{Dial: []string{fmt.Sprintf("%s:%d", upstreamIP, port)}},
				},
			},
		},
	}

	// Get current routes, insert before catch-all, PUT entire array
	routes, err := m.getRoutes()
	if err != nil {
		return fmt.Errorf("failed to get L4 routes: %w", err)
	}

	// Insert before the last route (catch-all)
	if len(routes) > 0 {
		catchAll := routes[len(routes)-1]
		routes = append(routes[:len(routes)-1], route, catchAll)
	} else {
		routes = append(routes, route)
	}

	return m.putRoutes(routes)
}

// RemoveL4Route removes the TLS passthrough route for the given SNI hostname.
func (m *L4ProxyManager) RemoveL4Route(sni string) error {
	routes, err := m.getRoutes()
	if err != nil {
		return fmt.Errorf("failed to get L4 routes: %w", err)
	}

	newRoutes := make([]CaddyL4Route, 0, len(routes))
	found := false
	for _, r := range routes {
		if m.routeMatchesSNI(r, sni) {
			found = true
		} else {
			newRoutes = append(newRoutes, r)
		}
	}

	if !found {
		return nil // not found, already removed (idempotent)
	}

	return m.putRoutes(newRoutes)
}

// ListL4Routes returns all configured TLS passthrough routes (excludes the catch-all).
func (m *L4ProxyManager) ListL4Routes() ([]L4Route, error) {
	routes, err := m.getRoutes()
	if err != nil {
		return nil, err
	}

	var l4Routes []L4Route
	for _, route := range routes {
		// Skip catch-all routes (no match conditions)
		if len(route.Match) == 0 {
			continue
		}

		l4Route := L4Route{}

		// Extract SNI
		if len(route.Match) > 0 && route.Match[0].TLS != nil && len(route.Match[0].TLS.SNI) > 0 {
			l4Route.SNI = route.Match[0].TLS.SNI[0]
		}

		// Extract upstream
		if len(route.Handle) > 0 && len(route.Handle[0].Upstreams) > 0 && len(route.Handle[0].Upstreams[0].Dial) > 0 {
			dial := route.Handle[0].Upstreams[0].Dial[0]
			l4Route.UpstreamIP, l4Route.UpstreamPort = parseDial(dial)
		}

		if l4Route.SNI != "" {
			l4Routes = append(l4Routes, l4Route)
		}
	}

	return l4Routes, nil
}

// --- Internal helpers ---

// getRoutes fetches the current L4 routes from Caddy.
func (m *L4ProxyManager) getRoutes() ([]CaddyL4Route, error) {
	url := fmt.Sprintf("%s/config/apps/layer4/servers/%s/routes", m.caddyAdminURL, L4ServerName)
	resp, err := m.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to get L4 routes: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("caddy returned error (status %d): %s", resp.StatusCode, string(body))
	}

	var routes []CaddyL4Route
	if err := json.NewDecoder(resp.Body).Decode(&routes); err != nil {
		return nil, fmt.Errorf("failed to decode L4 routes: %w", err)
	}

	return routes, nil
}

// putRoutes replaces all L4 routes via PATCH (Caddy returns 409 on PUT for existing keys).
func (m *L4ProxyManager) putRoutes(routes []CaddyL4Route) error {
	routesJSON, err := json.Marshal(routes)
	if err != nil {
		return fmt.Errorf("failed to marshal routes: %w", err)
	}

	url := fmt.Sprintf("%s/config/apps/layer4/servers/%s/routes", m.caddyAdminURL, L4ServerName)
	req, err := http.NewRequest("PATCH", url, bytes.NewReader(routesJSON))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to patch routes: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("caddy error (status %d): %s", resp.StatusCode, string(body))
	}

	return nil
}

// routeMatchesSNI checks if a route matches the given SNI hostname.
func (m *L4ProxyManager) routeMatchesSNI(route CaddyL4Route, sni string) bool {
	for _, match := range route.Match {
		if match.TLS != nil {
			for _, s := range match.TLS.SNI {
				if s == sni {
					return true
				}
			}
		}
	}
	return false
}

// getFullConfig reads the complete Caddy config as raw JSON.
func (m *L4ProxyManager) getFullConfig() (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/config/", m.caddyAdminURL)
	resp, err := m.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to get config: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}

	var config map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to decode config: %w", err)
	}
	return config, nil
}

// loadConfig atomically applies a complete config via POST /load.
func (m *L4ProxyManager) loadConfig(config map[string]interface{}) error {
	configJSON, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	url := fmt.Sprintf("%s/load", m.caddyAdminURL)
	resp, err := m.httpClient.Post(url, "application/json", bytes.NewReader(configJSON))
	if err != nil {
		return fmt.Errorf("failed to POST /load: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("load failed (status %d): %s", resp.StatusCode, string(body))
	}

	return nil
}

// moveHTTPServerOff443 changes the HTTP server from :443 to :8443 and adds tls_connection_policies.
func (m *L4ProxyManager) moveHTTPServerOff443(apps map[string]interface{}) error {
	httpApp := getMapField(apps, "http")
	if httpApp == nil {
		return fmt.Errorf("no http app")
	}

	servers := getMapField(httpApp, "servers")
	if servers == nil {
		return fmt.Errorf("no servers in http app")
	}

	for name, v := range servers {
		srv, ok := v.(map[string]interface{})
		if !ok {
			continue
		}

		listen, _ := srv["listen"].([]interface{})
		newListen := make([]interface{}, 0, len(listen))
		has443 := false
		for _, l := range listen {
			ls, _ := l.(string)
			if ls == ":443" {
				newListen = append(newListen, l4HTTPFallbackListen)
				has443 = true
			} else {
				newListen = append(newListen, l)
			}
		}

		if has443 {
			srv["listen"] = newListen
			// Enable TLS on the non-standard port
			srv["tls_connection_policies"] = []interface{}{map[string]interface{}{}}
			log.Printf("[L4ProxyManager] HTTP server %q: listen changed to %v", name, newListen)
		}
	}

	return nil
}

// moveHTTPServerTo443 restores the HTTP server from :8443 to :443.
func (m *L4ProxyManager) moveHTTPServerTo443(apps map[string]interface{}) {
	httpApp := getMapField(apps, "http")
	if httpApp == nil {
		return
	}

	servers := getMapField(httpApp, "servers")
	if servers == nil {
		return
	}

	for _, v := range servers {
		srv, ok := v.(map[string]interface{})
		if !ok {
			continue
		}

		listen, _ := srv["listen"].([]interface{})
		newListen := make([]interface{}, 0, len(listen))
		for _, l := range listen {
			ls, _ := l.(string)
			if ls == l4HTTPFallbackListen {
				newListen = append(newListen, ":443")
			} else {
				newListen = append(newListen, l)
			}
		}
		srv["listen"] = newListen

		// Remove tls_connection_policies (auto-HTTPS handles TLS on :443)
		delete(srv, "tls_connection_policies")
	}
}

// getMapField safely gets a nested map[string]interface{} from a parent map.
func getMapField(m map[string]interface{}, key string) map[string]interface{} {
	v, _ := m[key].(map[string]interface{})
	return v
}

// parseDial parses "ip:port" into separate IP and port values.
func parseDial(dial string) (string, int) {
	for i := len(dial) - 1; i >= 0; i-- {
		if dial[i] == ':' {
			ip := dial[:i]
			port := 0
			for _, c := range dial[i+1:] {
				port = port*10 + int(c-'0')
			}
			return ip, port
		}
	}
	return dial, 0
}
