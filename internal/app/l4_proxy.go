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
//
// When proxyProtocolTrusted is non-empty, the L4 server is structured per the
// sandbox-tier-1-verified pattern B: a single outer route whose handlers are
// (proxy_protocol, subroute), with the catchall inside the subroute tagged
// with proxy_protocol: "v2" so caddy-l4 emits a PROXY header to srv0. SNI
// passthrough routes live inside the subroute too — getRoutes/putRoutes
// detect the wrapping and operate on the inner route list, so the existing
// AddL4Route / RemoveL4Route / ListL4Routes flows continue to work without
// changes.
type L4ProxyManager struct {
	caddyAdminURL        string
	httpClient           *http.Client
	proxyProtocolTrusted []string // empty = no PROXY-protocol awareness
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

// SetProxyProtocolTrusted records the CIDRs from which the L4 server will
// accept PROXY v2 headers. Once set, every subsequent ActivateL4 produces the
// wrapped pattern-B shape (and EnableL4ProxyProtocol can re-shape an already
// active server).
//
// trustedSenderCIDRs MUST NOT be empty or wildcard.
func (m *L4ProxyManager) SetProxyProtocolTrusted(trustedSenderCIDRs []string) error {
	if len(trustedSenderCIDRs) == 0 {
		return fmt.Errorf("L4ProxyManager.SetProxyProtocolTrusted: trustedSenderCIDRs must not be empty")
	}
	for _, c := range trustedSenderCIDRs {
		if c == "0.0.0.0/0" || c == "::/0" {
			return fmt.Errorf("L4ProxyManager.SetProxyProtocolTrusted: refusing wildcard CIDR %q", c)
		}
	}
	m.proxyProtocolTrusted = trustedSenderCIDRs
	return nil
}

// proxyProtocolEnabled reports whether the manager has been configured to
// produce the wrapped shape. Used by ActivateL4 + helpers.
func (m *L4ProxyManager) proxyProtocolEnabled() bool {
	return len(m.proxyProtocolTrusted) > 0
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
// When the manager has been configured with proxyProtocolTrusted (via
// SetProxyProtocolTrusted or EnableL4ProxyProtocol), the L4 server is
// produced in the sandbox-tier-1-verified pattern B shape: a single outer
// route whose handlers are (proxy_protocol, subroute), with the catchall
// inside the subroute tagged with `proxy_protocol: "v2"` so caddy-l4
// re-emits a PROXY header to srv0. SNI passthrough routes (added later via
// AddL4Route) live inside the same subroute.
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

	// Create L4 app with the appropriate route shape.
	apps["layer4"] = map[string]interface{}{
		"servers": map[string]interface{}{
			L4ServerName: m.buildL4ServerConfig([]interface{}{m.buildCatchallRoute()}),
		},
	}

	if err := m.loadConfig(config); err != nil {
		return fmt.Errorf("failed to load config with L4: %w", err)
	}

	if m.proxyProtocolEnabled() {
		log.Printf("[L4ProxyManager] Activated (PROXY-aware): HTTP moved to %s, L4 owns :443, allow=%v",
			l4HTTPFallbackListen, m.proxyProtocolTrusted)
	} else {
		log.Printf("[L4ProxyManager] Activated: HTTP moved to %s, L4 owns :443", l4HTTPFallbackListen)
	}
	return nil
}

// buildL4ServerConfig returns an L4 server config map using the supplied
// "effective" inner-route list (i.e. the SNI routes plus catchall in their
// natural order). When proxyProtocolEnabled, wraps them in the pattern B
// outer route. When not, returns the flat (legacy) shape.
func (m *L4ProxyManager) buildL4ServerConfig(innerRoutes []interface{}) map[string]interface{} {
	if !m.proxyProtocolEnabled() {
		return map[string]interface{}{
			"listen": []interface{}{":443"},
			"routes": innerRoutes,
		}
	}
	return map[string]interface{}{
		"listen": []interface{}{":443"},
		"routes": []interface{}{
			map[string]interface{}{
				"handle": []interface{}{
					m.buildProxyProtocolHandler(),
					map[string]interface{}{
						"handler": "subroute",
						"routes":  innerRoutes,
					},
				},
			},
		},
	}
}

// buildCatchallRoute returns the catchall (no-match) route that forwards to
// the HTTP server. When proxyProtocolEnabled, the proxy handler emits a
// PROXY v2 header to srv0 so srv0's listener_wrapper can recover the source.
func (m *L4ProxyManager) buildCatchallRoute() map[string]interface{} {
	handler := map[string]interface{}{
		"handler": "proxy",
		"upstreams": []interface{}{
			map[string]interface{}{"dial": []interface{}{l4HTTPFallbackDial}},
		},
	}
	if m.proxyProtocolEnabled() {
		handler["proxy_protocol"] = "v2"
	}
	return map[string]interface{}{
		"handle": []interface{}{handler},
	}
}

// buildProxyProtocolHandler returns the proxy_protocol layer4 handler that
// consumes the PROXY v2 header from connections in the trusted CIDR list.
func (m *L4ProxyManager) buildProxyProtocolHandler() map[string]interface{} {
	allow := make([]interface{}, len(m.proxyProtocolTrusted))
	for i, c := range m.proxyProtocolTrusted {
		allow[i] = c
	}
	return map[string]interface{}{
		"handler": "proxy_protocol",
		"allow":   allow,
		"timeout": "5s",
	}
}

// EnableL4ProxyProtocol records the trusted PROXY senders on this manager and,
// if L4 is already active in Caddy, re-shapes its routes into the wrapped
// (pattern B) topology atomically. Future ActivateL4 calls (e.g. by
// RouteSyncJob when a passthrough route lands in the DB) will also produce
// the wrapped shape.
//
// Idempotent: a second call with the same CIDRs is a no-op when the L4 server
// is already in wrapped form.
func (m *L4ProxyManager) EnableL4ProxyProtocol(trustedCIDRs []string) error {
	if err := m.SetProxyProtocolTrusted(trustedCIDRs); err != nil {
		return err
	}
	if !m.IsL4Active() {
		log.Printf("[L4ProxyManager] PROXY protocol configured (allow=%v); L4 not active yet, will apply on activation", trustedCIDRs)
		return nil
	}
	return m.reshapeL4()
}

// reshapeL4 reads the current L4 server config, extracts the effective inner
// route list (whether the server is currently wrapped or flat), tags the
// catchall with proxy_protocol: "v2", and writes back the wrapped shape.
func (m *L4ProxyManager) reshapeL4() error {
	config, err := m.getFullConfig()
	if err != nil {
		return fmt.Errorf("get full config: %w", err)
	}
	apps := getMapField(config, "apps")
	layer4 := getMapField(apps, "layer4")
	servers := getMapField(layer4, "servers")
	srv := getMapField(servers, L4ServerName)
	if srv == nil {
		return fmt.Errorf("L4 server %q missing", L4ServerName)
	}
	outerRoutes, _ := srv["routes"].([]interface{})
	innerRoutes := effectiveInnerRoutes(outerRoutes)

	// Tag the catchall (last route, no `match`) with proxy_protocol: "v2".
	if len(innerRoutes) > 0 {
		if last, ok := innerRoutes[len(innerRoutes)-1].(map[string]interface{}); ok {
			if _, hasMatch := last["match"]; !hasMatch {
				if hs, ok := last["handle"].([]interface{}); ok {
					for _, h := range hs {
						if hm, ok := h.(map[string]interface{}); ok && hm["handler"] == "proxy" {
							hm["proxy_protocol"] = "v2"
						}
					}
				}
			}
		}
	}

	// Replace the L4 server config with the wrapped shape.
	servers[L4ServerName] = m.buildL4ServerConfig(innerRoutes)

	if err := m.loadConfig(config); err != nil {
		return fmt.Errorf("load wrapped L4 config: %w", err)
	}
	log.Printf("[L4ProxyManager] PROXY protocol enabled: %d inner route(s), allow=%v", len(innerRoutes), m.proxyProtocolTrusted)
	return nil
}

// effectiveInnerRoutes returns the inner subroute's route list when outer is
// wrapped, otherwise outer unchanged. Recognises the pattern B shape: a
// single outer route with handlers [proxy_protocol, subroute].
func effectiveInnerRoutes(outerRoutes []interface{}) []interface{} {
	if !isWrappedRouteList(outerRoutes) {
		return outerRoutes
	}
	outer, _ := outerRoutes[0].(map[string]interface{})
	handlers, _ := outer["handle"].([]interface{})
	sub, _ := handlers[1].(map[string]interface{})
	inner, _ := sub["routes"].([]interface{})
	return inner
}

// isWrappedRouteList reports whether the given outer-routes list is in the
// pattern B wrapped shape: exactly one route whose first handler is
// proxy_protocol.
func isWrappedRouteList(outerRoutes []interface{}) bool {
	if len(outerRoutes) != 1 {
		return false
	}
	r, ok := outerRoutes[0].(map[string]interface{})
	if !ok {
		return false
	}
	hs, ok := r["handle"].([]interface{})
	if !ok || len(hs) == 0 {
		return false
	}
	h0, ok := hs[0].(map[string]interface{})
	if !ok {
		return false
	}
	return h0["handler"] == "proxy_protocol"
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

// getRoutes fetches the effective L4 routes from Caddy via the atomic full-
// config GET. Returns the inner subroute's routes when the server is in
// wrapped (pattern B) form, the outer routes when flat. Returns nil when L4
// isn't configured yet.
func (m *L4ProxyManager) getRoutes() ([]CaddyL4Route, error) {
	config, err := m.getFullConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get full config: %w", err)
	}
	srv := getMapField(getMapField(getMapField(config, "apps"), "layer4"), "servers")
	server := getMapField(srv, L4ServerName)
	if server == nil {
		return nil, nil
	}
	outerRoutes, _ := server["routes"].([]interface{})
	inner := effectiveInnerRoutes(outerRoutes)

	// Round-trip the raw maps into typed routes for the caller.
	body, err := json.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("re-marshal effective routes: %w", err)
	}
	var routes []CaddyL4Route
	if err := json.Unmarshal(body, &routes); err != nil {
		return nil, fmt.Errorf("decode effective routes: %w", err)
	}
	return routes, nil
}

// putRoutes replaces the effective L4 route list atomically via /load. When
// the server is wrapped (pattern B), the inner subroute's `routes` is
// replaced; outer wrapping is left intact. When flat, the outer `routes` is
// replaced. Either way, the rest of the Caddy config is preserved verbatim.
func (m *L4ProxyManager) putRoutes(routes []CaddyL4Route) error {
	config, err := m.getFullConfig()
	if err != nil {
		return fmt.Errorf("get full config: %w", err)
	}
	apps := getMapField(config, "apps")
	layer4 := getMapField(apps, "layer4")
	servers := getMapField(layer4, "servers")
	server := getMapField(servers, L4ServerName)
	if server == nil {
		return fmt.Errorf("L4 server %q not active — call ActivateL4 first", L4ServerName)
	}

	// Round-trip typed routes into raw maps for embedding into the config tree.
	body, err := json.Marshal(routes)
	if err != nil {
		return fmt.Errorf("marshal routes: %w", err)
	}
	var newInner []interface{}
	if err := json.Unmarshal(body, &newInner); err != nil {
		return fmt.Errorf("decode new routes: %w", err)
	}

	outerRoutes, _ := server["routes"].([]interface{})
	if isWrappedRouteList(outerRoutes) {
		// Replace only the subroute's inner routes; keep the proxy_protocol
		// handler and the outer wrapper structure untouched.
		outer, _ := outerRoutes[0].(map[string]interface{})
		handlers, _ := outer["handle"].([]interface{})
		sub, _ := handlers[1].(map[string]interface{})
		sub["routes"] = newInner
	} else {
		server["routes"] = newInner
	}

	return m.loadConfig(config)
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
