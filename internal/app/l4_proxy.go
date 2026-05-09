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
