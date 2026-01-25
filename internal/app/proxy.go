package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DefaultCaddyServerName is the default Caddy server name used in Caddyfile configs
const DefaultCaddyServerName = "srv0"

// ProxyManager manages Caddy reverse proxy configuration
type ProxyManager struct {
	caddyAdminURL string
	baseDomain    string
	serverName    string // Caddy server name (default: "srv0")
	httpClient    *http.Client
}

// Route represents a proxy route configuration
type Route struct {
	Subdomain   string `json:"subdomain"`
	FullDomain  string `json:"full_domain"`
	UpstreamIP  string `json:"upstream_ip"`
	UpstreamPort int   `json:"upstream_port"`
}

// CaddyRoute represents a Caddy route configuration
type CaddyRoute struct {
	ID     string                   `json:"@id,omitempty"`
	Match  []CaddyMatch             `json:"match"`
	Handle []map[string]interface{} `json:"handle"`
}

// CaddyMatch represents a Caddy match configuration
type CaddyMatch struct {
	Host []string `json:"host,omitempty"`
}

// CaddyUpstream represents a Caddy upstream configuration
type CaddyUpstream struct {
	Dial string `json:"dial"`
}

// NewProxyManager creates a new proxy manager
func NewProxyManager(caddyAdminURL, baseDomain string) *ProxyManager {
	return &ProxyManager{
		caddyAdminURL: caddyAdminURL,
		baseDomain:    baseDomain,
		serverName:    DefaultCaddyServerName,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// SetServerName sets the Caddy server name (useful when Caddy uses a custom server name)
func (p *ProxyManager) SetServerName(name string) {
	p.serverName = name
}

// AddRoute adds a new route to Caddy
func (p *ProxyManager) AddRoute(subdomain, containerIP string, port int) error {
	fullDomain := fmt.Sprintf("%s.%s", subdomain, p.baseDomain)

	route := CaddyRoute{
		ID: subdomain, // Use subdomain as route ID for easy removal
		Match: []CaddyMatch{
			{Host: []string{fullDomain}},
		},
		Handle: []map[string]interface{}{
			{
				"handler": "reverse_proxy",
				"upstreams": []CaddyUpstream{
					{Dial: fmt.Sprintf("%s:%d", containerIP, port)},
				},
			},
		},
	}

	// Serialize route to JSON
	routeJSON, err := json.Marshal(route)
	if err != nil {
		return fmt.Errorf("failed to marshal route: %w", err)
	}

	// Add route via Caddy API
	url := fmt.Sprintf("%s/config/apps/http/servers/%s/routes", p.caddyAdminURL, p.serverName)
	req, err := http.NewRequest("POST", url, bytes.NewReader(routeJSON))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to add route: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("caddy returned error (status %d): %s", resp.StatusCode, string(body))
	}

	return nil
}

// RemoveRoute removes a route from Caddy by subdomain
func (p *ProxyManager) RemoveRoute(subdomain string) error {
	// Delete route by ID
	url := fmt.Sprintf("%s/id/%s", p.caddyAdminURL, subdomain)
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to remove route: %w", err)
	}
	defer resp.Body.Close()

	// 404 is acceptable - route might already be deleted
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("caddy returned error (status %d): %s", resp.StatusCode, string(body))
	}

	return nil
}

// ListRoutes returns all configured routes
func (p *ProxyManager) ListRoutes() ([]Route, error) {
	url := fmt.Sprintf("%s/config/apps/http/servers/%s/routes", p.caddyAdminURL, p.serverName)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to list routes: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		// Handle case when no routes are configured (path doesn't exist in Caddy config)
		// Caddy returns 400 with "invalid traversal path" when the http app or server doesn't exist
		if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusNotFound {
			return []Route{}, nil
		}
		return nil, fmt.Errorf("caddy returned error (status %d): %s", resp.StatusCode, string(body))
	}

	var caddyRoutes []CaddyRoute
	if err := json.NewDecoder(resp.Body).Decode(&caddyRoutes); err != nil {
		return nil, fmt.Errorf("failed to decode routes: %w", err)
	}

	var routes []Route
	for _, cr := range caddyRoutes {
		if len(cr.Match) > 0 && len(cr.Match[0].Host) > 0 {
			fullDomain := cr.Match[0].Host[0]
			route := Route{
				Subdomain:  cr.ID,
				FullDomain: fullDomain,
			}

			// Extract upstream info if available
			if len(cr.Handle) > 0 {
				if upstreams, ok := cr.Handle[0]["upstreams"].([]interface{}); ok && len(upstreams) > 0 {
					if upstream, ok := upstreams[0].(map[string]interface{}); ok {
						if dial, ok := upstream["dial"].(string); ok {
							// Parse dial string (format: "ip:port")
							route.UpstreamIP = dial
						}
					}
				}
			}

			routes = append(routes, route)
		}
	}

	return routes, nil
}

// UpdateRoute updates an existing route
func (p *ProxyManager) UpdateRoute(subdomain, containerIP string, port int) error {
	// Remove existing route first
	p.RemoveRoute(subdomain) // Ignore errors

	// Add new route
	return p.AddRoute(subdomain, containerIP, port)
}

// EnsureServerConfig ensures the Caddy server has basic configuration
// This should be called once during initialization
func (p *ProxyManager) EnsureServerConfig() error {
	// Check if server config exists
	url := fmt.Sprintf("%s/config/apps/http/servers/%s", p.caddyAdminURL, p.serverName)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		// Server might not be configured, create it
		return p.createServerConfig()
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return p.createServerConfig()
	}

	return nil
}

// createServerConfig creates the initial Caddy server configuration
func (p *ProxyManager) createServerConfig() error {
	config := map[string]interface{}{
		"listen": []string{":80", ":443"},
		"routes": []interface{}{},
	}

	configJSON, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	url := fmt.Sprintf("%s/config/apps/http/servers/%s", p.caddyAdminURL, p.serverName)
	req, err := http.NewRequest("PUT", url, bytes.NewReader(configJSON))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to create server config: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("caddy returned error (status %d): %s", resp.StatusCode, string(body))
	}

	return nil
}
