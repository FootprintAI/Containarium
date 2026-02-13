package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
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

// Route represents a proxy route configuration (our domain model)
type Route struct {
	Subdomain    string `json:"subdomain"`
	FullDomain   string `json:"full_domain"`
	UpstreamIP   string `json:"upstream_ip"`
	UpstreamPort int    `json:"upstream_port"`
}

// caddyRouteJSON is used for JSON marshaling routes to Caddy API
// It uses a concrete handler type for type safety while remaining JSON-compatible
type caddyRouteJSON struct {
	ID     string                       `json:"@id,omitempty"`
	Match  []CaddyMatchTyped            `json:"match,omitempty"`
	Handle []CaddyReverseProxyHandler   `json:"handle,omitempty"`
}

// caddyRouteRaw is used for unmarshaling routes from Caddy API
// Caddy can return various handler types, so we use json.RawMessage
type caddyRouteRaw struct {
	ID     string            `json:"@id,omitempty"`
	Match  []CaddyMatchTyped `json:"match,omitempty"`
	Handle []json.RawMessage `json:"handle,omitempty"`
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
// If subdomain contains the base domain, it's used as-is; otherwise base domain is appended
func (p *ProxyManager) AddRoute(subdomain, containerIP string, port int) error {
	fullDomain := subdomain
	routeID := subdomain

	// Check if subdomain already contains the base domain
	if p.baseDomain != "" && !strings.HasSuffix(subdomain, "."+p.baseDomain) && !strings.HasSuffix(subdomain, p.baseDomain) {
		fullDomain = fmt.Sprintf("%s.%s", subdomain, p.baseDomain)
	} else {
		// Extract subdomain part for route ID if full domain was provided
		routeID = strings.TrimSuffix(subdomain, "."+p.baseDomain)
		routeID = strings.TrimSuffix(routeID, p.baseDomain)
	}

	route := caddyRouteJSON{
		ID: routeID, // Use subdomain as route ID for easy removal
		Match: []CaddyMatchTyped{
			{Host: []string{fullDomain}},
		},
		Handle: []CaddyReverseProxyHandler{
			{
				Handler: "reverse_proxy",
				Upstreams: []CaddyUpstreamTyped{
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

	// Provision TLS certificate for the domain
	if err := p.ProvisionTLS(fullDomain); err != nil {
		// Log warning but don't fail - route is added, TLS might work with existing wildcard cert
		// or the domain might already have a certificate
		fmt.Printf("Warning: Failed to provision TLS for %s: %v\n", fullDomain, err)
	}

	return nil
}

// ProvisionTLS provisions a TLS certificate for the given domain via Caddy's on-demand TLS
// or by adding it to the TLS automation policy
func (p *ProxyManager) ProvisionTLS(domain string) error {
	// First, check if there's an existing automation policy we can add to
	// Get current TLS config
	url := fmt.Sprintf("%s/config/apps/tls/automation/policies", p.caddyAdminURL)
	resp, err := p.httpClient.Get(url)
	if err != nil {
		return fmt.Errorf("failed to get TLS policies: %w", err)
	}
	defer resp.Body.Close()

	var policies []CaddyTLSAutomationPolicy
	if resp.StatusCode == http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		json.Unmarshal(body, &policies)
	}

	// Check if domain is already in a policy
	for _, policy := range policies {
		for _, subject := range policy.Subjects {
			if subject == domain {
				// Domain already has a policy, no need to add
				return nil
			}
		}
	}

	// Add domain to a new or existing policy
	// If there are existing policies, add to the first one that has issuers configured
	if len(policies) > 0 {
		// Add domain to the first policy's subjects
		policies[0].Subjects = append(policies[0].Subjects, domain)

		// Update the policy
		policyJSON, err := json.Marshal(policies)
		if err != nil {
			return fmt.Errorf("failed to marshal policies: %w", err)
		}

		req, err := http.NewRequest("PATCH", url, bytes.NewReader(policyJSON))
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := p.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("failed to update TLS policy: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("caddy returned error updating TLS policy (status %d): %s", resp.StatusCode, string(body))
		}

		return nil
	}

	// No existing policies, create a new one with ACME issuers
	newPolicy := NewTLSPolicy([]string{domain})

	policyJSON, err := json.Marshal([]CaddyTLSAutomationPolicy{newPolicy})
	if err != nil {
		return fmt.Errorf("failed to marshal new policy: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(policyJSON))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err = p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to create TLS policy: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("caddy returned error creating TLS policy (status %d): %s", resp.StatusCode, string(body))
	}

	return nil
}

// RemoveRoute removes a route from Caddy by subdomain or full domain
func (p *ProxyManager) RemoveRoute(domain string) error {
	// Extract route ID from domain (same logic as AddRoute)
	routeID := domain
	if p.baseDomain != "" {
		// If domain contains the base domain, extract just the subdomain part
		if strings.HasSuffix(domain, "."+p.baseDomain) {
			routeID = strings.TrimSuffix(domain, "."+p.baseDomain)
		} else if strings.HasSuffix(domain, p.baseDomain) {
			routeID = strings.TrimSuffix(domain, p.baseDomain)
		}
	}

	// First try to delete by ID (for routes created via our API)
	url := fmt.Sprintf("%s/id/%s", p.caddyAdminURL, routeID)
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to remove route: %w", err)
	}
	resp.Body.Close()

	// If deleted successfully by ID, we're done
	if resp.StatusCode == http.StatusOK {
		return nil
	}

	// If route not found by ID, try to find and delete by index
	// This handles routes created via Caddyfile or without @id
	return p.removeRouteByDomain(domain)
}

// removeRouteByDomain finds a route by its domain and deletes it by index
func (p *ProxyManager) removeRouteByDomain(domain string) error {
	// Get all routes
	routesURL := fmt.Sprintf("%s/config/apps/http/servers/%s/routes", p.caddyAdminURL, p.serverName)
	req, err := http.NewRequest("GET", routesURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to list routes: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to list routes (status %d): %s", resp.StatusCode, string(body))
	}

	// Parse routes to find the index of the one matching our domain
	var routes []caddyRouteRaw
	if err := json.NewDecoder(resp.Body).Decode(&routes); err != nil {
		return fmt.Errorf("failed to decode routes: %w", err)
	}

	// Find the route with matching host
	for i, route := range routes {
		if len(route.Match) > 0 {
			for _, host := range route.Match[0].Host {
				if host == domain {
					// Found the route, delete by index
					deleteURL := fmt.Sprintf("%s/config/apps/http/servers/%s/routes/%d", p.caddyAdminURL, p.serverName, i)
					delReq, err := http.NewRequest("DELETE", deleteURL, nil)
					if err != nil {
						return fmt.Errorf("failed to create delete request: %w", err)
					}

					delResp, err := p.httpClient.Do(delReq)
					if err != nil {
						return fmt.Errorf("failed to delete route: %w", err)
					}
					delResp.Body.Close()

					if delResp.StatusCode != http.StatusOK {
						return fmt.Errorf("failed to delete route (status %d)", delResp.StatusCode)
					}
					return nil
				}
			}
		}
	}

	// Route not found - this is acceptable, might already be deleted
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

	var caddyRoutes []caddyRouteRaw
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

			// Extract upstream info from handler if available
			if len(cr.Handle) > 0 {
				var handler CaddyReverseProxyHandler
				if err := json.Unmarshal(cr.Handle[0], &handler); err == nil {
					if len(handler.Upstreams) > 0 {
						dial := handler.Upstreams[0].Dial
						// Parse ip:port from Dial field
						if lastColon := strings.LastIndex(dial, ":"); lastColon != -1 {
							route.UpstreamIP = dial[:lastColon]
							if port, err := strconv.Atoi(dial[lastColon+1:]); err == nil {
								route.UpstreamPort = port
							}
						} else {
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
	// First, ensure the HTTP app exists
	if err := p.ensureHTTPApp(); err != nil {
		return fmt.Errorf("failed to ensure HTTP app: %w", err)
	}

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

	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusBadRequest {
		return p.createServerConfig()
	}

	return nil
}

// ensureHTTPApp ensures the HTTP app and server exist in Caddy config
func (p *ProxyManager) ensureHTTPApp() error {
	// Check if HTTP app exists
	url := fmt.Sprintf("%s/config/apps/http", p.caddyAdminURL)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		// HTTP app doesn't exist, create it with server
		return p.createHTTPApp()
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusBadRequest {
		return p.createHTTPApp()
	}

	// HTTP app exists, check if it has the server configured
	var httpApp CaddyHTTPApp
	if err := json.NewDecoder(resp.Body).Decode(&httpApp); err != nil {
		// Invalid config, recreate
		return p.createHTTPApp()
	}

	// Check if servers map exists and has our server
	if httpApp.Servers == nil {
		// No servers map, recreate
		return p.createHTTPApp()
	}

	if _, exists := httpApp.Servers[p.serverName]; !exists {
		// Server doesn't exist, add it
		return p.createServerConfig()
	}

	return nil
}

// createHTTPApp creates the HTTP app with the server already configured
func (p *ProxyManager) createHTTPApp() error {
	// Create HTTP app with the server configured (avoid separate creation)
	httpApp := CaddyHTTPApp{
		Servers: map[string]*CaddyServerConfig{
			p.serverName: {
				Listen: []string{":80", ":443"},
				Routes: []CaddyRouteTyped{},
			},
		},
	}

	configJSON, err := json.Marshal(httpApp)
	if err != nil {
		return fmt.Errorf("failed to marshal HTTP app config: %w", err)
	}

	url := fmt.Sprintf("%s/config/apps/http", p.caddyAdminURL)
	req, err := http.NewRequest("PUT", url, bytes.NewReader(configJSON))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to create HTTP app: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("caddy returned error creating HTTP app (status %d): %s", resp.StatusCode, string(body))
	}

	return nil
}

// createServerConfig creates the initial Caddy server configuration
func (p *ProxyManager) createServerConfig() error {
	config := CaddyServerConfig{
		Listen: []string{":80", ":443"},
		Routes: []CaddyRouteTyped{},
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
