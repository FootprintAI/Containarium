package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
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
	// dnsChallenge, when non-nil, makes provisioned policies solve ACME
	// DNS-01 (required for wildcard certs). Nil keeps Caddy's default
	// HTTP-01 + TLS-ALPN-01. Configured via WithDNSChallenge /
	// DNSChallengeFromEnv. See issue #378.
	dnsChallenge *CaddyACMEChallenges
	// proxyProtocolTrusted records the CIDRs passed to the last successful
	// EnableProxyProtocol, so the self-healing reconcile (EnsureBaseConfig)
	// can re-install the PROXY listener wrappers after the bundled Caddy
	// reverts to its stub Caddyfile. Empty = PROXY protocol not enabled. #400.
	proxyProtocolTrusted []string
	// wafEnabled prepends the coraza-caddy WAF handler to every HTTP route's
	// handler chain (Tier 3 PR-3, #662). Off by default — when false, routes are
	// byte-identical to before. Requires the Caddy binary built with the coraza
	// module. wafDirectives is the SecLang the engine loads (CRS + engine mode).
	wafEnabled    bool
	wafDirectives string
	// byocIngressAddr, when non-empty, adds one extra plaintext listener to the
	// edge server (e.g. "127.0.0.1:8081") that serves the SAME Host-matched
	// routes as :443 but WITHOUT TLS — the sentinel-terminate BYOC public HTTP
	// ingress data path (#733 slice 3). On a BYOC host the sentinel terminates
	// TLS with the wildcard it holds and plaintext-forwards over the tunnel to
	// this listener, which Host-routes to the box; the host needs no cert.
	//
	// MUST be loopback-scoped ("127.0.0.1:<port>") so it is reachable only via
	// the tunnel client (which dials 127.0.0.1:<port>) and never from the LAN —
	// it serves tenant routes in the clear. Empty = disabled (default): region
	// hosts and non-BYOC deployments are byte-identical to before. Because it is
	// not Caddy's http_port (80), automatic-HTTPS redirects don't apply — the
	// listener serves the reverse_proxy routes directly as plaintext HTTP.
	byocIngressAddr string
}

// RouteProtocol represents the protocol type for a route
type RouteProtocol string

const (
	// RouteProtocolHTTP is for standard HTTP/1.1 and HTTP/2 routes
	RouteProtocolHTTP RouteProtocol = "http"
	// RouteProtocolGRPC is for gRPC routes (requires HTTP/2)
	RouteProtocolGRPC RouteProtocol = "grpc"
	// RouteProtocolTLSPassthrough is for TLS passthrough routes (SNI-based, no TLS termination)
	RouteProtocolTLSPassthrough RouteProtocol = "tls_passthrough"
)

// Route represents a proxy route configuration (our domain model)
type Route struct {
	Subdomain    string        `json:"subdomain"`
	FullDomain   string        `json:"full_domain"`
	UpstreamIP   string        `json:"upstream_ip"`
	UpstreamPort int           `json:"upstream_port"`
	Protocol     RouteProtocol `json:"protocol,omitempty"` // "http" or "grpc", defaults to "http"
}

// caddyRouteJSON is used for JSON marshaling routes to Caddy API. Handle is the
// CaddyHandler interface so the chain can carry a WAF handler before
// reverse_proxy (#662 PR-3); a reverse_proxy handler marshals identically either
// way, so a WAF-disabled route is byte-for-byte what it was.
type caddyRouteJSON struct {
	ID     string            `json:"@id,omitempty"`
	Match  []CaddyMatchTyped `json:"match,omitempty"`
	Handle []CaddyHandler    `json:"handle,omitempty"`
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

// WithDNSChallenge configures the manager to provision certificates via ACME
// DNS-01, which is required for wildcard subjects and sidesteps the HTTP-01
// redirect failure mode. Nil keeps the default HTTP-01 + TLS-ALPN-01 path.
// Returns the manager for chaining. See DNSChallengeFromEnv and issue #378.
func (p *ProxyManager) WithDNSChallenge(dns *CaddyACMEChallenges) *ProxyManager {
	p.dnsChallenge = dns
	return p
}

// HasDNSChallenge reports whether the manager is configured to solve ACME
// DNS-01 — i.e. whether a wildcard certificate can be issued (HTTP-01 /
// TLS-ALPN-01 cannot). Callers use this to decide whether to provision a
// `*.<base-domain>` wildcard for per-region/subdomain endpoints. See #389.
func (p *ProxyManager) HasDNSChallenge() bool {
	return p.dnsChallenge != nil
}

// WithWAF enables the coraza-caddy WAF on every HTTP route this manager programs
// (#662 PR-3): the WAF handler is prepended to the handler chain so Coraza
// evaluates the request (CRS + virtual-patch rules in directives) before it
// reaches the upstream. Requires the Caddy binary built with the coraza module.
// directives is the SecLang to load (see DefaultWAFDirectives — enforce vs
// detection-only). Off by default; returns the manager for chaining.
func (p *ProxyManager) WithWAF(directives string) *ProxyManager {
	p.wafEnabled = true
	p.wafDirectives = directives
	return p
}

// WAFEnabled reports whether ingress WAF inspection is on.
func (p *ProxyManager) WAFEnabled() bool { return p.wafEnabled }

// WithBYOCIngress adds a loopback-scoped plaintext ingress listener to the edge
// server for the sentinel-terminate BYOC public-HTTP-ingress path (#733). addr
// should be "127.0.0.1:<port>"; an empty addr is a no-op (default: disabled).
// Returns the manager for chaining. See the byocIngressAddr field doc.
func (p *ProxyManager) WithBYOCIngress(addr string) *ProxyManager {
	p.byocIngressAddr = strings.TrimSpace(addr)
	return p
}

// BYOCIngressAddr returns the configured plaintext ingress listener address
// (empty when disabled).
func (p *ProxyManager) BYOCIngressAddr() string { return p.byocIngressAddr }

// listenAddrs returns the edge server's listen set: always :80 and :443, plus
// the BYOC plaintext ingress listener when configured (#733 slice 3). Centralised
// so every place that (re)builds the server config — createHTTPApp and
// createServerConfig, both reached by the #400 self-heal rebuild — agrees, so a
// Caddy revert-and-rebuild doesn't silently drop the ingress listener.
func (p *ProxyManager) listenAddrs() []string {
	addrs := []string{":80", ":443"}
	if p.byocIngressAddr != "" {
		addrs = append(addrs, p.byocIngressAddr)
	}
	return addrs
}

// SetServerName sets the Caddy server name (useful when Caddy uses a custom server name)
func (p *ProxyManager) SetServerName(name string) {
	p.serverName = name
}

// AddRoute adds a new HTTP route to Caddy
// If subdomain contains the base domain, it's used as-is; otherwise base domain is appended
func (p *ProxyManager) AddRoute(subdomain, containerIP string, port int) error {
	return p.addRouteWithProtocol(subdomain, containerIP, port, RouteProtocolHTTP)
}

// AddGRPCRoute adds a new gRPC route to Caddy with HTTP/2 transport
// gRPC requires HTTP/2 (h2c for cleartext connection to backend)
func (p *ProxyManager) AddGRPCRoute(subdomain, containerIP string, port int) error {
	return p.addRouteWithProtocol(subdomain, containerIP, port, RouteProtocolGRPC)
}

// addRouteWithProtocol adds a route with the specified protocol type
func (p *ProxyManager) addRouteWithProtocol(subdomain, containerIP string, port int, protocol RouteProtocol) error {
	fullDomain := subdomain
	routeID := subdomain

	// Determine whether to append the base domain.
	// If the input is a simple subdomain (no dots), append baseDomain.
	// If it already contains baseDomain as suffix, extract the subdomain part.
	// If it's a fully-qualified domain that is NOT a subdomain of baseDomain
	// (e.g., "api.example.com" when baseDomain is "<cluster>.example.com"),
	// use it as-is — it's an independent domain.
	if p.baseDomain != "" {
		if strings.HasSuffix(subdomain, "."+p.baseDomain) || strings.HasSuffix(subdomain, p.baseDomain) {
			// Already contains base domain — extract subdomain for route ID
			routeID = strings.TrimSuffix(subdomain, "."+p.baseDomain)
			routeID = strings.TrimSuffix(routeID, p.baseDomain)
		} else if !strings.Contains(subdomain, ".") {
			// Simple subdomain (no dots) — append base domain
			fullDomain = fmt.Sprintf("%s.%s", subdomain, p.baseDomain)
		}
		// Otherwise: it's a FQDN that is not a subdomain of baseDomain — use as-is
	}

	// Create handler based on protocol
	handler := CaddyReverseProxyHandler{
		Handler: "reverse_proxy",
		Upstreams: []CaddyUpstreamTyped{
			{Dial: fmt.Sprintf("%s:%d", containerIP, port)},
		},
	}

	// Add HTTP/2 transport for gRPC
	if protocol == RouteProtocolGRPC {
		handler.Transport = NewGRPCTransport()
	}

	route := caddyRouteJSON{
		ID: routeID, // Use subdomain as route ID for easy removal
		Match: []CaddyMatchTyped{
			{Host: []string{fullDomain}},
		},
		// Prepend the coraza WAF handler when enabled, so it inspects before
		// reverse_proxy; a no-op (unchanged chain) when disabled (#662 PR-3).
		Handle: PrependWAF([]CaddyHandler{handler}, p.wafEnabled, p.wafDirectives),
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

// RemoveTLSSubject strips `domain` from every TLS automation policy's
// `subjects` list. Used by the container-delete cascade: once a container
// is gone, Caddy should stop trying to ACME-renew its hostname's cert
// (otherwise it'll keep hitting Let's Encrypt with no upstream to
// challenge, slowly burning rate-limit budget).
//
// No-op if `domain` isn't in any subjects list. Leaves an empty policy
// in place if `domain` was the only subject — that's harmless (Caddy
// just has nothing to do for it) and avoids the complexity of deciding
// whether to delete the entire policy entry (which might be the only
// reference to the ACME issuers config).
func (p *ProxyManager) RemoveTLSSubject(domain string) error {
	url := fmt.Sprintf("%s/config/apps/tls/automation/policies", p.caddyAdminURL)
	resp, err := p.httpClient.Get(url)
	if err != nil {
		return fmt.Errorf("get TLS policies: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusBadRequest {
		// No TLS app configured; nothing to remove.
		return nil
	}

	var policies []CaddyTLSAutomationPolicy
	body, _ := io.ReadAll(resp.Body)
	if len(bytes.TrimSpace(body)) == 0 || string(bytes.TrimSpace(body)) == "null" {
		return nil
	}
	if err := json.Unmarshal(body, &policies); err != nil {
		return fmt.Errorf("decode TLS policies: %w", err)
	}

	changed := false
	for i := range policies {
		filtered := policies[i].Subjects[:0]
		for _, s := range policies[i].Subjects {
			if s == domain {
				changed = true
				continue
			}
			filtered = append(filtered, s)
		}
		policies[i].Subjects = filtered
	}
	if !changed {
		return nil
	}

	out, err := json.Marshal(policies)
	if err != nil {
		return fmt.Errorf("marshal TLS policies: %w", err)
	}
	req, err := http.NewRequest("PATCH", url, bytes.NewReader(out))
	if err != nil {
		return fmt.Errorf("build PATCH request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	patchResp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("patch TLS policies: %w", err)
	}
	defer patchResp.Body.Close()
	if patchResp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(patchResp.Body)
		return fmt.Errorf("caddy returned %d patching TLS policies: %s", patchResp.StatusCode, string(errBody))
	}
	return nil
}

// ProvisionTLS provisions a TLS certificate for the given domain via Caddy's on-demand TLS
// or by adding it to the TLS automation policy
func (p *ProxyManager) ProvisionTLS(domain string) error {
	// Caddy's admin API returns 400 "invalid traversal path" when you
	// PATCH/POST a sub-path whose parent doesn't exist yet. On a fresh
	// Caddy that's never had a TLS app configured, /config/apps/tls is
	// `null`, so /config/apps/tls/automation/policies has no parent.
	// Bootstrap the app first if it's missing.
	if err := p.ensureTLSApp(); err != nil {
		return fmt.Errorf("failed to bootstrap TLS app: %w", err)
	}

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
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read TLS policies response: %w", err)
		}
		if err := json.Unmarshal(body, &policies); err != nil {
			return fmt.Errorf("failed to unmarshal TLS policies: %w", err)
		}
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

	// No existing policies, create a new one with ACME issuers (DNS-01 when
	// configured, otherwise Caddy's default HTTP-01 + TLS-ALPN-01).
	newPolicy := NewTLSPolicyWithDNS([]string{domain}, p.dnsChallenge)

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

// ProvisionWildcardTLS adds a single "*.<baseDomain>" wildcard subject to
// Caddy's TLS automation, issued via DNS-01. This is the per-cluster
// alternative to per-subdomain on-demand issuance: one cert covers every
// subdomain, eliminating the Let's Encrypt per-domain rate-limit exposure and
// the HTTP-01 redirect failure mode (issue #378).
//
// Requires a DNS-01 challenge to be configured — HTTP-01 / TLS-ALPN-01 cannot
// issue wildcard certificates, so this returns an error rather than silently
// falling back to a path that can't work.
func (p *ProxyManager) ProvisionWildcardTLS() error {
	if p.dnsChallenge == nil {
		return fmt.Errorf("wildcard TLS requires an ACME DNS-01 provider (set CONTAINARIUM_ACME_DNS_PROVIDER); HTTP-01 / TLS-ALPN-01 cannot issue wildcard certificates")
	}
	if p.baseDomain == "" {
		return fmt.Errorf("wildcard TLS requires a base domain")
	}
	return p.ProvisionTLS("*." + p.baseDomain)
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
				Protocol:   RouteProtocolHTTP, // Default to HTTP
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

					// Detect gRPC routes by checking for HTTP/2 transport
					if handler.Transport != nil && handler.Transport.Protocol == "http" {
						for _, v := range handler.Transport.Versions {
							if v == "h2c" || v == "2" {
								route.Protocol = RouteProtocolGRPC
								break
							}
						}
					}
				}
			}

			routes = append(routes, route)
		}
	}

	return routes, nil
}

// UpdateRoute updates an existing HTTP route
func (p *ProxyManager) UpdateRoute(subdomain, containerIP string, port int) error {
	return p.UpdateRouteWithProtocol(subdomain, containerIP, port, RouteProtocolHTTP)
}

// UpdateGRPCRoute updates an existing gRPC route
func (p *ProxyManager) UpdateGRPCRoute(subdomain, containerIP string, port int) error {
	return p.UpdateRouteWithProtocol(subdomain, containerIP, port, RouteProtocolGRPC)
}

// UpdateRouteWithProtocol updates an existing route with the specified protocol
func (p *ProxyManager) UpdateRouteWithProtocol(subdomain, containerIP string, port int, protocol RouteProtocol) error {
	// Remove existing route first (idempotent; route may not exist yet)
	if err := p.RemoveRoute(subdomain); err != nil {
		log.Printf("[ProxyManager] RemoveRoute(%s) before update: %v", subdomain, err)
	}

	// Add new route with protocol
	return p.addRouteWithProtocol(subdomain, containerIP, port, protocol)
}

// EnsureServerConfig ensures the Caddy server has basic configuration
// This should be called once during initialization
func (p *ProxyManager) EnsureServerConfig() error {
	// First, ensure the HTTP app exists
	if err := p.ensureHTTPApp(); err != nil {
		return fmt.Errorf("failed to ensure HTTP app: %w", err)
	}

	// Ensure the TLS app exists (required for ProvisionTLS to work)
	if err := p.ensureTLSApp(); err != nil {
		// Non-fatal: routes will work over HTTP, but TLS provisioning may fail
		fmt.Printf("Warning: Failed to ensure TLS app: %v\n", err)
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

// ensureTLSApp ensures the TLS app with automation exists in Caddy config.
// Without this, ProvisionTLS calls will fail with "invalid traversal path".
func (p *ProxyManager) ensureTLSApp() error {
	url := fmt.Sprintf("%s/config/apps/tls", p.caddyAdminURL)
	resp, err := p.httpClient.Get(url)
	if err != nil {
		return p.createTLSApp()
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusBadRequest {
		return p.createTLSApp()
	}

	// Check if it's null or empty. Caddy returns "null\n" (with trailing
	// newline) for a missing config path, so trim whitespace before
	// comparing.
	body, _ := io.ReadAll(resp.Body)
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" || trimmed == "null" {
		return p.createTLSApp()
	}

	return nil
}

// createTLSApp creates the base TLS app with automation policies using ACME issuers
func (p *ProxyManager) createTLSApp() error {
	// Typed config (was a map[string]interface{}). When no DNS challenge is
	// configured the issuers carry no `challenges` field, so the emitted JSON
	// is identical to the previous default. With DNS-01 configured, both the
	// ACME and ZeroSSL issuers gain the provider's `challenges.dns` block.
	tlsApp := CaddyTLSApp{
		Automation: &CaddyTLSAutomation{
			Policies: []CaddyTLSAutomationPolicy{
				{Issuers: issuersFor(p.dnsChallenge)},
			},
		},
	}

	configJSON, err := json.Marshal(tlsApp)
	if err != nil {
		return fmt.Errorf("failed to marshal TLS config: %w", err)
	}

	url := fmt.Sprintf("%s/config/apps/tls", p.caddyAdminURL)
	req, err := http.NewRequest("PUT", url, bytes.NewReader(configJSON))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to create TLS app: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("caddy returned error creating TLS app (status %d): %s", resp.StatusCode, string(body))
	}

	return nil
}

// ensureHTTPApp ensures the HTTP app and server exist in Caddy config.
//
// We probe with a loose schema (map[string]json.RawMessage on servers) rather
// than the typed CaddyHTTPApp. The full type transitively contains
// []CaddyHandler — an interface slice — which encoding/json cannot decode
// into, so a strict decode would always fail on any non-empty config and
// fall through to createHTTPApp's PUT, which 409s because the http app
// already exists. The result before this fix was that every daemon startup
// logged "key already exists: http" and silently lost any subsequent route
// updates the daemon tried to apply (e.g. registering a newly-connected
// tunnel-promoted pool primary).
func (p *ProxyManager) ensureHTTPApp() error {
	url := fmt.Sprintf("%s/config/apps/http", p.caddyAdminURL)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return p.createHTTPApp()
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusBadRequest {
		return p.createHTTPApp()
	}

	body, _ := io.ReadAll(resp.Body)
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" || trimmed == "null" {
		return p.createHTTPApp()
	}

	var probe struct {
		Servers map[string]json.RawMessage `json:"servers,omitempty"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return p.createHTTPApp()
	}

	if probe.Servers == nil {
		return p.createHTTPApp()
	}

	if _, exists := probe.Servers[p.serverName]; !exists {
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
				Listen: p.listenAddrs(),
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

// EnableProxyProtocol installs a [proxy_protocol, tls] listener_wrappers chain
// and sets trusted_proxies on the Caddy server, so connections arriving from
// trustedCIDRs (typically the sentinel's IP, or 127.0.0.0/8 in tunnel mode)
// are PROXY-decoded and the real client IP propagates as X-Forwarded-For to
// upstream containers.
//
// trustedCIDRs MUST NOT be empty or wildcard — an unrestricted allow list lets
// any direct VPC client spoof its source IP via a forged PROXY header.
//
// Implementation: GETs the full Caddy config, sets the two new fields on the
// HTTP server map in place (preserving listen/routes/automatic_https/etc.),
// then atomically POSTs /load. A naive PATCH on the server path REPLACES the
// resource at that path — that wipes everything else on the server, which is
// exactly the regression we're avoiding here.
func (p *ProxyManager) EnableProxyProtocol(trustedCIDRs []string) error {
	if len(trustedCIDRs) == 0 {
		return fmt.Errorf("EnableProxyProtocol: trustedCIDRs must not be empty (refusing to accept PROXY headers from any source)")
	}
	for _, c := range trustedCIDRs {
		if c == "0.0.0.0/0" || c == "::/0" {
			return fmt.Errorf("EnableProxyProtocol: refusing wildcard CIDR %q — pin to the sentinel IP or 127.0.0.0/8", c)
		}
	}

	config, err := p.getFullConfig()
	if err != nil {
		return fmt.Errorf("get full config: %w", err)
	}
	apps := getMapField(config, "apps")
	httpApp := getMapField(apps, "http")
	servers := getMapField(httpApp, "servers")
	srv := getMapField(servers, p.serverName)
	if srv == nil {
		return fmt.Errorf("HTTP server %q missing from config", p.serverName)
	}

	// Set only the two fields we care about — leave listen/routes/etc intact.
	// proxy_protocol must come before tls in the wrapper chain so the PROXY
	// header is consumed before TLS parsing.
	srv["listener_wrappers"] = []interface{}{
		map[string]interface{}{
			"wrapper": "proxy_protocol",
			"timeout": "5s",
			"allow":   toAnySlice(trustedCIDRs),
		},
		map[string]interface{}{"wrapper": "tls"},
	}
	srv["trusted_proxies"] = map[string]interface{}{
		"source": "static",
		"ranges": toAnySlice(trustedCIDRs),
	}

	if err := p.loadConfig(config); err != nil {
		return fmt.Errorf("load config with proxy_protocol: %w", err)
	}
	// Remember the trusted set so EnsureBaseConfig can re-apply the wrappers
	// after a stub-Caddyfile revert (#400).
	p.proxyProtocolTrusted = append(p.proxyProtocolTrusted[:0], trustedCIDRs...)
	return nil
}

// EnsureBaseConfig re-asserts the base Caddy edge config — the http app, the
// `srv0` server, the tls app, and (when configured) the PROXY listener
// wrappers — rebuilding them when the bundled Caddy has reverted to its stub
// Caddyfile (`{ admin :2019 }`).
//
// The bundled `*-core-caddy` boots from that stub and is configured entirely
// over the admin API; any caddy reload/restart/crash drops the running config
// back to the stub, which wipes the http app. The periodic route sync then
// loops on `400 invalid traversal path` and :443 goes permanently dark with no
// self-heal (issue #400). Calling this at the top of every sync makes the edge
// reconcile itself: once the base is rebuilt, the normal route/L4 diff
// repopulates HTTP routes (with TLS subjects, via AddRoute→ProvisionTLS) and
// re-activates layer4.
//
// It is cheap when the config is intact (a single GET) and only issues writes
// on a detected revert. Returns whether it rebuilt.
func (p *ProxyManager) EnsureBaseConfig() (bool, error) {
	intact, err := p.baseConfigIntact()
	if err != nil {
		return false, err
	}
	if intact {
		return false, nil
	}
	if err := p.EnsureServerConfig(); err != nil {
		return false, fmt.Errorf("rebuild base server config: %w", err)
	}
	if len(p.proxyProtocolTrusted) > 0 {
		if err := p.EnableProxyProtocol(p.proxyProtocolTrusted); err != nil {
			return true, fmt.Errorf("re-apply PROXY protocol after rebuild: %w", err)
		}
	}
	return true, nil
}

// baseConfigIntact reports whether the Caddy http server `srv0` is present and
// (when PROXY protocol is configured) still carries its listener wrappers. A
// false return means Caddy has reverted to the stub Caddyfile and the base
// config must be rebuilt. See EnsureBaseConfig (#400).
func (p *ProxyManager) baseConfigIntact() (bool, error) {
	url := fmt.Sprintf("%s/config/apps/http/servers/%s", p.caddyAdminURL, p.serverName)
	resp, err := p.httpClient.Get(url)
	if err != nil {
		return false, fmt.Errorf("probe http server config: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusBadRequest {
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return false, fmt.Errorf("probe http server config: status %d: %s", resp.StatusCode, string(body))
	}
	body, _ := io.ReadAll(resp.Body)
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" || trimmed == "null" {
		return false, nil
	}
	// When PROXY protocol is enabled the server must keep its listener wrappers;
	// a rebuilt-but-bare server (no wrappers) means the wrappers were wiped too.
	if len(p.proxyProtocolTrusted) > 0 {
		var srv map[string]json.RawMessage
		if err := json.Unmarshal([]byte(trimmed), &srv); err != nil {
			// Malformed — treat as reverted so we rebuild from a known-good base.
			return false, nil
		}
		if _, ok := srv["listener_wrappers"]; !ok {
			return false, nil
		}
	}
	return true, nil
}

// toAnySlice converts a []string into []interface{} for embedding into raw
// (map[string]interface{}) Caddy config nodes that we'll re-marshal to JSON.
func toAnySlice(in []string) []interface{} {
	out := make([]interface{}, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}

// getFullConfig reads the complete Caddy config as a raw map.
func (p *ProxyManager) getFullConfig() (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/config/", p.caddyAdminURL)
	resp, err := p.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("get config: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("caddy returned %d: %s", resp.StatusCode, string(b))
	}
	var config map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	return config, nil
}

// loadConfig atomically replaces the entire Caddy config via POST /load.
func (p *ProxyManager) loadConfig(config map[string]interface{}) error {
	body, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	url := fmt.Sprintf("%s/load", p.caddyAdminURL)
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create /load request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("post /load: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("caddy /load returned %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

// createServerConfig creates the initial Caddy server configuration
func (p *ProxyManager) createServerConfig() error {
	config := CaddyServerConfig{
		Listen: p.listenAddrs(),
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
