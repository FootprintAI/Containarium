package app

import (
	"encoding/json"
	"os"
	"strings"
)

// Caddy API Types
// These types provide type-safe representations of Caddy's JSON API structures.
// Reference: https://caddyserver.com/docs/json/

// CaddyServerConfig represents a Caddy HTTP server configuration
type CaddyServerConfig struct {
	Listen           []string               `json:"listen"`
	ListenerWrappers []CaddyListenerWrapper `json:"listener_wrappers,omitempty"`
	Routes           []CaddyRouteTyped      `json:"routes"` // No omitempty - Caddy needs empty array to exist
	TrustedProxies   *CaddyTrustedProxies   `json:"trusted_proxies,omitempty"`
}

// CaddyListenerWrapper represents one entry in a server's listener_wrappers
// chain. The order matters: proxy_protocol must come before tls so the PROXY
// header is consumed before the TLS parser runs.
type CaddyListenerWrapper struct {
	Wrapper string   `json:"wrapper"`           // e.g. "proxy_protocol", "tls"
	Timeout string   `json:"timeout,omitempty"` // e.g. "5s" — only meaningful for proxy_protocol
	Allow   []string `json:"allow,omitempty"`   // CIDR list of trusted senders for proxy_protocol
}

// CaddyTrustedProxies marks IP ranges whose forwarded IP information Caddy will
// trust. Combined with the proxy_protocol listener wrapper, the parsed source
// address propagates into reverse_proxy as X-Forwarded-For for upstream
// containers.
type CaddyTrustedProxies struct {
	Source string   `json:"source"` // "static"
	Ranges []string `json:"ranges"`
}

// CaddyRouteTyped represents a fully typed Caddy route configuration
type CaddyRouteTyped struct {
	ID     string            `json:"@id,omitempty"`
	Match  []CaddyMatchTyped `json:"match,omitempty"`
	Handle []CaddyHandler    `json:"handle,omitempty"`
}

// CaddyMatchTyped represents typed match conditions for a route
type CaddyMatchTyped struct {
	Host []string `json:"host,omitempty"`
	Path []string `json:"path,omitempty"`
}

// CaddyHandler is an interface for Caddy handlers
// This allows type-safe handling of different handler types
type CaddyHandler interface {
	HandlerName() string
}

// CaddyReverseProxyHandler represents a reverse_proxy handler configuration
type CaddyReverseProxyHandler struct {
	Handler   string               `json:"handler"` // Always "reverse_proxy"
	Upstreams []CaddyUpstreamTyped `json:"upstreams"`
	Headers   *CaddyHeadersConfig  `json:"headers,omitempty"`
	Transport *CaddyHTTPTransport  `json:"transport,omitempty"` // For gRPC/HTTP2 support
}

// CaddyHTTPTransport represents the HTTP transport configuration
// Used to enable HTTP/2 (h2c) for gRPC proxying
type CaddyHTTPTransport struct {
	Protocol string   `json:"protocol"`           // Always "http" for HTTP transport
	Versions []string `json:"versions,omitempty"` // ["h2c", "2"] for gRPC
}

// NewGRPCTransport creates a transport configuration for gRPC (HTTP/2 cleartext)
func NewGRPCTransport() *CaddyHTTPTransport {
	return &CaddyHTTPTransport{
		Protocol: "http",
		Versions: []string{"h2c", "2"},
	}
}

// HandlerName implements CaddyHandler
func (h CaddyReverseProxyHandler) HandlerName() string {
	return "reverse_proxy"
}

// CaddyUpstreamTyped represents a typed upstream server configuration
type CaddyUpstreamTyped struct {
	Dial string `json:"dial"` // Format: "host:port"
}

// CaddyHeadersConfig represents header manipulation configuration
type CaddyHeadersConfig struct {
	Request  *CaddyHeaderOps `json:"request,omitempty"`
	Response *CaddyHeaderOps `json:"response,omitempty"`
}

// CaddyHeaderOps represents header operations (add, set, delete)
type CaddyHeaderOps struct {
	Add    map[string][]string `json:"add,omitempty"`
	Set    map[string][]string `json:"set,omitempty"`
	Delete []string            `json:"delete,omitempty"`
}

// CaddyStaticResponseHandler represents a static_response handler
type CaddyStaticResponseHandler struct {
	Handler    string              `json:"handler"` // Always "static_response"
	StatusCode int                 `json:"status_code,omitempty"`
	Headers    map[string][]string `json:"headers,omitempty"`
	Body       string              `json:"body,omitempty"`
}

// HandlerName implements CaddyHandler
func (h CaddyStaticResponseHandler) HandlerName() string {
	return "static_response"
}

// CaddyTLSAutomationPolicy represents a TLS automation policy
type CaddyTLSAutomationPolicy struct {
	Subjects      []string         `json:"subjects,omitempty"`
	Issuers       []CaddyTLSIssuer `json:"issuers,omitempty"`
	OnDemand      bool             `json:"on_demand,omitempty"`
	MustStaple    bool             `json:"must_staple,omitempty"`
	RenewalWindow string           `json:"renewal_window,omitempty"` // Duration string, e.g., "720h"
}

// CaddyTLSIssuer represents a TLS certificate issuer configuration
type CaddyTLSIssuer struct {
	Module               string               `json:"module"`          // "acme", "internal", "zerossl"
	CA                   string               `json:"ca,omitempty"`    // ACME CA URL
	Email                string               `json:"email,omitempty"` // ACME account email
	ExternalAccountKey   string               `json:"external_account,omitempty"`
	TrustedRootsPEMFiles []string             `json:"trusted_roots_pem_files,omitempty"`
	Challenges           *CaddyACMEChallenges `json:"challenges,omitempty"` // DNS-01 opt-in; nil = Caddy default (HTTP-01 + TLS-ALPN-01)
}

// CaddyACMEChallenges configures which ACME challenge types the issuer may
// use. Only the DNS-01 path is modeled here — it's the one that can issue
// wildcard certs and sidesteps the HTTP-01 redirect failure mode. Leaving
// this nil keeps Caddy's default HTTP-01 + TLS-ALPN-01 behavior.
type CaddyACMEChallenges struct {
	DNS *CaddyDNSChallenge `json:"dns,omitempty"`
}

// CaddyDNSChallenge holds the DNS-01 provider configuration. Provider is a
// type-erased object because each caddy-dns module has its own schema (e.g.
// cloudflare uses {"name":"cloudflare","api_token":"..."}, route53 reads the
// AWS environment with just {"name":"route53"}). The Caddy binary must be
// built with the matching dns.providers.<name> module — see
// internal/hosting/caddy.go for the xcaddy build path.
type CaddyDNSChallenge struct {
	Provider map[string]interface{} `json:"provider"`
}

// CaddyTLSAutomation represents the TLS automation configuration
type CaddyTLSAutomation struct {
	Policies []CaddyTLSAutomationPolicy `json:"policies,omitempty"`
}

// CaddyTLSApp represents the TLS app configuration
type CaddyTLSApp struct {
	Automation *CaddyTLSAutomation `json:"automation,omitempty"`
}

// CaddyHTTPApp represents the HTTP app configuration
type CaddyHTTPApp struct {
	Servers map[string]*CaddyServerConfig `json:"servers,omitempty"`
}

// --- Layer 4 (caddy-l4) types for SNI-based TLS passthrough ---

// CaddyL4App represents the layer4 app configuration
type CaddyL4App struct {
	Servers map[string]*CaddyL4Server `json:"servers"`
}

// CaddyL4Server represents a layer4 server with listeners and routes
type CaddyL4Server struct {
	Listen []string       `json:"listen"`
	Routes []CaddyL4Route `json:"routes"`
}

// CaddyL4Route represents a layer4 route with match conditions and handlers
type CaddyL4Route struct {
	Match  []CaddyL4Match   `json:"match,omitempty"`
	Handle []CaddyL4Handler `json:"handle"`
}

// CaddyL4Match represents match conditions for a layer4 route
type CaddyL4Match struct {
	TLS *CaddyL4TLSMatch `json:"tls,omitempty"`
}

// CaddyL4TLSMatch matches TLS ClientHello SNI field
type CaddyL4TLSMatch struct {
	SNI []string `json:"sni"`
}

// CaddyL4Handler represents a layer4 handler (proxy or subroute).
// ProxyProtocol is set on the catchall's proxy handler to "v2" when the L4
// server is in PROXY-aware mode — caddy-l4 then re-emits a PROXY v2 header
// to the upstream HTTP server (srv0) so srv0's listener_wrapper can recover
// the parsed source.
type CaddyL4Handler struct {
	Handler       string            `json:"handler"`
	Upstreams     []CaddyL4Upstream `json:"upstreams,omitempty"`
	ProxyProtocol string            `json:"proxy_protocol,omitempty"`
}

// CaddyL4Upstream represents an upstream for layer4 proxy
type CaddyL4Upstream struct {
	Dial []string `json:"dial"`
}

// CaddyConfig represents the top-level Caddy configuration
type CaddyConfig struct {
	Admin *CaddyAdminConfig `json:"admin,omitempty"`
	Apps  *CaddyApps        `json:"apps,omitempty"`
}

// CaddyAdminConfig represents admin API configuration
type CaddyAdminConfig struct {
	Listen string `json:"listen,omitempty"` // e.g., ":2019" or "localhost:2019"
}

// CaddyApps contains all Caddy app configurations
type CaddyApps struct {
	HTTP *CaddyHTTPApp `json:"http,omitempty"`
	TLS  *CaddyTLSApp  `json:"tls,omitempty"`
}

// NewReverseProxyRoute creates a typed reverse proxy route for HTTP
func NewReverseProxyRoute(id string, hosts []string, upstreamDial string) CaddyRouteTyped {
	return CaddyRouteTyped{
		ID: id,
		Match: []CaddyMatchTyped{
			{Host: hosts},
		},
		Handle: []CaddyHandler{
			CaddyReverseProxyHandler{
				Handler: "reverse_proxy",
				Upstreams: []CaddyUpstreamTyped{
					{Dial: upstreamDial},
				},
			},
		},
	}
}

// NewGRPCReverseProxyRoute creates a typed reverse proxy route for gRPC
// gRPC requires HTTP/2 (h2c for cleartext to backend)
func NewGRPCReverseProxyRoute(id string, hosts []string, upstreamDial string) CaddyRouteTyped {
	return CaddyRouteTyped{
		ID: id,
		Match: []CaddyMatchTyped{
			{Host: hosts},
		},
		Handle: []CaddyHandler{
			CaddyReverseProxyHandler{
				Handler: "reverse_proxy",
				Upstreams: []CaddyUpstreamTyped{
					{Dial: upstreamDial},
				},
				Transport: NewGRPCTransport(),
			},
		},
	}
}

// NewACMEIssuer creates a Let's Encrypt ACME issuer
func NewACMEIssuer() CaddyTLSIssuer {
	return CaddyTLSIssuer{
		Module: "acme",
	}
}

// NewZeroSSLIssuer creates a ZeroSSL ACME issuer
func NewZeroSSLIssuer() CaddyTLSIssuer {
	return CaddyTLSIssuer{
		Module: "acme",
		CA:     "https://acme.zerossl.com/v2/DV90",
	}
}

// issuersFor returns the standard ACME + ZeroSSL issuers, attaching the
// DNS-01 challenge config to each when dns is non-nil (both CAs support
// DNS-01). When dns is nil the issuers carry no `challenges` field, so the
// emitted JSON is identical to the pre-DNS-01 default (HTTP-01 + TLS-ALPN-01).
func issuersFor(dns *CaddyACMEChallenges) []CaddyTLSIssuer {
	acme := NewACMEIssuer()
	zerossl := NewZeroSSLIssuer()
	acme.Challenges = dns
	zerossl.Challenges = dns
	return []CaddyTLSIssuer{acme, zerossl}
}

// NewTLSPolicy creates a TLS automation policy with default issuers
// (HTTP-01 + TLS-ALPN-01).
func NewTLSPolicy(subjects []string) CaddyTLSAutomationPolicy {
	return NewTLSPolicyWithDNS(subjects, nil)
}

// NewTLSPolicyWithDNS creates a TLS automation policy whose issuers solve
// DNS-01 via the given challenge config. Passing nil is equivalent to
// NewTLSPolicy. DNS-01 is required for wildcard subjects (e.g.
// "*.example.com").
func NewTLSPolicyWithDNS(subjects []string, dns *CaddyACMEChallenges) CaddyTLSAutomationPolicy {
	return CaddyTLSAutomationPolicy{
		Subjects: subjects,
		Issuers:  issuersFor(dns),
	}
}

// DNSChallengeFromEnv builds a DNS-01 challenge config from the daemon's
// environment, or returns nil (the default — HTTP-01 + TLS-ALPN-01) when
// DNS-01 isn't opted into.
//
//   - CONTAINARIUM_ACME_DNS_PROVIDER — the caddy-dns provider name, e.g.
//     "cloudflare". Empty/unset → DNS-01 disabled, returns nil.
//   - CONTAINARIUM_ACME_DNS_PROVIDER_CONFIG — optional JSON object of
//     provider-specific fields merged into the provider block, so any
//     caddy-dns module works without hardcoding its schema, e.g.
//     '{"api_token":"{env.MY_TOKEN}"}'. Caddy expands {env.X} at load time,
//     so the secret itself is never placed in this process's config or logs.
//
// As a convenience for the common case, "cloudflare" defaults api_token to
// "{env.CF_API_TOKEN}" when not overridden. The Caddy binary must be built
// with the matching dns.providers.<name> module.
func DNSChallengeFromEnv() *CaddyACMEChallenges {
	provider := strings.TrimSpace(os.Getenv("CONTAINARIUM_ACME_DNS_PROVIDER"))
	if provider == "" {
		return nil
	}
	prov := map[string]interface{}{"name": provider}
	if raw := strings.TrimSpace(os.Getenv("CONTAINARIUM_ACME_DNS_PROVIDER_CONFIG")); raw != "" {
		var extra map[string]interface{}
		if err := json.Unmarshal([]byte(raw), &extra); err == nil {
			for k, v := range extra {
				prov[k] = v
			}
		}
	}
	if provider == "cloudflare" {
		if _, ok := prov["api_token"]; !ok {
			prov["api_token"] = "{env.CF_API_TOKEN}"
		}
	}
	return &CaddyACMEChallenges{DNS: &CaddyDNSChallenge{Provider: prov}}
}

// dnsProviderModules maps a caddy-dns provider name to its Go module path,
// for the xcaddy build of Caddy. This is the single source of truth shared by
// the core Caddy build (internal/server.setupCaddy) and the hosting Caddy
// build (internal/hosting.CaddyManager.providerModule): the build must compile
// in the matching dns.providers.<name> module or Caddy rejects the DNS-01
// config the daemon emits.
var dnsProviderModules = map[string]string{
	"cloudflare":     "github.com/caddy-dns/cloudflare",
	"route53":        "github.com/caddy-dns/route53",
	"godaddy":        "github.com/caddy-dns/godaddy",
	"googleclouddns": "github.com/caddy-dns/googleclouddns",
	"digitalocean":   "github.com/caddy-dns/digitalocean",
	"azure":          "github.com/caddy-dns/azure",
	"vultr":          "github.com/caddy-dns/vultr",
	"duckdns":        "github.com/caddy-dns/duckdns",
	"namecheap":      "github.com/caddy-dns/namecheap",
}

// DNSProviderModule returns the xcaddy `--with` module path for a caddy-dns
// provider name, or "" if unknown. Used by the core Caddy build to compile in
// the DNS-01 provider the daemon is configured to emit (#378).
func DNSProviderModule(provider string) string {
	return dnsProviderModules[strings.TrimSpace(provider)]
}

// DNSProviderFromEnv returns the configured caddy-dns provider name (from
// CONTAINARIUM_ACME_DNS_PROVIDER), or "" when DNS-01 isn't opted into.
func DNSProviderFromEnv() string {
	return strings.TrimSpace(os.Getenv("CONTAINARIUM_ACME_DNS_PROVIDER"))
}
