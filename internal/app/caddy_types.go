package app

// Caddy API Types
// These types provide type-safe representations of Caddy's JSON API structures.
// Reference: https://caddyserver.com/docs/json/

// CaddyServerConfig represents a Caddy HTTP server configuration
type CaddyServerConfig struct {
	Listen []string          `json:"listen"`
	Routes []CaddyRouteTyped `json:"routes"` // No omitempty - Caddy needs empty array to exist
}

// CaddyRouteTyped represents a fully typed Caddy route configuration
type CaddyRouteTyped struct {
	ID     string             `json:"@id,omitempty"`
	Match  []CaddyMatchTyped  `json:"match,omitempty"`
	Handle []CaddyHandler     `json:"handle,omitempty"`
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
	Handler   string                `json:"handler"` // Always "reverse_proxy"
	Upstreams []CaddyUpstreamTyped  `json:"upstreams"`
	Headers   *CaddyHeadersConfig   `json:"headers,omitempty"`
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
	Handler    string            `json:"handler"` // Always "static_response"
	StatusCode int               `json:"status_code,omitempty"`
	Headers    map[string][]string `json:"headers,omitempty"`
	Body       string            `json:"body,omitempty"`
}

// HandlerName implements CaddyHandler
func (h CaddyStaticResponseHandler) HandlerName() string {
	return "static_response"
}

// CaddyTLSAutomationPolicy represents a TLS automation policy
type CaddyTLSAutomationPolicy struct {
	Subjects      []string          `json:"subjects,omitempty"`
	Issuers       []CaddyTLSIssuer  `json:"issuers,omitempty"`
	OnDemand      bool              `json:"on_demand,omitempty"`
	MustStaple    bool              `json:"must_staple,omitempty"`
	RenewalWindow string            `json:"renewal_window,omitempty"` // Duration string, e.g., "720h"
}

// CaddyTLSIssuer represents a TLS certificate issuer configuration
type CaddyTLSIssuer struct {
	Module                string `json:"module"`            // "acme", "internal", "zerossl"
	CA                    string `json:"ca,omitempty"`      // ACME CA URL
	Email                 string `json:"email,omitempty"`   // ACME account email
	ExternalAccountKey    string `json:"external_account,omitempty"`
	TrustedRootsPEMFiles  []string `json:"trusted_roots_pem_files,omitempty"`
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

// NewReverseProxyRoute creates a typed reverse proxy route
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

// NewTLSPolicy creates a TLS automation policy with default issuers
func NewTLSPolicy(subjects []string) CaddyTLSAutomationPolicy {
	return CaddyTLSAutomationPolicy{
		Subjects: subjects,
		Issuers: []CaddyTLSIssuer{
			NewACMEIssuer(),
			NewZeroSSLIssuer(),
		},
	}
}
