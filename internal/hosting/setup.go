package hosting

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// SetupConfig holds all configuration for hosting setup
type SetupConfig struct {
	// Domain is the base domain for app hosting
	Domain string

	// Email is the email for Let's Encrypt notifications
	Email string

	// Provider configuration
	Provider  string
	APIKey    string
	APISecret string

	// ServerIP is the server's public IP address (auto-detected if empty)
	ServerIP string

	// SkipDNS skips DNS record creation
	SkipDNS bool

	// SkipCaddy skips Caddy installation
	SkipCaddy bool

	// NoWildcard skips wildcard DNS/SSL (only provision main domain)
	NoWildcard bool

	// Verbose enables verbose output
	Verbose bool
}

// SetupResult holds the result of the setup process
type SetupResult struct {
	ServerIP    string
	DNSCreated  bool
	CaddySetup  bool
	CaddyStatus string
}

// Setup performs the complete hosting setup
type Setup struct {
	config   SetupConfig
	provider DNSProvider
	caddy    *CaddyManager
	logger   func(format string, args ...interface{})
}

// NewSetup creates a new Setup instance
func NewSetup(cfg SetupConfig, logger func(format string, args ...interface{})) (*Setup, error) {
	if logger == nil {
		logger = func(format string, args ...interface{}) {}
	}

	// Create DNS provider
	provider, err := NewProvider(ProviderConfig{
		Provider:  cfg.Provider,
		APIKey:    cfg.APIKey,
		APISecret: cfg.APISecret,
	})
	if err != nil {
		return nil, err
	}

	// Determine provider environment variable name
	envVars := map[string]string{
		"godaddy":        "GODADDY_API_TOKEN",
		"cloudflare":     "CF_API_TOKEN",
		"route53":        "AWS_ACCESS_KEY_ID",
		"googleclouddns": "GCP_PROJECT",
		"digitalocean":   "DO_AUTH_TOKEN",
		"azure":          "AZURE_CLIENT_ID",
		"vultr":          "VULTR_API_KEY",
		"duckdns":        "DUCKDNS_API_TOKEN",
		"namecheap":      "NAMECHEAP_API_KEY",
	}

	// Format credential based on provider
	var credential string
	switch cfg.Provider {
	case "godaddy":
		credential = fmt.Sprintf("%s:%s", cfg.APIKey, cfg.APISecret)
	default:
		credential = cfg.APIKey
	}

	// Create Caddy manager
	caddy := NewCaddyManager(CaddyConfig{
		Domain:             cfg.Domain,
		Email:              cfg.Email,
		Provider:           cfg.Provider,
		ProviderEnvVar:     envVars[cfg.Provider],
		ProviderCredential: credential,
		NoWildcard:         cfg.NoWildcard,
	})

	return &Setup{
		config:   cfg,
		provider: provider,
		caddy:    caddy,
		logger:   logger,
	}, nil
}

// Run executes the complete setup process
func (s *Setup) Run(ctx context.Context) (*SetupResult, error) {
	result := &SetupResult{}

	// Step 1: Verify credentials
	s.logger("Verifying %s API credentials...", s.config.Provider)
	if err := s.provider.VerifyCredentials(ctx); err != nil {
		return nil, fmt.Errorf("invalid API credentials: %w", err)
	}
	s.logger("API credentials verified")

	// Step 2: Verify domain ownership
	s.logger("Verifying domain '%s'...", s.config.Domain)
	if err := s.provider.VerifyDomain(ctx, s.config.Domain); err != nil {
		return nil, fmt.Errorf("domain verification failed: %w", err)
	}
	s.logger("Domain '%s' verified", s.config.Domain)

	// Step 3: Detect server IP if not provided
	if s.config.ServerIP == "" {
		s.logger("Detecting server IP address...")
		ip, err := DetectPublicIP(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to detect server IP: %w", err)
		}
		s.config.ServerIP = ip
	}
	result.ServerIP = s.config.ServerIP
	s.logger("Server IP: %s", result.ServerIP)

	// Step 4: Create DNS records
	if !s.config.SkipDNS {
		s.logger("Creating DNS records...")
		s.logger("  @ -> %s (main domain)", result.ServerIP)
		if !s.config.NoWildcard {
			s.logger("  * -> %s (wildcard)", result.ServerIP)
		}

		includeWildcard := !s.config.NoWildcard
		if err := s.provider.SetupHostingRecords(ctx, s.config.Domain, result.ServerIP, includeWildcard); err != nil {
			return nil, fmt.Errorf("failed to create DNS records: %w", err)
		}
		result.DNSCreated = true
		s.logger("DNS records created successfully")
	} else {
		s.logger("Skipping DNS record creation (--skip-dns)")
	}

	// Step 5: Setup Caddy
	if !s.config.SkipCaddy {
		s.logger("Setting up Caddy reverse proxy...")

		if !s.caddy.IsCaddyInstalled() {
			s.logger("Installing Caddy with %s DNS plugin (this may take a few minutes)...", s.config.Provider)
		}

		if err := s.caddy.Setup(ctx); err != nil {
			return nil, fmt.Errorf("failed to setup Caddy: %w", err)
		}
		result.CaddySetup = true

		// Check if Caddy is running
		if s.caddy.IsCaddyRunning() {
			result.CaddyStatus = "running"
			s.logger("Caddy is running")
		} else {
			result.CaddyStatus = "not running"
			s.logger("Warning: Caddy service is not running")
		}
	} else {
		s.logger("Skipping Caddy setup (--skip-caddy)")
	}

	return result, nil
}

// DetectPublicIP attempts to detect the server's public IP address
func DetectPublicIP(ctx context.Context) (string, error) {
	services := []string{
		"https://ifconfig.me",
		"https://ipinfo.io/ip",
		"https://api.ipify.org",
		"https://icanhazip.com",
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	for _, svc := range services {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, svc, nil)
		if err != nil {
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		ip := strings.TrimSpace(string(body))
		if ip != "" && isValidIP(ip) {
			return ip, nil
		}
	}

	return "", fmt.Errorf("could not detect public IP address")
}

// isValidIP performs a basic validation of an IP address
func isValidIP(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > 3 {
			return false
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

// VerifyHTTPS attempts to verify that HTTPS is working for the domain
func VerifyHTTPS(ctx context.Context, domain string) error {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	url := fmt.Sprintf("https://%s", domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTPS request failed: %w", err)
	}
	defer resp.Body.Close()

	// Any response means HTTPS is working (cert is valid)
	return nil
}
