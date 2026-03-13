package hosting

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
	"time"
)

const (
	// DefaultCaddyBin is the default path to the Caddy binary
	DefaultCaddyBin = "/usr/local/bin/caddy"

	// DefaultCaddyfile is the default path to the Caddyfile
	DefaultCaddyfile = "/etc/caddy/Caddyfile"

	// DefaultCaddyService is the path to the Caddy systemd service
	DefaultCaddyService = "/etc/systemd/system/caddy.service"
)

// CaddyConfig holds configuration for Caddy setup
type CaddyConfig struct {
	// Domain is the base domain for app hosting
	Domain string

	// Email is the email for Let's Encrypt notifications
	Email string

	// Provider is the DNS provider name
	Provider string

	// ProviderEnvVar is the environment variable name for the provider credentials
	ProviderEnvVar string

	// ProviderCredential is the credential value (e.g., API key:secret)
	ProviderCredential string

	// CaddyBin is the path to the Caddy binary
	CaddyBin string

	// Caddyfile is the path to the Caddyfile
	Caddyfile string

	// NoWildcard skips wildcard domain configuration (only main domain)
	NoWildcard bool
}

// CaddyManager handles Caddy installation and configuration
type CaddyManager struct {
	config CaddyConfig
}

// NewCaddyManager creates a new Caddy manager
func NewCaddyManager(cfg CaddyConfig) *CaddyManager {
	if cfg.CaddyBin == "" {
		cfg.CaddyBin = DefaultCaddyBin
	}
	if cfg.Caddyfile == "" {
		cfg.Caddyfile = DefaultCaddyfile
	}
	return &CaddyManager{config: cfg}
}

// providerModule returns the Go module path for the DNS provider
func (m *CaddyManager) providerModule() string {
	modules := map[string]string{
		"godaddy":        "github.com/caddy-dns/godaddy",
		"cloudflare":    "github.com/caddy-dns/cloudflare",
		"route53":       "github.com/caddy-dns/route53",
		"googleclouddns": "github.com/caddy-dns/googleclouddns",
		"digitalocean":  "github.com/caddy-dns/digitalocean",
		"azure":         "github.com/caddy-dns/azure",
		"vultr":         "github.com/caddy-dns/vultr",
		"duckdns":       "github.com/caddy-dns/duckdns",
		"namecheap":     "github.com/caddy-dns/namecheap",
	}
	return modules[m.config.Provider]
}

// dnsConfigBlock returns the Caddyfile DNS configuration block for the provider
func (m *CaddyManager) dnsConfigBlock() string {
	configs := map[string]string{
		"godaddy":        "dns godaddy { api_token {env.GODADDY_API_TOKEN} }",
		"cloudflare":    "dns cloudflare {env.CF_API_TOKEN}",
		"route53":       "dns route53",
		"googleclouddns": "dns googleclouddns {env.GCP_PROJECT}",
		"digitalocean":  "dns digitalocean {env.DO_AUTH_TOKEN}",
		"azure":         "dns azure",
		"vultr":         "dns vultr {env.VULTR_API_KEY}",
		"duckdns":       "dns duckdns {env.DUCKDNS_API_TOKEN}",
		"namecheap":     "dns namecheap",
	}
	return configs[m.config.Provider]
}

// IsCaddyInstalled checks if Caddy is installed with the required DNS plugin
func (m *CaddyManager) IsCaddyInstalled() bool {
	if _, err := os.Stat(m.config.CaddyBin); os.IsNotExist(err) {
		return false
	}

	// Check if the DNS provider module is included
	cmd := exec.Command(m.config.CaddyBin, "list-modules")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	// Look for dns.providers.<provider> and layer4 module
	expectedModule := fmt.Sprintf("dns.providers.%s", m.config.Provider)
	outputStr := string(output)
	return strings.Contains(outputStr, expectedModule) && strings.Contains(outputStr, "layer4")
}

// InstallCaddy installs Caddy with the DNS provider plugin using xcaddy
func (m *CaddyManager) InstallCaddy(ctx context.Context) error {
	// Check if Go is installed
	if _, err := exec.LookPath("go"); err != nil {
		return fmt.Errorf("Go is required to build Caddy: %w", err)
	}

	// Install xcaddy if not present
	if _, err := exec.LookPath("xcaddy"); err != nil {
		cmd := exec.CommandContext(ctx, "go", "install", "github.com/caddyserver/xcaddy/cmd/xcaddy@latest")
		cmd.Env = append(os.Environ(), "GOBIN=/usr/local/bin")
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("install xcaddy: %s: %w", string(output), err)
		}
	}

	// Build Caddy with DNS provider plugin
	module := m.providerModule()
	if module == "" {
		return fmt.Errorf("no module defined for provider: %s", m.config.Provider)
	}

	buildDir := "/tmp/caddy-build"
	if err := os.MkdirAll(buildDir, 0755); err != nil {
		return fmt.Errorf("create build dir: %w", err)
	}

	cmd := exec.CommandContext(ctx, "xcaddy", "build",
		"--with", module,
		"--with", "github.com/mholt/caddy-l4",
		"--output", m.config.CaddyBin)
	cmd.Dir = buildDir
	cmd.Env = os.Environ()

	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("build caddy: %s: %w", string(output), err)
	}

	// Make executable
	if err := os.Chmod(m.config.CaddyBin, 0755); err != nil {
		return fmt.Errorf("chmod caddy: %w", err)
	}

	return nil
}

// caddyfileTemplate is the template for generating Caddyfile
const caddyfileTemplate = `# Caddy configuration for Containarium App Hosting
# Generated by containarium hosting setup on {{.Timestamp}}

{
    # Admin API for dynamic route configuration
    admin localhost:2019

    # Email for Let's Encrypt notifications
    email {{.Email}}
}
{{if not .NoWildcard}}
# Wildcard domain with DNS-01 challenge for automatic TLS
*.{{.Domain}} {
    tls {
        {{.DNSConfig}}
    }

    # Default response for unconfigured subdomains
    respond "App not found" 404
}
{{end}}
# Main domain - Containarium API gateway
{{.Domain}} {
    tls {
        {{.DNSConfig}}
    }

    # Proxy to Containarium REST API
    reverse_proxy localhost:8080
}
`

// WriteCaddyfile generates and writes the Caddyfile
func (m *CaddyManager) WriteCaddyfile() error {
	// Ensure directory exists
	dir := filepath.Dir(m.config.Caddyfile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create caddy config dir: %w", err)
	}

	tmpl, err := template.New("caddyfile").Parse(caddyfileTemplate)
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}

	data := struct {
		Domain     string
		Email      string
		DNSConfig  string
		Timestamp  string
		NoWildcard bool
	}{
		Domain:     m.config.Domain,
		Email:      m.config.Email,
		DNSConfig:  m.dnsConfigBlock(),
		Timestamp:  time.Now().Format(time.RFC3339),
		NoWildcard: m.config.NoWildcard,
	}

	f, err := os.Create(m.config.Caddyfile)
	if err != nil {
		return fmt.Errorf("create caddyfile: %w", err)
	}
	defer f.Close()

	if err := tmpl.Execute(f, data); err != nil {
		return fmt.Errorf("execute template: %w", err)
	}

	return nil
}

// systemdTemplate is the template for the Caddy systemd service
const systemdTemplate = `[Unit]
Description=Caddy - App Hosting Reverse Proxy
Documentation=https://caddyserver.com/docs/
After=network.target network-online.target
Requires=network-online.target

[Service]
Type=notify
User=caddy
Group=caddy
ExecStart={{.CaddyBin}} run --environ --config {{.Caddyfile}}
ExecReload={{.CaddyBin}} reload --config {{.Caddyfile}} --force
TimeoutStopSec=5s
LimitNOFILE=1048576
PrivateTmp=true
AmbientCapabilities=CAP_NET_BIND_SERVICE

# DNS provider credentials
Environment={{.EnvVar}}={{.Credential}}

[Install]
WantedBy=multi-user.target
`

// WriteSystemdService creates the Caddy systemd service file
func (m *CaddyManager) WriteSystemdService() error {
	tmpl, err := template.New("systemd").Parse(systemdTemplate)
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}

	data := struct {
		CaddyBin   string
		Caddyfile  string
		EnvVar     string
		Credential string
	}{
		CaddyBin:   m.config.CaddyBin,
		Caddyfile:  m.config.Caddyfile,
		EnvVar:     m.config.ProviderEnvVar,
		Credential: m.config.ProviderCredential,
	}

	f, err := os.Create(DefaultCaddyService)
	if err != nil {
		return fmt.Errorf("create service file: %w", err)
	}
	defer f.Close()

	if err := tmpl.Execute(f, data); err != nil {
		return fmt.Errorf("execute template: %w", err)
	}

	return nil
}

// EnsureCaddyUser creates the caddy system user if it doesn't exist
func (m *CaddyManager) EnsureCaddyUser() error {
	// Check if user exists
	cmd := exec.Command("id", "caddy")
	if err := cmd.Run(); err == nil {
		return nil // User already exists
	}

	// Create user
	cmd = exec.Command("useradd", "--system", "--home", "/var/lib/caddy", "--shell", "/usr/sbin/nologin", "caddy")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("create caddy user: %s: %w", string(output), err)
	}

	// Create home directory
	if err := os.MkdirAll("/var/lib/caddy", 0755); err != nil {
		return fmt.Errorf("create caddy home: %w", err)
	}

	// Set ownership
	cmd = exec.Command("chown", "-R", "caddy:caddy", "/var/lib/caddy")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("chown caddy home: %s: %w", string(output), err)
	}

	return nil
}

// ReloadSystemd reloads the systemd daemon
func (m *CaddyManager) ReloadSystemd() error {
	cmd := exec.Command("systemctl", "daemon-reload")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %s: %w", string(output), err)
	}
	return nil
}

// EnableAndStartCaddy enables and starts the Caddy service
func (m *CaddyManager) EnableAndStartCaddy() error {
	// Enable service
	cmd := exec.Command("systemctl", "enable", "caddy")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl enable caddy: %s: %w", string(output), err)
	}

	// Restart service (handles both start and restart cases)
	cmd = exec.Command("systemctl", "restart", "caddy")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl restart caddy: %s: %w", string(output), err)
	}

	return nil
}

// IsCaddyRunning checks if Caddy is running
func (m *CaddyManager) IsCaddyRunning() bool {
	cmd := exec.Command("systemctl", "is-active", "--quiet", "caddy")
	return cmd.Run() == nil
}

// Setup performs the complete Caddy setup
func (m *CaddyManager) Setup(ctx context.Context) error {
	// Install Caddy if needed
	if !m.IsCaddyInstalled() {
		if err := m.InstallCaddy(ctx); err != nil {
			return fmt.Errorf("install caddy: %w", err)
		}
	}

	// Ensure caddy user exists
	if err := m.EnsureCaddyUser(); err != nil {
		return fmt.Errorf("ensure caddy user: %w", err)
	}

	// Write Caddyfile
	if err := m.WriteCaddyfile(); err != nil {
		return fmt.Errorf("write caddyfile: %w", err)
	}

	// Write systemd service
	if err := m.WriteSystemdService(); err != nil {
		return fmt.Errorf("write systemd service: %w", err)
	}

	// Reload systemd
	if err := m.ReloadSystemd(); err != nil {
		return fmt.Errorf("reload systemd: %w", err)
	}

	// Start Caddy
	if err := m.EnableAndStartCaddy(); err != nil {
		return fmt.Errorf("start caddy: %w", err)
	}

	return nil
}
