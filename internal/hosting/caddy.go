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

	"github.com/footprintai/containarium/internal/app"
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

	// WAF, when true, builds Caddy with the coraza-caddy WAF module (Tier 3
	// PR-3, #662) so ingress routes can run the OWASP CRS. Off by default — the
	// module is only pulled into the build when an operator opts into ingress WAF,
	// keeping the default Caddy build (and its dependency surface) unchanged.
	WAF bool
}

// corazaCaddyModule is the coraza-caddy WAF plugin added to the xcaddy build
// when CaddyConfig.WAF is set. Pinned major version; the exact patch is resolved
// by xcaddy/go at build time.
const corazaCaddyModule = "github.com/corazawaf/coraza-caddy/v2"

// xcaddyBuildArgs assembles the `xcaddy build` arguments: always the DNS
// provider + caddy-l4, plus the coraza WAF module when waf is set (#662 PR-3),
// then the output path. Pure so the gating is unit-tested without running xcaddy.
func xcaddyBuildArgs(providerModule string, waf bool, output string) []string {
	args := []string{"build",
		"--with", providerModule,
		"--with", "github.com/mholt/caddy-l4",
	}
	if waf {
		args = append(args, "--with", corazaCaddyModule)
	}
	return append(args, "--output", output)
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

// providerModule returns the Go module path for the configured DNS provider.
// Delegates to app.DNSProviderModule — the single source of truth shared with
// the core Caddy build (internal/server.setupCaddy) so the two can't drift.
func (m *CaddyManager) providerModule() string {
	return app.DNSProviderModule(m.config.Provider)
}

// dnsConfigBlock returns the Caddyfile DNS configuration block for the provider
func (m *CaddyManager) dnsConfigBlock() string {
	configs := map[string]string{
		"godaddy":        "dns godaddy { api_token {env.GODADDY_API_TOKEN} }",
		"cloudflare":     "dns cloudflare {env.CF_API_TOKEN}",
		"route53":        "dns route53",
		"googleclouddns": "dns googleclouddns {env.GCP_PROJECT}",
		"digitalocean":   "dns digitalocean {env.DO_AUTH_TOKEN}",
		"azure":          "dns azure",
		"vultr":          "dns vultr {env.VULTR_API_KEY}",
		"duckdns":        "dns duckdns {env.DUCKDNS_API_TOKEN}",
		"namecheap":      "dns namecheap",
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
	if !strings.Contains(outputStr, expectedModule) || !strings.Contains(outputStr, "layer4") {
		return false
	}
	// When WAF is requested, the coraza handler (http.handlers.waf) must be in
	// the build too — otherwise a route's WAF handler would fail to load.
	if m.config.WAF && !strings.Contains(outputStr, "http.handlers.waf") {
		return false
	}
	return true
}

// InstallCaddy installs Caddy with the DNS provider plugin using xcaddy
func (m *CaddyManager) InstallCaddy(ctx context.Context) error {
	// Check if Go is installed
	if _, err := exec.LookPath("go"); err != nil {
		return fmt.Errorf("the Go toolchain is required to build Caddy: %w", err)
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
	if err := os.MkdirAll(buildDir, 0755); err != nil { //nolint:gosec // G301: ephemeral build dir, no secrets
		return fmt.Errorf("create build dir: %w", err)
	}

	// #nosec G204 -- args are a DNS-provider module name resolved from config,
	// compile-time-constant module paths, and the configured output path; no
	// user/tainted input reaches the command line.
	cmd := exec.CommandContext(ctx, "xcaddy", xcaddyBuildArgs(module, m.config.WAF, m.config.CaddyBin)...)
	cmd.Dir = buildDir
	cmd.Env = os.Environ()

	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("build caddy: %s: %w", string(output), err)
	}

	// Make executable
	if err := os.Chmod(m.config.CaddyBin, 0755); err != nil { //nolint:gosec // G302: the Caddy binary needs the executable bit (0755)
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

    # Audit C-MED-2: pin TLS floor and cipher suites. Caddy's
    # defaults already prefer TLS 1.3, but the global directive
    # below makes the floor explicit and survives any future
    # default change. "protocols tls1.2 tls1.3" keeps TLS 1.2
    # available for older clients while refusing anything older.
    # "ciphers" lists only AEAD suites (no CBC, no RC4) -- the
    # 1.3 set is hard-coded by the protocol, so this only
    # affects 1.2 fallback.
    servers {
        protocols tls1.2 tls1.3
    }
}
{{if not .NoWildcard}}
# Wildcard domain with DNS-01 challenge for automatic TLS
*.{{.Domain}} {
    tls {
        {{.DNSConfig}}
        ciphers TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305 TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305
        curves x25519 secp384r1 secp256r1
    }

    # Default response for unconfigured subdomains
    respond "App not found" 404
}
{{end}}
# Main domain - Containarium API gateway
{{.Domain}} {
    tls {
        {{.DNSConfig}}
        ciphers TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305 TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305
        curves x25519 secp384r1 secp256r1
    }

    # Proxy to Containarium REST API
    reverse_proxy localhost:8080
}
`

// WriteCaddyfile generates and writes the Caddyfile
func (m *CaddyManager) WriteCaddyfile() error {
	// Ensure directory exists
	dir := filepath.Dir(m.config.Caddyfile)
	if err := os.MkdirAll(dir, 0755); err != nil { //nolint:gosec // G301: standard config dir, not secret-bearing
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
	defer func() { _ = f.Close() }()

	if err := tmpl.Execute(f, data); err != nil {
		return fmt.Errorf("execute template: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close caddyfile: %w", err)
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
	defer func() { _ = f.Close() }()

	if err := tmpl.Execute(f, data); err != nil {
		return fmt.Errorf("execute template: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close service file: %w", err)
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

	// Create home directory. Mode 0750 instead of 0755 so the
	// caddy group can read (Caddy itself runs as caddy:caddy)
	// but world cannot — TLS private keys live under here. The
	// daemon refuses to start the Caddy service if the existing
	// dir has more-permissive bits set (see CheckStorageDirPerms).
	// Audit C-MED-7.
	if err := os.MkdirAll("/var/lib/caddy", 0o750); err != nil {
		return fmt.Errorf("create caddy home: %w", err)
	}

	// Set ownership
	cmd = exec.Command("chown", "-R", "caddy:caddy", "/var/lib/caddy")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("chown caddy home: %s: %w", string(output), err)
	}

	// Tighten existing dir mode (in case it was created at 0755
	// by a previous version). chmod is idempotent. 0750 is
	// intentional — the caddy:caddy group needs read access for
	// the daemon process; world bits stay off.
	if err := os.Chmod("/var/lib/caddy", 0o750); err != nil { // #nosec G302 -- group access is required for caddy:caddy
		return fmt.Errorf("chmod caddy home: %w", err)
	}

	return nil
}

// CheckStorageDirPerms refuses to proceed if `dir` (typically
// /var/lib/caddy/.local/share/caddy — the ACME storage path that
// holds TLS private keys) has any non-owner/group bit set. The
// caddy daemon needs the keys readable as caddy:caddy; nothing
// else should be able to see them.
//
// Audit C-MED-7. Symmetric with the master-key perm check in
// pkg/core/secrets/crypto.go and the JWT-token-file check in
// internal/mcp/client.go.
func CheckStorageDirPerms(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("stat Caddy storage %s: %w", dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("caddy storage path %s is not a directory", dir)
	}
	if perm := info.Mode().Perm(); perm&0o007 != 0 {
		return fmt.Errorf("caddy storage %s has insecure permissions %#o (world bits set); chmod o-rwx it — TLS private keys live here", dir, perm)
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

// EnableAndStartCaddy enables and starts the Caddy service.
// Refuses to start if /var/lib/caddy has world-readable bits
// (audit C-MED-7) — TLS private keys live under there.
// The check is a stat() of the existing dir; if it didn't
// exist, EnsureCaddyUser created it at 0750 just above.
func (m *CaddyManager) EnableAndStartCaddy() error {
	if err := CheckStorageDirPerms("/var/lib/caddy"); err != nil {
		return fmt.Errorf("refusing to start Caddy: %w", err)
	}

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
