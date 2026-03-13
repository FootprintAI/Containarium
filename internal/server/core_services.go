package server

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/incus"
	"github.com/footprintai/containarium/internal/stacks"
)

const (
	// CorePostgresContainer is the name of the core PostgreSQL container
	CorePostgresContainer = "containarium-core-postgres"

	// CoreCaddyContainer is the name of the core Caddy container
	CoreCaddyContainer = "containarium-core-caddy"

	// Default PostgreSQL credentials
	DefaultPostgresUser     = "containarium"
	DefaultPostgresPassword = "containarium"
	DefaultPostgresDB       = "containarium"
	DefaultPostgresPort     = 5432

	// Default Caddy admin port
	DefaultCaddyAdminPort = 2019

	// CoreSecurityContainer is the name of the core ClamAV security container
	CoreSecurityContainer = "containarium-core-security"

	// CoreVictoriaMetricsContainer is the name of the core Victoria Metrics + Grafana container
	CoreVictoriaMetricsContainer = "containarium-core-victoriametrics"

	// Default Victoria Metrics port
	DefaultVMPort = 8428

	// Default Grafana port
	DefaultGrafanaPort = 3000

	// Default Victoria Metrics retention period
	DefaultVMRetention = "30d"
)

// CoreServicesConfig holds configuration for core services
type CoreServicesConfig struct {
	// PostgreSQL settings
	PostgresUser     string
	PostgresPassword string
	PostgresDB       string

	// Network settings
	NetworkCIDR string // e.g., "10.100.0.0/24"
}

// CoreServices manages the core infrastructure containers (PostgreSQL, Caddy, VictoriaMetrics+Grafana)
type CoreServices struct {
	incusClient        *incus.Client
	config             CoreServicesConfig
	postgresIP         string
	caddyIP            string
	victoriaMetricsIP  string
}

// NewCoreServices creates a new core services manager
func NewCoreServices(incusClient *incus.Client, config CoreServicesConfig) *CoreServices {
	if config.PostgresUser == "" {
		config.PostgresUser = DefaultPostgresUser
	}
	if config.PostgresPassword == "" {
		config.PostgresPassword = DefaultPostgresPassword
	}
	if config.PostgresDB == "" {
		config.PostgresDB = DefaultPostgresDB
	}
	if config.NetworkCIDR == "" {
		config.NetworkCIDR = "10.100.0.0/24"
	}

	return &CoreServices{
		incusClient: incusClient,
		config:      config,
	}
}

// EnsurePostgres ensures PostgreSQL container is running and returns the connection string
func (cs *CoreServices) EnsurePostgres(ctx context.Context) (string, error) {
	// Check if container already exists
	info, err := cs.incusClient.GetContainer(CorePostgresContainer)
	if err == nil {
		// Backfill role label and boot priority for containers created before this change
		cs.backfillConfig(CorePostgresContainer, incus.RolePostgres, "100")

		// Container exists
		if info.State == "Running" {
			cs.postgresIP = info.IPAddress
			log.Printf("PostgreSQL container already running at %s", cs.postgresIP)
			return cs.getPostgresConnString(), nil
		}
		// Container exists but not running, start it
		log.Printf("Starting existing PostgreSQL container...")
		if err := cs.incusClient.StartContainer(CorePostgresContainer); err != nil {
			return "", fmt.Errorf("failed to start postgres container: %w", err)
		}
		// Wait for network
		ip, err := cs.incusClient.WaitForNetwork(CorePostgresContainer, 60*time.Second)
		if err != nil {
			return "", fmt.Errorf("failed to get postgres IP: %w", err)
		}
		cs.postgresIP = ip
		// Wait for PostgreSQL to be ready
		if err := cs.waitForPostgres(ctx); err != nil {
			return "", err
		}
		return cs.getPostgresConnString(), nil
	}

	// Container doesn't exist, create it
	log.Printf("Creating PostgreSQL container...")

	config := incus.ContainerConfig{
		Name:      CorePostgresContainer,
		Image:     "images:ubuntu/24.04",
		CPU:       "2",
		Memory:    "2GB",
		AutoStart: true,
		Disk: &incus.DiskDevice{
			Path: "/",
			Pool: "default",
			Size: "10GB",
		},
	}

	if err := cs.incusClient.CreateContainer(config); err != nil {
		return "", fmt.Errorf("failed to create postgres container: %w", err)
	}

	// Set role label and boot priority
	cs.incusClient.UpdateContainerConfig(CorePostgresContainer, incus.RoleKey, string(incus.RolePostgres))
	cs.incusClient.UpdateContainerConfig(CorePostgresContainer, "boot.autostart", "true")
	cs.incusClient.UpdateContainerConfig(CorePostgresContainer, "boot.autostart.priority", "100")

	// Start container
	if err := cs.incusClient.StartContainer(CorePostgresContainer); err != nil {
		return "", fmt.Errorf("failed to start postgres container: %w", err)
	}

	// Wait for network
	ip, err := cs.incusClient.WaitForNetwork(CorePostgresContainer, 60*time.Second)
	if err != nil {
		return "", fmt.Errorf("failed to get postgres IP: %w", err)
	}
	cs.postgresIP = ip
	log.Printf("PostgreSQL container IP: %s", cs.postgresIP)

	// Install and configure PostgreSQL
	if err := cs.setupPostgres(ctx); err != nil {
		return "", fmt.Errorf("failed to setup postgres: %w", err)
	}

	// Apply base scripts (timezone, clamav) — best-effort
	cs.applyBaseScripts(CorePostgresContainer, "ubuntu")

	return cs.getPostgresConnString(), nil
}

// setupPostgres installs and configures PostgreSQL in the container
func (cs *CoreServices) setupPostgres(ctx context.Context) error {
	log.Printf("Installing PostgreSQL...")

	// Wait for apt to be available
	time.Sleep(5 * time.Second)

	// Update and install PostgreSQL
	commands := [][]string{
		{"apt-get", "update"},
		{"apt-get", "install", "-y", "postgresql", "postgresql-contrib"},
	}

	for _, cmd := range commands {
		if err := cs.incusClient.Exec(CorePostgresContainer, cmd); err != nil {
			return fmt.Errorf("failed to run %v: %w", cmd, err)
		}
	}

	// Start PostgreSQL
	if err := cs.incusClient.Exec(CorePostgresContainer, []string{"systemctl", "start", "postgresql"}); err != nil {
		return fmt.Errorf("failed to start postgresql: %w", err)
	}

	if err := cs.incusClient.Exec(CorePostgresContainer, []string{"systemctl", "enable", "postgresql"}); err != nil {
		return fmt.Errorf("failed to enable postgresql: %w", err)
	}

	// Create user and database
	createUserCmd := fmt.Sprintf("CREATE USER %s WITH PASSWORD '%s';", cs.config.PostgresUser, cs.config.PostgresPassword)
	createDBCmd := fmt.Sprintf("CREATE DATABASE %s OWNER %s;", cs.config.PostgresDB, cs.config.PostgresUser)

	if err := cs.incusClient.Exec(CorePostgresContainer, []string{
		"su", "-", "postgres", "-c", fmt.Sprintf("psql -c \"%s\"", createUserCmd),
	}); err != nil {
		// User might already exist, continue
		log.Printf("Note: PostgreSQL user might already exist")
	}

	if err := cs.incusClient.Exec(CorePostgresContainer, []string{
		"su", "-", "postgres", "-c", fmt.Sprintf("psql -c \"%s\"", createDBCmd),
	}); err != nil {
		// Database might already exist, continue
		log.Printf("Note: PostgreSQL database might already exist")
	}

	// Configure PostgreSQL to listen on all interfaces
	pgConfPath := "/etc/postgresql/16/main/postgresql.conf"
	pgHbaPath := "/etc/postgresql/16/main/pg_hba.conf"

	// Update listen_addresses
	if err := cs.incusClient.Exec(CorePostgresContainer, []string{
		"bash", "-c", fmt.Sprintf("sed -i \"s/#listen_addresses = 'localhost'/listen_addresses = '*'/\" %s", pgConfPath),
	}); err != nil {
		return fmt.Errorf("failed to update postgresql.conf: %w", err)
	}

	// Allow connections from container network
	networkPrefix := cs.config.NetworkCIDR
	hbaEntry := fmt.Sprintf("host    all             all             %s            md5", networkPrefix)
	if err := cs.incusClient.Exec(CorePostgresContainer, []string{
		"bash", "-c", fmt.Sprintf("echo '%s' >> %s", hbaEntry, pgHbaPath),
	}); err != nil {
		return fmt.Errorf("failed to update pg_hba.conf: %w", err)
	}

	// Restart PostgreSQL
	if err := cs.incusClient.Exec(CorePostgresContainer, []string{"systemctl", "restart", "postgresql"}); err != nil {
		return fmt.Errorf("failed to restart postgresql: %w", err)
	}

	// Wait for PostgreSQL to be ready
	if err := cs.waitForPostgres(ctx); err != nil {
		return err
	}

	log.Printf("PostgreSQL setup complete")
	return nil
}

// waitForPostgres waits for PostgreSQL to be ready to accept connections
func (cs *CoreServices) waitForPostgres(ctx context.Context) error {
	log.Printf("Waiting for PostgreSQL to be ready...")

	for i := 0; i < 30; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Try to connect
		if err := cs.incusClient.Exec(CorePostgresContainer, []string{
			"su", "-", "postgres", "-c", "pg_isready",
		}); err == nil {
			log.Printf("PostgreSQL is ready")
			return nil
		}

		time.Sleep(2 * time.Second)
	}

	return fmt.Errorf("timeout waiting for PostgreSQL to be ready")
}

// getPostgresConnString returns the PostgreSQL connection string
func (cs *CoreServices) getPostgresConnString() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		cs.config.PostgresUser,
		cs.config.PostgresPassword,
		cs.postgresIP,
		DefaultPostgresPort,
		cs.config.PostgresDB,
	)
}

// GetPostgresIP returns the PostgreSQL container IP
func (cs *CoreServices) GetPostgresIP() string {
	return cs.postgresIP
}

// EnsureCaddy ensures Caddy container is running and returns the admin URL
func (cs *CoreServices) EnsureCaddy(ctx context.Context, baseDomain string) (string, error) {
	// Check if container already exists
	info, err := cs.incusClient.GetContainer(CoreCaddyContainer)
	if err == nil {
		// Backfill role label and boot priority for containers created before this change
		cs.backfillConfig(CoreCaddyContainer, incus.RoleCaddy, "90")

		// Container exists
		if info.State == "Running" {
			cs.caddyIP = info.IPAddress
			log.Printf("Caddy container already running at %s", cs.caddyIP)
			return cs.getCaddyAdminURL(), nil
		}
		// Container exists but not running, start it
		log.Printf("Starting existing Caddy container...")
		if err := cs.incusClient.StartContainer(CoreCaddyContainer); err != nil {
			return "", fmt.Errorf("failed to start caddy container: %w", err)
		}
		ip, err := cs.incusClient.WaitForNetwork(CoreCaddyContainer, 60*time.Second)
		if err != nil {
			return "", fmt.Errorf("failed to get caddy IP: %w", err)
		}
		cs.caddyIP = ip
		return cs.getCaddyAdminURL(), nil
	}

	// Container doesn't exist, create it
	log.Printf("Creating Caddy container...")

	config := incus.ContainerConfig{
		Name:      CoreCaddyContainer,
		Image:     "images:ubuntu/24.04",
		CPU:       "1",
		Memory:    "512MB",
		AutoStart: true,
		Disk: &incus.DiskDevice{
			Path: "/",
			Pool: "default",
			Size: "5GB",
		},
	}

	if err := cs.incusClient.CreateContainer(config); err != nil {
		return "", fmt.Errorf("failed to create caddy container: %w", err)
	}

	// Set role label and boot priority
	cs.incusClient.UpdateContainerConfig(CoreCaddyContainer, incus.RoleKey, string(incus.RoleCaddy))
	cs.incusClient.UpdateContainerConfig(CoreCaddyContainer, "boot.autostart", "true")
	cs.incusClient.UpdateContainerConfig(CoreCaddyContainer, "boot.autostart.priority", "90")

	// Start container
	if err := cs.incusClient.StartContainer(CoreCaddyContainer); err != nil {
		return "", fmt.Errorf("failed to start caddy container: %w", err)
	}

	// Wait for network
	ip, err := cs.incusClient.WaitForNetwork(CoreCaddyContainer, 60*time.Second)
	if err != nil {
		return "", fmt.Errorf("failed to get caddy IP: %w", err)
	}
	cs.caddyIP = ip
	log.Printf("Caddy container IP: %s", cs.caddyIP)

	// Install and configure Caddy
	if err := cs.setupCaddy(ctx, baseDomain); err != nil {
		return "", fmt.Errorf("failed to setup caddy: %w", err)
	}

	// Apply base scripts (timezone, clamav) — best-effort
	cs.applyBaseScripts(CoreCaddyContainer, "ubuntu")

	return cs.getCaddyAdminURL(), nil
}

// setupCaddy installs and configures Caddy in the container.
// It builds Caddy from source with xcaddy to include the caddy-l4 plugin
// for SNI-based TLS passthrough routing.
func (cs *CoreServices) setupCaddy(ctx context.Context, baseDomain string) error {
	log.Printf("Installing Caddy with L4 plugin...")

	// Wait for apt to be available
	time.Sleep(5 * time.Second)

	// Install Go and build dependencies (needed for xcaddy)
	commands := [][]string{
		{"apt-get", "update"},
		{"apt-get", "install", "-y", "curl", "golang-go"},
	}

	for _, cmd := range commands {
		if err := cs.incusClient.Exec(CoreCaddyContainer, cmd); err != nil {
			return fmt.Errorf("failed to run %v: %w", cmd, err)
		}
	}

	// Install xcaddy
	log.Printf("Installing xcaddy...")
	if err := cs.incusClient.Exec(CoreCaddyContainer, []string{
		"bash", "-c", "GOBIN=/usr/local/bin go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest",
	}); err != nil {
		return fmt.Errorf("failed to install xcaddy: %w", err)
	}

	// Build Caddy with caddy-l4 plugin using xcaddy
	log.Printf("Building Caddy with caddy-l4 plugin (this may take a few minutes)...")
	if err := cs.incusClient.Exec(CoreCaddyContainer, []string{
		"bash", "-c", "xcaddy build --with github.com/mholt/caddy-l4 --output /usr/bin/caddy",
	}); err != nil {
		return fmt.Errorf("failed to build caddy with xcaddy: %w", err)
	}

	// Create caddy user and directories
	cs.incusClient.Exec(CoreCaddyContainer, []string{
		"bash", "-c", "id caddy >/dev/null 2>&1 || useradd --system --home /var/lib/caddy --shell /usr/sbin/nologin caddy",
	})
	cs.incusClient.Exec(CoreCaddyContainer, []string{"mkdir", "-p", "/var/lib/caddy", "/etc/caddy"})
	cs.incusClient.Exec(CoreCaddyContainer, []string{"chown", "-R", "caddy:caddy", "/var/lib/caddy"})

	// Create Caddyfile with admin API enabled
	caddyfile := `{
	admin :2019
}

# Default catch-all - will be configured dynamically via admin API
`

	if err := cs.incusClient.WriteFile(CoreCaddyContainer, "/etc/caddy/Caddyfile", []byte(caddyfile), "0644"); err != nil {
		return fmt.Errorf("failed to write Caddyfile: %w", err)
	}

	// Create systemd service for Caddy
	systemdUnit := `[Unit]
Description=Caddy
After=network.target network-online.target
Requires=network-online.target

[Service]
Type=notify
User=caddy
Group=caddy
ExecStart=/usr/bin/caddy run --environ --config /etc/caddy/Caddyfile
ExecReload=/usr/bin/caddy reload --config /etc/caddy/Caddyfile --force
TimeoutStopSec=5s
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
`
	if err := cs.incusClient.WriteFile(CoreCaddyContainer, "/etc/systemd/system/caddy.service", []byte(systemdUnit), "0644"); err != nil {
		return fmt.Errorf("failed to write caddy service: %w", err)
	}

	// Enable and start Caddy
	cs.incusClient.Exec(CoreCaddyContainer, []string{"systemctl", "daemon-reload"})
	if err := cs.incusClient.Exec(CoreCaddyContainer, []string{"systemctl", "enable", "caddy"}); err != nil {
		return fmt.Errorf("failed to enable caddy: %w", err)
	}
	if err := cs.incusClient.Exec(CoreCaddyContainer, []string{"systemctl", "restart", "caddy"}); err != nil {
		return fmt.Errorf("failed to restart caddy: %w", err)
	}

	// Wait for Caddy to be ready
	time.Sleep(3 * time.Second)

	log.Printf("Caddy setup complete (with caddy-l4 plugin)")
	return nil
}

// getCaddyAdminURL returns the Caddy admin API URL
func (cs *CoreServices) getCaddyAdminURL() string {
	return fmt.Sprintf("http://%s:%d", cs.caddyIP, DefaultCaddyAdminPort)
}

// GetCaddyIP returns the Caddy container IP
func (cs *CoreServices) GetCaddyIP() string {
	return cs.caddyIP
}

// EnsureVictoriaMetrics ensures the Victoria Metrics + Grafana container is running
func (cs *CoreServices) EnsureVictoriaMetrics(ctx context.Context, postgresIP string) (string, error) {
	// Check if container already exists
	info, err := cs.incusClient.GetContainer(CoreVictoriaMetricsContainer)
	if err == nil {
		// Backfill role label and boot priority
		cs.backfillConfig(CoreVictoriaMetricsContainer, incus.RoleVictoriaMetrics, "80")

		// Container exists
		if info.State == "Running" {
			cs.victoriaMetricsIP = info.IPAddress
			log.Printf("VictoriaMetrics container already running at %s", cs.victoriaMetricsIP)
			return cs.victoriaMetricsIP, nil
		}
		// Container exists but not running, start it
		log.Printf("Starting existing VictoriaMetrics container...")
		if err := cs.incusClient.StartContainer(CoreVictoriaMetricsContainer); err != nil {
			return "", fmt.Errorf("failed to start victoriametrics container: %w", err)
		}
		ip, err := cs.incusClient.WaitForNetwork(CoreVictoriaMetricsContainer, 60*time.Second)
		if err != nil {
			return "", fmt.Errorf("failed to get victoriametrics IP: %w", err)
		}
		cs.victoriaMetricsIP = ip
		// Wait for services
		if err := cs.waitForVictoriaMetrics(ctx); err != nil {
			return "", err
		}
		return cs.victoriaMetricsIP, nil
	}

	// Container doesn't exist, create it
	log.Printf("Creating VictoriaMetrics + Grafana container...")

	config := incus.ContainerConfig{
		Name:      CoreVictoriaMetricsContainer,
		Image:     "images:ubuntu/24.04",
		CPU:       "1",
		Memory:    "1GB",
		AutoStart: true,
		Disk: &incus.DiskDevice{
			Path: "/",
			Pool: "default",
			Size: "10GB",
		},
	}

	if err := cs.incusClient.CreateContainer(config); err != nil {
		return "", fmt.Errorf("failed to create victoriametrics container: %w", err)
	}

	// Set role label and boot priority
	cs.incusClient.UpdateContainerConfig(CoreVictoriaMetricsContainer, incus.RoleKey, string(incus.RoleVictoriaMetrics))
	cs.incusClient.UpdateContainerConfig(CoreVictoriaMetricsContainer, "boot.autostart", "true")
	cs.incusClient.UpdateContainerConfig(CoreVictoriaMetricsContainer, "boot.autostart.priority", "80")

	// Start container
	if err := cs.incusClient.StartContainer(CoreVictoriaMetricsContainer); err != nil {
		return "", fmt.Errorf("failed to start victoriametrics container: %w", err)
	}

	// Wait for network
	ip, err := cs.incusClient.WaitForNetwork(CoreVictoriaMetricsContainer, 60*time.Second)
	if err != nil {
		return "", fmt.Errorf("failed to get victoriametrics IP: %w", err)
	}
	cs.victoriaMetricsIP = ip
	log.Printf("VictoriaMetrics container IP: %s", cs.victoriaMetricsIP)

	// Install and configure Victoria Metrics + Grafana
	if err := cs.setupVictoriaMetrics(ctx, postgresIP); err != nil {
		return "", fmt.Errorf("failed to setup victoriametrics: %w", err)
	}

	// Apply base scripts (timezone, clamav) — best-effort
	cs.applyBaseScripts(CoreVictoriaMetricsContainer, "ubuntu")

	return cs.victoriaMetricsIP, nil
}

// setupVictoriaMetrics installs Victoria Metrics and Grafana in the container
func (cs *CoreServices) setupVictoriaMetrics(ctx context.Context, postgresIP string) error {
	log.Printf("Installing Victoria Metrics + Grafana...")

	// Wait for apt to be available
	time.Sleep(5 * time.Second)

	// Install prerequisites
	commands := [][]string{
		{"apt-get", "update"},
		{"apt-get", "install", "-y", "curl", "wget", "apt-transport-https", "software-properties-common", "gnupg"},
	}

	for _, cmd := range commands {
		if err := cs.incusClient.Exec(CoreVictoriaMetricsContainer, cmd); err != nil {
			return fmt.Errorf("failed to run %v: %w", cmd, err)
		}
	}

	// Install Victoria Metrics single-node binary
	vmCommands := [][]string{
		{"bash", "-c", "wget -qO /tmp/victoria-metrics.tar.gz https://github.com/VictoriaMetrics/VictoriaMetrics/releases/download/v1.108.1/victoria-metrics-linux-amd64-v1.108.1.tar.gz"},
		{"bash", "-c", "tar -xzf /tmp/victoria-metrics.tar.gz -C /usr/local/bin/ victoria-metrics-prod"},
		{"bash", "-c", "chmod +x /usr/local/bin/victoria-metrics-prod"},
		{"mkdir", "-p", "/var/lib/victoria-metrics"},
	}

	for _, cmd := range vmCommands {
		if err := cs.incusClient.Exec(CoreVictoriaMetricsContainer, cmd); err != nil {
			return fmt.Errorf("failed to install victoria-metrics: %w", err)
		}
	}

	// Create Victoria Metrics systemd service
	vmService := `[Unit]
Description=Victoria Metrics
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/victoria-metrics-prod -storageDataPath=/var/lib/victoria-metrics -retentionPeriod=30d -httpListenAddr=:8428 -opentelemetry.usePrometheusNaming
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`
	if err := cs.incusClient.WriteFile(CoreVictoriaMetricsContainer, "/etc/systemd/system/victoria-metrics.service", []byte(vmService), "0644"); err != nil {
		return fmt.Errorf("failed to write victoria-metrics service: %w", err)
	}

	// Start Victoria Metrics
	vmStartCommands := [][]string{
		{"systemctl", "daemon-reload"},
		{"systemctl", "enable", "victoria-metrics"},
		{"systemctl", "start", "victoria-metrics"},
	}

	for _, cmd := range vmStartCommands {
		if err := cs.incusClient.Exec(CoreVictoriaMetricsContainer, cmd); err != nil {
			return fmt.Errorf("failed to start victoria-metrics: %w", err)
		}
	}

	// Wait for Victoria Metrics
	if err := cs.waitForVictoriaMetrics(ctx); err != nil {
		return fmt.Errorf("victoria-metrics not ready: %w", err)
	}

	// Install Grafana OSS
	grafanaCommands := [][]string{
		{"bash", "-c", "wget -q -O /usr/share/keyrings/grafana.key https://apt.grafana.com/gpg.key"},
		{"bash", "-c", "echo 'deb [signed-by=/usr/share/keyrings/grafana.key] https://apt.grafana.com stable main' | tee /etc/apt/sources.list.d/grafana.list"},
		{"apt-get", "update"},
		{"apt-get", "install", "-y", "grafana"},
	}

	for _, cmd := range grafanaCommands {
		if err := cs.incusClient.Exec(CoreVictoriaMetricsContainer, cmd); err != nil {
			return fmt.Errorf("failed to install grafana: %w", err)
		}
	}

	// Create grafana database in PostgreSQL container
	createGrafanaDBCmd := "CREATE DATABASE grafana OWNER containarium;"
	if err := cs.incusClient.Exec(CorePostgresContainer, []string{
		"su", "-", "postgres", "-c", fmt.Sprintf("psql -c \"%s\"", createGrafanaDBCmd),
	}); err != nil {
		log.Printf("Note: Grafana database might already exist")
	}

	// Configure Grafana
	grafanaIni := fmt.Sprintf(`[database]
type = postgres
host = %s:5432
name = grafana
user = %s
password = %s
ssl_mode = disable

[security]
allow_embedding = true
admin_user = admin
admin_password = containarium

[auth.anonymous]
enabled = true
org_role = Viewer

[users]
default_theme = light

[server]
http_port = 3000
root_url = %%(protocol)s://%%(domain)s/grafana/
serve_from_sub_path = true
`, postgresIP, DefaultPostgresUser, DefaultPostgresPassword)

	if err := cs.incusClient.WriteFile(CoreVictoriaMetricsContainer, "/etc/grafana/grafana.ini", []byte(grafanaIni), "0644"); err != nil {
		return fmt.Errorf("failed to write grafana.ini: %w", err)
	}

	// Provision Victoria Metrics datasource
	if err := cs.incusClient.Exec(CoreVictoriaMetricsContainer, []string{"mkdir", "-p", "/etc/grafana/provisioning/datasources"}); err != nil {
		return fmt.Errorf("failed to create datasource dir: %w", err)
	}

	datasourceYaml := `apiVersion: 1
deleteDatasources:
  - name: VictoriaMetrics
    orgId: 1
datasources:
  - name: VictoriaMetrics
    uid: victoriametrics
    type: prometheus
    access: proxy
    url: http://localhost:8428
    isDefault: true
    editable: false
`
	if err := cs.incusClient.WriteFile(CoreVictoriaMetricsContainer, "/etc/grafana/provisioning/datasources/vm.yaml", []byte(datasourceYaml), "0644"); err != nil {
		return fmt.Errorf("failed to write datasource config: %w", err)
	}

	// Provision dashboards
	if err := cs.incusClient.Exec(CoreVictoriaMetricsContainer, []string{"mkdir", "-p", "/etc/grafana/provisioning/dashboards"}); err != nil {
		return fmt.Errorf("failed to create dashboard provisioning dir: %w", err)
	}

	dashboardProvisionYaml := `apiVersion: 1
providers:
  - name: 'default'
    orgId: 1
    folder: 'Containarium'
    type: file
    disableDeletion: false
    updateIntervalSeconds: 30
    options:
      path: /var/lib/grafana/dashboards
      foldersFromFilesStructure: false
`
	if err := cs.incusClient.WriteFile(CoreVictoriaMetricsContainer, "/etc/grafana/provisioning/dashboards/default.yaml", []byte(dashboardProvisionYaml), "0644"); err != nil {
		return fmt.Errorf("failed to write dashboard provisioning config: %w", err)
	}

	// Create dashboards directory and write the single consolidated dashboard
	if err := cs.incusClient.Exec(CoreVictoriaMetricsContainer, []string{"mkdir", "-p", "/var/lib/grafana/dashboards"}); err != nil {
		return fmt.Errorf("failed to create dashboards dir: %w", err)
	}

	if err := cs.incusClient.WriteFile(CoreVictoriaMetricsContainer, "/var/lib/grafana/dashboards/overview.json", []byte(OverviewDashboard), "0644"); err != nil {
		return fmt.Errorf("failed to write overview dashboard: %w", err)
	}

	// Start Grafana
	grafanaStartCommands := [][]string{
		{"systemctl", "daemon-reload"},
		{"systemctl", "enable", "grafana-server"},
		{"systemctl", "start", "grafana-server"},
	}

	for _, cmd := range grafanaStartCommands {
		if err := cs.incusClient.Exec(CoreVictoriaMetricsContainer, cmd); err != nil {
			return fmt.Errorf("failed to start grafana: %w", err)
		}
	}

	// Wait for Grafana
	if err := cs.waitForGrafana(ctx); err != nil {
		return fmt.Errorf("grafana not ready: %w", err)
	}

	log.Printf("VictoriaMetrics + Grafana setup complete")
	return nil
}

// waitForVictoriaMetrics waits for Victoria Metrics to be ready
func (cs *CoreServices) waitForVictoriaMetrics(ctx context.Context) error {
	log.Printf("Waiting for Victoria Metrics to be ready...")

	for i := 0; i < 30; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err := cs.incusClient.Exec(CoreVictoriaMetricsContainer, []string{
			"curl", "-sf", "http://localhost:8428/health",
		}); err == nil {
			log.Printf("Victoria Metrics is ready")
			return nil
		}

		time.Sleep(2 * time.Second)
	}

	return fmt.Errorf("timeout waiting for Victoria Metrics to be ready")
}

// waitForGrafana waits for Grafana to be ready
func (cs *CoreServices) waitForGrafana(ctx context.Context) error {
	log.Printf("Waiting for Grafana to be ready...")

	for i := 0; i < 30; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err := cs.incusClient.Exec(CoreVictoriaMetricsContainer, []string{
			"curl", "-sf", "http://localhost:3000/api/health",
		}); err == nil {
			log.Printf("Grafana is ready")
			return nil
		}

		time.Sleep(2 * time.Second)
	}

	return fmt.Errorf("timeout waiting for Grafana to be ready")
}

// GetVictoriaMetricsIP returns the Victoria Metrics container IP
func (cs *CoreServices) GetVictoriaMetricsIP() string {
	return cs.victoriaMetricsIP
}

// GetVictoriaMetricsURL returns the Victoria Metrics HTTP API URL
func (cs *CoreServices) GetVictoriaMetricsURL() string {
	return fmt.Sprintf("http://%s:%d", cs.victoriaMetricsIP, DefaultVMPort)
}

// applyBaseScripts runs all base scripts on a container using the given username.
// Errors are logged but not fatal — base scripts are best-effort on core containers.
func (cs *CoreServices) applyBaseScripts(containerName, username string) {
	stackMgr := stacks.GetDefault()
	baseScripts := stackMgr.GetAllBaseScripts()
	if len(baseScripts) == 0 {
		return
	}

	log.Printf("Applying base scripts to %s (user=%s)...", containerName, username)

	// Collect all packages
	var allPkgs []string
	for _, bs := range baseScripts {
		// Pre-install
		for _, cmd := range bs.PreInstall {
			cmd = strings.ReplaceAll(cmd, "{{USERNAME}}", username)
			_ = cs.incusClient.Exec(containerName, []string{"bash", "-c", cmd})
		}
		allPkgs = append(allPkgs, bs.Packages...)
	}

	// Install packages in one shot
	if len(allPkgs) > 0 {
		_ = cs.incusClient.Exec(containerName, []string{"apt-get", "update"})
		installCmd := append([]string{"apt-get", "install", "-y"}, allPkgs...)
		_ = cs.incusClient.Exec(containerName, installCmd)
	}

	// Post-install
	for _, bs := range baseScripts {
		for _, cmd := range bs.PostInstall {
			cmd = strings.ReplaceAll(cmd, "{{USERNAME}}", username)
			_ = cs.incusClient.Exec(containerName, []string{"bash", "-c", cmd})
		}
	}

	log.Printf("Base scripts applied to %s", containerName)
}

// GetGrafanaURL returns the Grafana URL
func (cs *CoreServices) GetGrafanaURL() string {
	return fmt.Sprintf("http://%s:%d", cs.victoriaMetricsIP, DefaultGrafanaPort)
}

// EnsureSecurity ensures the ClamAV security container is running
func (cs *CoreServices) EnsureSecurity(ctx context.Context) error {
	// Check if container already exists
	info, err := cs.incusClient.GetContainer(CoreSecurityContainer)
	if err == nil {
		cs.backfillConfig(CoreSecurityContainer, incus.RoleSecurity, "70")

		if info.State == "Running" {
			log.Printf("Security container already running at %s", info.IPAddress)
			return nil
		}
		log.Printf("Starting existing Security container...")
		if err := cs.incusClient.StartContainer(CoreSecurityContainer); err != nil {
			return fmt.Errorf("failed to start security container: %w", err)
		}
		if _, err := cs.incusClient.WaitForNetwork(CoreSecurityContainer, 60*time.Second); err != nil {
			return fmt.Errorf("failed to get security container IP: %w", err)
		}
		return nil
	}

	// Container doesn't exist, create it
	log.Printf("Creating ClamAV security container...")

	config := incus.ContainerConfig{
		Name:      CoreSecurityContainer,
		Image:     "images:ubuntu/24.04",
		CPU:       "1",
		Memory:    "1GB",
		AutoStart: true,
		Disk: &incus.DiskDevice{
			Path: "/",
			Pool: "default",
			Size: "5GB",
		},
	}

	if err := cs.incusClient.CreateContainer(config); err != nil {
		return fmt.Errorf("failed to create security container: %w", err)
	}

	cs.incusClient.UpdateContainerConfig(CoreSecurityContainer, incus.RoleKey, string(incus.RoleSecurity))
	cs.incusClient.UpdateContainerConfig(CoreSecurityContainer, "boot.autostart", "true")
	cs.incusClient.UpdateContainerConfig(CoreSecurityContainer, "boot.autostart.priority", "70")

	if err := cs.incusClient.StartContainer(CoreSecurityContainer); err != nil {
		return fmt.Errorf("failed to start security container: %w", err)
	}

	if _, err := cs.incusClient.WaitForNetwork(CoreSecurityContainer, 60*time.Second); err != nil {
		return fmt.Errorf("failed to get security container IP: %w", err)
	}

	if err := cs.setupSecurity(ctx); err != nil {
		return fmt.Errorf("failed to setup security: %w", err)
	}

	// Apply base scripts (timezone) — best-effort
	cs.applyBaseScripts(CoreSecurityContainer, "ubuntu")

	return nil
}

// setupSecurity installs ClamAV in the security container
func (cs *CoreServices) setupSecurity(ctx context.Context) error {
	log.Printf("Installing ClamAV...")

	time.Sleep(5 * time.Second)

	commands := [][]string{
		{"apt-get", "update"},
		{"apt-get", "install", "-y", "clamav", "clamav-daemon", "clamav-freshclam"},
	}

	for _, cmd := range commands {
		if err := cs.incusClient.Exec(CoreSecurityContainer, cmd); err != nil {
			return fmt.Errorf("failed to run %v: %w", cmd, err)
		}
	}

	// Enable and start freshclam (virus database updater)
	startCmds := [][]string{
		{"systemctl", "enable", "clamav-freshclam"},
		{"systemctl", "start", "clamav-freshclam"},
	}
	for _, cmd := range startCmds {
		if err := cs.incusClient.Exec(CoreSecurityContainer, cmd); err != nil {
			return fmt.Errorf("failed to run %v: %w", cmd, err)
		}
	}

	log.Printf("ClamAV security container setup complete")
	return nil
}

// backfillConfig ensures role label and boot priority are set on an existing
// container. This handles upgrades from older versions that lack these keys.
func (cs *CoreServices) backfillConfig(containerName string, role incus.Role, priority string) {
	cfg, _, err := cs.incusClient.GetRawInstance(containerName)
	if err != nil {
		return
	}
	if cfg[incus.RoleKey] == "" {
		if err := cs.incusClient.UpdateContainerConfig(containerName, incus.RoleKey, string(role)); err != nil {
			log.Printf("Warning: failed to backfill role on %s: %v", containerName, err)
		} else {
			log.Printf("Backfilled role=%s on %s", role, containerName)
		}
	}
	if cfg["boot.autostart.priority"] == "" {
		if err := cs.incusClient.UpdateContainerConfig(containerName, "boot.autostart.priority", priority); err != nil {
			log.Printf("Warning: failed to backfill boot priority on %s: %v", containerName, err)
		}
	}
	if cfg["boot.autostart"] == "" {
		cs.incusClient.UpdateContainerConfig(containerName, "boot.autostart", "true")
	}
}
