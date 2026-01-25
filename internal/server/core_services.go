package server

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/footprintai/containarium/internal/incus"
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

// CoreServices manages the core infrastructure containers (PostgreSQL, Caddy)
type CoreServices struct {
	incusClient *incus.Client
	config      CoreServicesConfig
	postgresIP  string
	caddyIP     string
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

	return cs.getCaddyAdminURL(), nil
}

// setupCaddy installs and configures Caddy in the container
func (cs *CoreServices) setupCaddy(ctx context.Context, baseDomain string) error {
	log.Printf("Installing Caddy...")

	// Wait for apt to be available
	time.Sleep(5 * time.Second)

	// Install Caddy
	commands := [][]string{
		{"apt-get", "update"},
		{"apt-get", "install", "-y", "debian-keyring", "debian-archive-keyring", "apt-transport-https", "curl"},
		{"bash", "-c", "curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg"},
		{"bash", "-c", "curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list"},
		{"apt-get", "update"},
		{"apt-get", "install", "-y", "caddy"},
	}

	for _, cmd := range commands {
		if err := cs.incusClient.Exec(CoreCaddyContainer, cmd); err != nil {
			return fmt.Errorf("failed to run %v: %w", cmd, err)
		}
	}

	// Create Caddyfile with admin API enabled
	caddyfile := fmt.Sprintf(`{
	admin :2019
}

# Default catch-all - will be configured dynamically via admin API
`)

	if err := cs.incusClient.WriteFile(CoreCaddyContainer, "/etc/caddy/Caddyfile", []byte(caddyfile), "0644"); err != nil {
		return fmt.Errorf("failed to write Caddyfile: %w", err)
	}

	// Start Caddy
	if err := cs.incusClient.Exec(CoreCaddyContainer, []string{"systemctl", "restart", "caddy"}); err != nil {
		return fmt.Errorf("failed to restart caddy: %w", err)
	}

	if err := cs.incusClient.Exec(CoreCaddyContainer, []string{"systemctl", "enable", "caddy"}); err != nil {
		return fmt.Errorf("failed to enable caddy: %w", err)
	}

	// Wait for Caddy to be ready
	time.Sleep(3 * time.Second)

	log.Printf("Caddy setup complete")
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
