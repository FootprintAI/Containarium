package core

import (
	"context"
	"fmt"
	"time"

	"github.com/footprintai/containarium/internal/container"
	"github.com/footprintai/containarium/internal/incus"
)

// IncusClient is an interface for the incus client to enable testing
type IncusClient interface {
	CreateContainer(config incus.ContainerConfig) error
	StartContainer(name string) error
	StopContainer(name string, force bool) error
	DeleteContainer(name string) error
	GetContainer(name string) (*incus.ContainerInfo, error)
	WaitForNetwork(name string, timeout time.Duration) (string, error)
	Exec(containerName string, command []string) error
}

const (
	// CoreContainerName is the name of the internal system container
	CoreContainerName = "_containarium-core"

	// CoreContainerImage is the default image for the core container
	CoreContainerImage = "images:ubuntu/24.04"

	// Default resource limits for core container
	DefaultCoreCPU    = "2"
	DefaultCoreMemory = "4GB"
	DefaultCoreDisk   = "50GB"
)

// dockerComposeTemplate is the docker-compose configuration for core services
const dockerComposeTemplate = `version: '3.8'

services:
  postgres:
    image: postgres:16-alpine
    container_name: _containarium-postgres
    restart: unless-stopped
    ports:
      - "5432:5432"
    environment:
      POSTGRES_DB: containarium
      POSTGRES_USER: containarium
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-changeme}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U containarium"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    container_name: _containarium-redis
    restart: unless-stopped
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    command: redis-server --appendonly yes
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 3s
      retries: 5

  caddy:
    image: caddy:2-alpine
    container_name: _containarium-caddy
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
      - "2019:2019"
    volumes:
      - caddy_data:/data
      - caddy_config:/config
    environment:
      - CADDY_ADMIN=0.0.0.0:2019

volumes:
  postgres_data:
  redis_data:
  caddy_data:
  caddy_config:
`

// Manager manages the _containarium-core internal system container
type Manager struct {
	incusClient IncusClient
	coreIP      string
	password    string
}

// Config holds configuration for the core manager
type Config struct {
	// PostgreSQL password (defaults to "changeme" if not set)
	PostgresPassword string

	// Auto-create core container if it doesn't exist
	AutoCreate bool

	// Custom resource limits (optional)
	CPU    string
	Memory string
	Disk   string
}

// New creates a new core manager
func New(incusClient IncusClient, password string) *Manager {
	if password == "" {
		password = "changeme"
	}
	return &Manager{
		incusClient: incusClient,
		password:    password,
	}
}

// EnsureCoreContainer ensures the _containarium-core container exists and is healthy
func (m *Manager) EnsureCoreContainer(ctx context.Context, config Config) error {
	// Validate the core container name (should pass for system containers)
	if err := container.ValidateSystemContainerName(CoreContainerName); err != nil {
		return fmt.Errorf("invalid core container name: %w", err)
	}

	// Check if container already exists
	containerInfo, err := m.incusClient.GetContainer(CoreContainerName)
	if err == nil && containerInfo != nil {
		// Container exists, check if it's running
		m.coreIP = containerInfo.IPAddress
		return m.healthCheck(ctx)
	}

	// Container doesn't exist
	if !config.AutoCreate {
		return fmt.Errorf("core container %s does not exist and auto-create is disabled", CoreContainerName)
	}

	// Create the core container
	return m.createCoreContainer(ctx, config)
}

// createCoreContainer creates and initializes the core container
func (m *Manager) createCoreContainer(ctx context.Context, config Config) error {
	// Set default resources if not provided
	cpu := config.CPU
	if cpu == "" {
		cpu = DefaultCoreCPU
	}
	memory := config.Memory
	if memory == "" {
		memory = DefaultCoreMemory
	}
	disk := config.Disk
	if disk == "" {
		disk = DefaultCoreDisk
	}

	// Create container
	containerConfig := incus.ContainerConfig{
		Name:          CoreContainerName,
		Image:         CoreContainerImage,
		CPU:           cpu,
		Memory:        memory,
		EnableNesting: true, // Required for Docker
		AutoStart:     true,
	}

	// Configure root disk device
	if disk != "" {
		containerConfig.Disk = &incus.DiskDevice{
			Path: "/",
			Pool: "default",
			Size: disk,
		}
	}

	if err := m.incusClient.CreateContainer(containerConfig); err != nil {
		return fmt.Errorf("failed to create core container: %w", err)
	}

	// Start the container
	if err := m.incusClient.StartContainer(CoreContainerName); err != nil {
		return fmt.Errorf("failed to start core container: %w", err)
	}

	// Wait for network
	ip, err := m.incusClient.WaitForNetwork(CoreContainerName, 60*time.Second)
	if err != nil {
		return fmt.Errorf("failed to get core container IP: %w", err)
	}
	m.coreIP = ip

	// Setup core services
	if err := m.setupCoreServices(ctx, config.PostgresPassword); err != nil {
		return fmt.Errorf("failed to setup core services: %w", err)
	}

	return nil
}

// setupCoreServices installs and configures Docker and core services
func (m *Manager) setupCoreServices(ctx context.Context, postgresPassword string) error {
	// Install Docker and docker-compose
	// Note: This is a simplified version. In production, we'd need more error handling
	installCmd := []string{
		"/bin/bash", "-c",
		"apt-get update && apt-get install -y docker.io docker-compose && systemctl enable docker && systemctl start docker",
	}

	if err := m.incusClient.Exec(CoreContainerName, installCmd); err != nil {
		return fmt.Errorf("failed to install Docker: %w", err)
	}

	// TODO: Write docker-compose.yml to container
	// For now, we'll assume it's written manually or via another method
	// This would require implementing a WriteFile method in the incus client

	// Start core services with docker-compose
	// TODO: Implement this once we have file writing capability
	// startCmd := []string{"/bin/bash", "-c", "cd /root && docker-compose up -d"}
	// if err := m.incusClient.Exec(CoreContainerName, startCmd); err != nil {
	// 	return fmt.Errorf("failed to start core services: %w", err)
	// }

	return nil
}

// healthCheck verifies that all core services are healthy
func (m *Manager) healthCheck(ctx context.Context) error {
	// Check if container is running
	containerInfo, err := m.incusClient.GetContainer(CoreContainerName)
	if err != nil {
		return fmt.Errorf("failed to get core container: %w", err)
	}

	if containerInfo == nil {
		return fmt.Errorf("core container %s does not exist", CoreContainerName)
	}

	if containerInfo.State != "Running" {
		return fmt.Errorf("core container is not running (state: %s)", containerInfo.State)
	}

	// Update IP if we don't have it
	if m.coreIP == "" {
		m.coreIP = containerInfo.IPAddress
	}

	// TODO: Add health checks for PostgreSQL, Redis, and Caddy
	// This would involve executing health check commands in the container

	return nil
}

// GetCoreIP returns the IP address of the core container
func (m *Manager) GetCoreIP() string {
	return m.coreIP
}

// GetPostgresConnectionString returns the PostgreSQL connection string
func (m *Manager) GetPostgresConnectionString() string {
	return fmt.Sprintf(
		"postgres://containarium:%s@%s:5432/containarium?sslmode=disable",
		m.password,
		m.coreIP,
	)
}

// GetRedisAddress returns the Redis address
func (m *Manager) GetRedisAddress() string {
	return fmt.Sprintf("%s:6379", m.coreIP)
}

// GetCaddyAdminURL returns the Caddy admin API URL
func (m *Manager) GetCaddyAdminURL() string {
	return fmt.Sprintf("http://%s:2019", m.coreIP)
}

// Destroy removes the core container and all its data
// WARNING: This will delete all application data!
func (m *Manager) Destroy(ctx context.Context) error {
	// Stop the container first
	if err := m.incusClient.StopContainer(CoreContainerName, false); err != nil {
		// Ignore error if container is already stopped
	}

	// Delete the container
	if err := m.incusClient.DeleteContainer(CoreContainerName); err != nil {
		return fmt.Errorf("failed to delete core container: %w", err)
	}

	m.coreIP = ""
	return nil
}

// IsHealthy checks if the core container and its services are healthy
func (m *Manager) IsHealthy(ctx context.Context) bool {
	return m.healthCheck(ctx) == nil
}
