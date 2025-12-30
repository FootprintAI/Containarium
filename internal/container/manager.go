package container

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/incus"
)

// Manager handles container lifecycle operations
type Manager struct {
	incus *incus.Client
}

// CreateOptions holds options for creating a container
type CreateOptions struct {
	Username     string
	Image        string
	CPU          string
	Memory       string
	Disk         string
	SSHKeys      []string
	EnableDocker bool
	AutoStart    bool
	Verbose      bool
}

// New creates a new container manager
func New() (*Manager, error) {
	client, err := incus.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create Incus client: %w", err)
	}

	return &Manager{incus: client}, nil
}

// Create creates a new container with full setup
func (m *Manager) Create(opts CreateOptions) (*incus.ContainerInfo, error) {
	containerName := opts.Username + "-container"

	if opts.Verbose {
		fmt.Printf("Creating container: %s\n", containerName)
	}

	// Step 1: Create container
	if opts.Verbose {
		fmt.Println("  [1/6] Creating container...")
	}

	config := incus.ContainerConfig{
		Name:          containerName,
		Image:         opts.Image,
		CPU:           opts.CPU,
		Memory:        opts.Memory,
		Disk:          opts.Disk,
		EnableNesting: opts.EnableDocker,
		AutoStart:     opts.AutoStart,
	}

	if err := m.incus.CreateContainer(config); err != nil {
		return nil, fmt.Errorf("failed to create container: %w", err)
	}

	// Step 2: Start container
	if opts.Verbose {
		fmt.Println("  [2/6] Starting container...")
	}

	if err := m.incus.StartContainer(containerName); err != nil {
		// Clean up on failure
		_ = m.incus.DeleteContainer(containerName)
		return nil, fmt.Errorf("failed to start container: %w", err)
	}

	// Step 3: Create jump server account (proxy-only, no shell access)
	if opts.Verbose {
		fmt.Println("  [3/7] Creating jump server account (proxy-only)...")
	}

	if len(opts.SSHKeys) > 0 {
		// Use the first SSH key for the jump server account
		if err := CreateJumpServerAccount(opts.Username, opts.SSHKeys[0], opts.Verbose); err != nil {
			_ = m.cleanup(containerName)
			return nil, fmt.Errorf("failed to create jump server account: %w", err)
		}
	} else {
		if opts.Verbose {
			fmt.Println("       Warning: No SSH keys provided, skipping jump server account creation")
		}
	}

	// Step 4: Wait for network
	if opts.Verbose {
		fmt.Println("  [4/7] Waiting for network...")
	}

	ipAddr, err := m.incus.WaitForNetwork(containerName, 30*time.Second)
	if err != nil {
		_ = m.cleanup(containerName)
		return nil, fmt.Errorf("failed to get container IP: %w", err)
	}

	if opts.Verbose {
		fmt.Printf("  Container IP: %s\n", ipAddr)
	}

	// Step 5: Install packages
	if opts.Verbose {
		fmt.Println("  [5/7] Installing Docker, SSH, and tools...")
	}

	if err := m.installPackages(containerName, opts.EnableDocker); err != nil {
		_ = m.cleanup(containerName)
		return nil, fmt.Errorf("failed to install packages: %w", err)
	}

	// Step 6: Create user
	if opts.Verbose {
		fmt.Printf("  [6/7] Creating user: %s...\n", opts.Username)
	}

	if err := m.createUser(containerName, opts.Username); err != nil {
		_ = m.cleanup(containerName)
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Step 7: Add SSH keys (including jump server's key for ProxyJump support)
	allKeys := make([]string, 0, len(opts.SSHKeys)+1)

	// Add jump server's SSH key automatically for ProxyJump support
	jumpServerKey, err := getJumpServerSSHKey()
	if err == nil && jumpServerKey != "" {
		allKeys = append(allKeys, jumpServerKey)
		if opts.Verbose {
			fmt.Println("  [7/7] Adding SSH keys (including jump server key for ProxyJump)...")
		}
	} else {
		if opts.Verbose {
			fmt.Println("  [7/7] Adding SSH keys...")
		}
	}

	// Add user-provided keys
	allKeys = append(allKeys, opts.SSHKeys...)

	if len(allKeys) > 0 {
		if opts.Verbose {
			fmt.Printf("       Adding %d SSH key(s)...\n", len(allKeys))
		}

		if err := m.addSSHKeys(containerName, opts.Username, allKeys); err != nil {
			_ = m.cleanup(containerName)
			return nil, fmt.Errorf("failed to add SSH keys: %w", err)
		}
	} else {
		if opts.Verbose {
			fmt.Println("       No SSH keys to add, skipping...")
		}
	}

	// Get container info
	info, err := m.incus.GetContainer(containerName)
	if err != nil {
		return nil, fmt.Errorf("failed to get container info: %w", err)
	}

	return info, nil
}

// installPackages installs required packages in the container
func (m *Manager) installPackages(containerName string, enableDocker bool) error {
	// Wait a bit for cloud-init to finish (if present)
	time.Sleep(5 * time.Second)

	// Update package lists
	if err := m.incus.Exec(containerName, []string{"apt-get", "update"}); err != nil {
		return fmt.Errorf("apt-get update failed: %w", err)
	}

	// Build package list
	packages := []string{
		"openssh-server",
		"sudo",
		"curl",
		"git",
		"vim",
		"htop",
		"net-tools",
		"iputils-ping",
	}

	if enableDocker {
		packages = append(packages, "docker.io", "docker-compose")
	}

	// Install packages
	installCmd := append([]string{"apt-get", "install", "-y"}, packages...)
	if err := m.incus.Exec(containerName, installCmd); err != nil {
		return fmt.Errorf("apt-get install failed: %w", err)
	}

	// Enable services
	if enableDocker {
		if err := m.incus.Exec(containerName, []string{"systemctl", "enable", "docker"}); err != nil {
			return fmt.Errorf("failed to enable docker: %w", err)
		}
		if err := m.incus.Exec(containerName, []string{"systemctl", "start", "docker"}); err != nil {
			return fmt.Errorf("failed to start docker: %w", err)
		}
	}

	if err := m.incus.Exec(containerName, []string{"systemctl", "enable", "ssh"}); err != nil {
		return fmt.Errorf("failed to enable ssh: %w", err)
	}
	if err := m.incus.Exec(containerName, []string{"systemctl", "start", "ssh"}); err != nil {
		return fmt.Errorf("failed to start ssh: %w", err)
	}

	return nil
}

// createUser creates a user in the container with sudo access
func (m *Manager) createUser(containerName, username string) error {
	// Create user
	if err := m.incus.Exec(containerName, []string{
		"adduser",
		"--disabled-password",
		"--gecos", "",
		username,
	}); err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	// Add to sudo group
	if err := m.incus.Exec(containerName, []string{"usermod", "-aG", "sudo", username}); err != nil {
		return fmt.Errorf("failed to add user to sudo: %w", err)
	}

	// Add to docker group (if docker is installed)
	_ = m.incus.Exec(containerName, []string{"usermod", "-aG", "docker", username})

	// Allow passwordless sudo
	sudoersLine := fmt.Sprintf("%s ALL=(ALL) NOPASSWD:ALL", username)
	if err := m.incus.Exec(containerName, []string{
		"bash", "-c",
		fmt.Sprintf("echo '%s' > /etc/sudoers.d/%s", sudoersLine, username),
	}); err != nil {
		return fmt.Errorf("failed to configure sudo: %w", err)
	}

	if err := m.incus.Exec(containerName, []string{
		"chmod", "0440", fmt.Sprintf("/etc/sudoers.d/%s", username),
	}); err != nil {
		return fmt.Errorf("failed to set sudoers permissions: %w", err)
	}

	return nil
}

// addSSHKeys adds SSH public keys to a user's authorized_keys
func (m *Manager) addSSHKeys(containerName, username string, sshKeys []string) error {
	sshDir := fmt.Sprintf("/home/%s/.ssh", username)

	// Create .ssh directory
	if err := m.incus.Exec(containerName, []string{"mkdir", "-p", sshDir}); err != nil {
		return fmt.Errorf("failed to create .ssh directory: %w", err)
	}

	// Set permissions on .ssh directory
	if err := m.incus.Exec(containerName, []string{"chmod", "700", sshDir}); err != nil {
		return fmt.Errorf("failed to set .ssh permissions: %w", err)
	}

	// Create authorized_keys file
	authorizedKeysPath := fmt.Sprintf("%s/authorized_keys", sshDir)
	if err := m.incus.Exec(containerName, []string{"touch", authorizedKeysPath}); err != nil {
		return fmt.Errorf("failed to create authorized_keys: %w", err)
	}

	// Add each SSH key
	for _, key := range sshKeys {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}

		cmd := fmt.Sprintf("echo '%s' >> %s", key, authorizedKeysPath)
		if err := m.incus.Exec(containerName, []string{"bash", "-c", cmd}); err != nil {
			return fmt.Errorf("failed to add SSH key: %w", err)
		}
	}

	// Set permissions on authorized_keys
	if err := m.incus.Exec(containerName, []string{"chmod", "600", authorizedKeysPath}); err != nil {
		return fmt.Errorf("failed to set authorized_keys permissions: %w", err)
	}

	// Set ownership
	chownTarget := fmt.Sprintf("%s:%s", username, username)
	if err := m.incus.Exec(containerName, []string{"chown", "-R", chownTarget, sshDir}); err != nil {
		return fmt.Errorf("failed to set .ssh ownership: %w", err)
	}

	return nil
}

// List lists all containers
func (m *Manager) List() ([]incus.ContainerInfo, error) {
	return m.incus.ListContainers()
}

// Get gets information about a specific container
func (m *Manager) Get(username string) (*incus.ContainerInfo, error) {
	containerName := username + "-container"
	return m.incus.GetContainer(containerName)
}

// Delete deletes a container
func (m *Manager) Delete(username string, force bool) error {
	containerName := username + "-container"

	// Get container state
	info, err := m.incus.GetContainer(containerName)
	if err != nil {
		return fmt.Errorf("container not found: %w", err)
	}

	// Stop if running
	if info.State == "Running" {
		if err := m.incus.StopContainer(containerName, force); err != nil {
			return fmt.Errorf("failed to stop container: %w", err)
		}
	}

	// Delete
	if err := m.incus.DeleteContainer(containerName); err != nil {
		return fmt.Errorf("failed to delete container: %w", err)
	}

	return nil
}

// cleanup removes a container (used on creation failure)
func (m *Manager) cleanup(containerName string) error {
	// Try to stop first (ignore errors)
	_ = m.incus.StopContainer(containerName, true)

	// Delete
	return m.incus.DeleteContainer(containerName)
}

// GetServerInfo gets information about the Incus server
func (m *Manager) GetServerInfo() (*incus.ServerInfo, error) {
	server, err := m.incus.GetServerInfo()
	if err != nil {
		return nil, err
	}

	// Convert to our own type for easier use
	info := &incus.ServerInfo{
		Version:    server.Environment.ServerVersion,
		KernelVersion: server.Environment.KernelVersion,
	}

	return info, nil
}

// getJumpServerSSHKey reads the jump server's SSH public key for ProxyJump support
func getJumpServerSSHKey() (string, error) {
	// First, try the systemd-accessible location (set up by startup script)
	systemdKeyPath := "/etc/containarium/jump_server_key.pub"
	if keyBytes, err := os.ReadFile(systemdKeyPath); err == nil {
		key := strings.TrimSpace(string(keyBytes))
		if key != "" {
			return key, nil
		}
	}

	// Fallback: Try common SSH public key locations
	// Note: This won't work if ProtectHome=true in systemd service
	homeDirectories := []string{
		os.Getenv("HOME"),
		"/home/hsinhoyeh", // Common user on GCE
		"/home/ubuntu",    // Common on Ubuntu systems
		"/home/admin",     // Common admin user
		"/root",           // Fallback to root
	}

	keyTypes := []string{"id_ed25519.pub", "id_rsa.pub", "id_ecdsa.pub"}

	for _, homeDir := range homeDirectories {
		if homeDir == "" {
			continue
		}
		for _, keyType := range keyTypes {
			keyPath := homeDir + "/.ssh/" + keyType
			if keyBytes, err := os.ReadFile(keyPath); err == nil {
				key := strings.TrimSpace(string(keyBytes))
				if key != "" {
					return key, nil
				}
			}
		}
	}

	// No SSH key found - this is OK, just means ProxyJump won't work automatically
	return "", nil
}
