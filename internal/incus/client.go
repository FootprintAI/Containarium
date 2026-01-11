package incus

import (
	"fmt"
	"strings"
	"time"

	incus "github.com/lxc/incus/client"
	"github.com/lxc/incus/shared/api"
)

// Client wraps the Incus API client
type Client struct {
	server incus.InstanceServer
}

// ContainerConfig holds configuration for creating a container
type ContainerConfig struct {
	Name         string
	Image        string
	CPU          string
	Memory       string
	Disk         string
	EnableNesting bool
	AutoStart    bool
}

// ContainerInfo holds information about a container
type ContainerInfo struct {
	Name      string
	State     string
	IPAddress string
	CPU       string
	Memory    string
	CreatedAt time.Time
}

// ServerInfo holds information about the Incus server
type ServerInfo struct {
	Version       string
	KernelVersion string
}

// New creates a new Incus client
// Connects to the local Incus daemon via Unix socket
func New() (*Client, error) {
	return NewWithSocket("/var/lib/incus/unix.socket")
}

// NewWithSocket creates a new Incus client with a specific socket path
func NewWithSocket(socketPath string) (*Client, error) {
	server, err := incus.ConnectIncusUnix(socketPath, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Incus: %w", err)
	}

	return &Client{server: server}, nil
}

// parseImageSource parses an image string and returns the appropriate InstanceSource
// Handles formats like:
//   - "ubuntu:24.04" or "ubuntu/24.04" -> local alias
//   - "images:ubuntu/24.04" -> remote from images.linuxcontainers.org
//   - "ubuntu" -> local alias
func parseImageSource(image string) api.InstanceSource {
	source := api.InstanceSource{
		Type: "image",
	}

	// Check if it's a remote image (contains ":")
	if strings.Contains(image, ":") {
		parts := strings.SplitN(image, ":", 2)
		remote := parts[0]
		alias := parts[1]

		// Map common remote names to their URLs
		switch remote {
		case "images":
			source.Server = "https://images.linuxcontainers.org"
			source.Protocol = "simplestreams"
			source.Alias = alias
		case "ubuntu":
			source.Server = "https://cloud-images.ubuntu.com/releases"
			source.Protocol = "simplestreams"
			source.Alias = alias
		case "ubuntu-daily":
			source.Server = "https://cloud-images.ubuntu.com/daily"
			source.Protocol = "simplestreams"
			source.Alias = alias
		default:
			// Unknown remote, try as local alias
			source.Alias = image
		}
	} else {
		// Local image alias
		source.Alias = image
	}

	return source
}

// CreateContainer creates a new container with the specified configuration
func (c *Client) CreateContainer(config ContainerConfig) error {
	// Prepare container creation request
	req := api.InstancesPost{
		Name: config.Name,
		Type: api.InstanceTypeContainer,
	}

	// Parse image source - handle remote images like "images:ubuntu/24.04"
	req.Source = parseImageSource(config.Image)

	// Set container configuration
	req.Config = make(map[string]string)

	// Resource limits
	if config.CPU != "" {
		req.Config["limits.cpu"] = config.CPU
	}
	if config.Memory != "" {
		req.Config["limits.memory"] = config.Memory
	}

	// Docker support (nesting)
	if config.EnableNesting {
		req.Config["security.nesting"] = "true"
		req.Config["security.syscalls.intercept.mknod"] = "true"
		req.Config["security.syscalls.intercept.setxattr"] = "true"
	}

	// Auto-start on boot
	if config.AutoStart {
		req.Config["boot.autostart"] = "true"
	}

	// Disk size (via device config)
	if config.Disk != "" {
		req.Devices = map[string]map[string]string{
			"root": {
				"type": "disk",
				"path": "/",
				"pool": "default",
				"size": config.Disk,
			},
		}
	}

	// Create the container
	op, err := c.server.CreateInstance(req)
	if err != nil {
		return fmt.Errorf("failed to create container: %w", err)
	}

	// Wait for operation to complete
	if err := op.Wait(); err != nil {
		return fmt.Errorf("failed to create container (operation failed): %w", err)
	}

	return nil
}

// StartContainer starts a container
func (c *Client) StartContainer(name string) error {
	reqState := api.InstanceStatePut{
		Action:  "start",
		Timeout: 30,
	}

	op, err := c.server.UpdateInstanceState(name, reqState, "")
	if err != nil {
		return fmt.Errorf("failed to start container: %w", err)
	}

	if err := op.Wait(); err != nil {
		return fmt.Errorf("failed to start container (operation failed): %w", err)
	}

	return nil
}

// StopContainer stops a container
func (c *Client) StopContainer(name string, force bool) error {
	action := "stop"
	if force {
		action = "stop --force"
	}

	reqState := api.InstanceStatePut{
		Action:  action,
		Timeout: 30,
	}

	op, err := c.server.UpdateInstanceState(name, reqState, "")
	if err != nil {
		return fmt.Errorf("failed to stop container: %w", err)
	}

	if err := op.Wait(); err != nil {
		return fmt.Errorf("failed to stop container (operation failed): %w", err)
	}

	return nil
}

// DeleteContainer deletes a container
func (c *Client) DeleteContainer(name string) error {
	op, err := c.server.DeleteInstance(name)
	if err != nil {
		return fmt.Errorf("failed to delete container: %w", err)
	}

	if err := op.Wait(); err != nil {
		return fmt.Errorf("failed to delete container (operation failed): %w", err)
	}

	return nil
}

// ListContainers lists all containers
func (c *Client) ListContainers() ([]ContainerInfo, error) {
	instances, err := c.server.GetInstances(api.InstanceTypeContainer)
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	var containers []ContainerInfo
	for _, inst := range instances {
		info := ContainerInfo{
			Name:      inst.Name,
			State:     inst.Status,
			CreatedAt: inst.CreatedAt,
		}

		// Get CPU and memory limits from config
		if cpu, ok := inst.Config["limits.cpu"]; ok {
			info.CPU = cpu
		}
		if mem, ok := inst.Config["limits.memory"]; ok {
			info.Memory = mem
		}

		// Get IP address - need to get state separately
		// Priority: eth0 (Incus bridge) > other non-docker interfaces > docker0
		state, _, err := c.server.GetInstanceState(inst.Name)
		if err == nil && state.Network != nil {
			var fallbackIP string

			// First pass: look for eth0 interface
			for netName, network := range state.Network {
				if netName == "eth0" {
					for _, addr := range network.Addresses {
						if addr.Family == "inet" && addr.Scope == "global" {
							info.IPAddress = addr.Address
							break
						}
					}
				}
			}

			// Second pass: if no eth0, use any non-docker interface
			if info.IPAddress == "" {
				for netName, network := range state.Network {
					if netName != "docker0" && netName != "lo" {
						for _, addr := range network.Addresses {
							if addr.Family == "inet" && addr.Scope == "global" {
								fallbackIP = addr.Address
								break
							}
						}
						if fallbackIP != "" {
							info.IPAddress = fallbackIP
							break
						}
					}
				}
			}

			// Last resort: use docker0 if nothing else found
			if info.IPAddress == "" && fallbackIP == "" {
				for _, network := range state.Network {
					for _, addr := range network.Addresses {
						if addr.Family == "inet" && addr.Scope == "global" {
							info.IPAddress = addr.Address
							break
						}
					}
					if info.IPAddress != "" {
						break
					}
				}
			}
		}

		containers = append(containers, info)
	}

	return containers, nil
}

// GetContainer gets information about a specific container
func (c *Client) GetContainer(name string) (*ContainerInfo, error) {
	inst, _, err := c.server.GetInstance(name)
	if err != nil {
		return nil, fmt.Errorf("failed to get container: %w", err)
	}

	info := &ContainerInfo{
		Name:      inst.Name,
		State:     inst.Status,
		CreatedAt: inst.CreatedAt,
	}

	// Get resource limits
	if cpu, ok := inst.Config["limits.cpu"]; ok {
		info.CPU = cpu
	}
	if mem, ok := inst.Config["limits.memory"]; ok {
		info.Memory = mem
	}

	// Get IP address - need to get state separately
	// Priority: eth0 (Incus bridge) > other non-docker interfaces > docker0
	state, _, err := c.server.GetInstanceState(name)
	if err == nil && state.Network != nil {
		var fallbackIP string

		// First pass: look for eth0 interface
		for netName, network := range state.Network {
			if netName == "eth0" {
				for _, addr := range network.Addresses {
					if addr.Family == "inet" && addr.Scope == "global" {
						info.IPAddress = addr.Address
						break
					}
				}
			}
		}

		// Second pass: if no eth0, use any non-docker interface
		if info.IPAddress == "" {
			for netName, network := range state.Network {
				if netName != "docker0" && netName != "lo" {
					for _, addr := range network.Addresses {
						if addr.Family == "inet" && addr.Scope == "global" {
							fallbackIP = addr.Address
							break
						}
					}
					if fallbackIP != "" {
						info.IPAddress = fallbackIP
						break
					}
				}
			}
		}

		// Last resort: use docker0 if nothing else found
		if info.IPAddress == "" && fallbackIP == "" {
			for _, network := range state.Network {
				for _, addr := range network.Addresses {
					if addr.Family == "inet" && addr.Scope == "global" {
						info.IPAddress = addr.Address
						break
					}
				}
				if info.IPAddress != "" {
					break
				}
			}
		}
	}

	return info, nil
}

// Exec executes a command inside a container
func (c *Client) Exec(containerName string, command []string) error {
	req := api.InstanceExecPost{
		Command:     command,
		WaitForWS:   true,
		Interactive: false,
	}

	op, err := c.server.ExecInstance(containerName, req, nil)
	if err != nil {
		return fmt.Errorf("failed to execute command: %w", err)
	}

	if err := op.Wait(); err != nil {
		return fmt.Errorf("command execution failed: %w", err)
	}

	return nil
}

// WaitForNetwork waits for the container to have a network IP
func (c *Client) WaitForNetwork(containerName string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		info, err := c.GetContainer(containerName)
		if err != nil {
			return "", err
		}

		if info.IPAddress != "" {
			return info.IPAddress, nil
		}

		time.Sleep(1 * time.Second)
	}

	return "", fmt.Errorf("timeout waiting for container network")
}

// GetServerInfo gets information about the Incus server
func (c *Client) GetServerInfo() (*api.Server, error) {
	server, _, err := c.server.GetServer()
	if err != nil {
		return nil, fmt.Errorf("failed to get server info: %w", err)
	}
	return server, nil
}

// SetConfig sets a configuration key for a container (e.g., limits.cpu, limits.memory)
func (c *Client) SetConfig(containerName, key, value string) error {
	// Get current container configuration
	inst, etag, err := c.server.GetInstance(containerName)
	if err != nil {
		return fmt.Errorf("failed to get container: %w", err)
	}

	// Update the configuration
	inst.Config[key] = value

	// Apply the changes
	op, err := c.server.UpdateInstance(containerName, inst.Writable(), etag)
	if err != nil {
		return fmt.Errorf("failed to update container config: %w", err)
	}

	// Wait for the operation to complete
	err = op.Wait()
	if err != nil {
		return fmt.Errorf("failed to wait for config update: %w", err)
	}

	return nil
}

// SetDeviceSize sets the size of a device (e.g., root disk)
func (c *Client) SetDeviceSize(containerName, deviceName, size string) error {
	// Get current container configuration
	inst, etag, err := c.server.GetInstance(containerName)
	if err != nil {
		return fmt.Errorf("failed to get container: %w", err)
	}

	// Check if device exists
	device, exists := inst.Devices[deviceName]
	if !exists {
		return fmt.Errorf("device %s not found in container", deviceName)
	}

	// Update the device size
	device["size"] = size
	inst.Devices[deviceName] = device

	// Apply the changes
	op, err := c.server.UpdateInstance(containerName, inst.Writable(), etag)
	if err != nil {
		return fmt.Errorf("failed to update device size: %w", err)
	}

	// Wait for the operation to complete
	err = op.Wait()
	if err != nil {
		return fmt.Errorf("failed to wait for device update: %w", err)
	}

	return nil
}

// CheckVersion checks if the Incus version meets minimum requirements
// Returns a warning message if version is below 6.19 (Docker build support)
func (c *Client) CheckVersion() (string, error) {
	server, err := c.GetServerInfo()
	if err != nil {
		return "", fmt.Errorf("failed to get Incus version: %w", err)
	}

	version := server.Environment.ServerVersion

	// Parse version (format: "6.20" or "6.0.0")
	var major, minor int
	_, err = fmt.Sscanf(version, "%d.%d", &major, &minor)
	if err != nil {
		// Could not parse version, return warning but don't fail
		return fmt.Sprintf("WARNING: Could not parse Incus version '%s', Docker builds may fail if running Incus < 6.19", version), nil
	}

	// Check minimum version (6.19+)
	if major < 6 || (major == 6 && minor < 19) {
		return fmt.Sprintf("WARNING: Incus %s detected. Docker builds require Incus 6.19+ due to AppArmor bug (CVE-2025-52881).\nInstall from Zabbly repository: https://pkgs.zabbly.com/", version), nil
	}

	return "", nil // Version is OK
}
