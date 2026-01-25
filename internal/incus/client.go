package incus

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"time"

	incus "github.com/lxc/incus/client"
	"github.com/lxc/incus/shared/api"
)

// Client wraps the Incus API client
type Client struct {
	server incus.InstanceServer
}

// DiskDevice represents a disk device configuration
type DiskDevice struct {
	Path string // Mount path (e.g., "/")
	Pool string // Storage pool name (e.g., "default")
	Size string // Disk size (e.g., "20GB")
}

// ToMap converts DiskDevice to the map format required by Incus API
func (d DiskDevice) ToMap() map[string]string {
	m := map[string]string{
		"type": "disk",
		"path": d.Path,
		"pool": d.Pool,
	}
	if d.Size != "" {
		m["size"] = d.Size
	}
	return m
}

// NICDevice represents a network interface device configuration
type NICDevice struct {
	Name        string // Interface name (e.g., "eth0")
	Network     string // Network name (e.g., "incusbr0")
	IPv4Address string // Static IPv4 address (empty for DHCP)
}

// ToMap converts NICDevice to the map format required by Incus API
func (n NICDevice) ToMap() map[string]string {
	m := map[string]string{
		"type":    "nic",
		"name":    n.Name,
		"network": n.Network,
	}
	if n.IPv4Address != "" {
		m["ipv4.address"] = n.IPv4Address
	}
	return m
}

// ContainerConfig holds configuration for creating a container
type ContainerConfig struct {
	Name                   string
	Image                  string
	CPU                    string
	Memory                 string
	Disk                   *DiskDevice // Root disk configuration
	NIC                    *NICDevice  // Network interface configuration
	EnableNesting          bool
	EnableDockerPrivileged bool // Full Docker support (requires privileged container + AppArmor disabled)
	AutoStart              bool
}

// ContainerInfo holds information about a container
type ContainerInfo struct {
	Name      string
	State     string
	IPAddress string
	CPU       string
	Memory    string
	Disk      string
	GPU       string // GPU device info (e.g., "nvidia.com/gpu" or GPU ID)
	CreatedAt time.Time
}

// ContainerMetrics holds runtime metrics for a container
type ContainerMetrics struct {
	Name             string
	CPUUsageSeconds  int64   // CPU usage in seconds
	MemoryUsageBytes int64   // Current memory usage in bytes
	MemoryLimitBytes int64   // Memory limit in bytes
	DiskUsageBytes   int64   // Root disk usage in bytes
	NetworkRxBytes   int64   // Network bytes received
	NetworkTxBytes   int64   // Network bytes transmitted
	ProcessCount     int32   // Number of running processes
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
//   - "images:ubuntu/24.04" -> remote from images.linuxcontainers.org
//   - "ubuntu/24.04" -> defaults to images.linuxcontainers.org (most common)
//   - "ubuntu:24.04" -> remote from cloud-images.ubuntu.com
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
	} else if strings.Contains(image, "/") {
		// Format like "ubuntu/24.04" without remote prefix
		// Default to images.linuxcontainers.org which is most commonly used
		source.Server = "https://images.linuxcontainers.org"
		source.Protocol = "simplestreams"
		source.Alias = image
	} else {
		// Simple name like "ubuntu" - treat as local alias
		source.Alias = image
	}

	return source
}

// CreateContainer creates a new container with the specified configuration
func (c *Client) CreateContainer(config ContainerConfig) error {
	// Debug: Log the image being used
	fmt.Printf("[DEBUG] CreateContainer - Image: '%s'\n", config.Image)

	// Prepare container creation request
	req := api.InstancesPost{
		Name: config.Name,
		Type: api.InstanceTypeContainer,
	}

	// Parse image source - handle remote images like "images:ubuntu/24.04"
	req.Source = parseImageSource(config.Image)

	// Debug: Log the parsed source
	fmt.Printf("[DEBUG] CreateContainer - Source: Type=%s, Server=%s, Protocol=%s, Alias=%s\n",
		req.Source.Type, req.Source.Server, req.Source.Protocol, req.Source.Alias)

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

	// Full Docker-in-Docker support (privileged mode with AppArmor disabled)
	// This is required for Docker to run properly inside the container
	if config.EnableDockerPrivileged {
		req.Config["security.privileged"] = "true"
		req.Config["raw.lxc"] = "lxc.apparmor.profile=unconfined"
	}

	// Auto-start on boot
	if config.AutoStart {
		req.Config["boot.autostart"] = "true"
	}

	// Device configuration
	req.Devices = make(map[string]map[string]string)

	// Root disk device
	if config.Disk != nil {
		req.Devices["root"] = config.Disk.ToMap()
		fmt.Printf("[DEBUG] CreateContainer - Disk: path=%s, pool=%s, size=%s\n",
			config.Disk.Path, config.Disk.Pool, config.Disk.Size)
	}

	// Network interface device
	if config.NIC != nil {
		req.Devices[config.NIC.Name] = config.NIC.ToMap()
		if config.NIC.IPv4Address != "" {
			fmt.Printf("[DEBUG] CreateContainer - NIC: name=%s, network=%s, static_ip=%s\n",
				config.NIC.Name, config.NIC.Network, config.NIC.IPv4Address)
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
	reqState := api.InstanceStatePut{
		Action:  "stop",
		Timeout: 30,
		Force:   force,
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
	// Get list of instance names first
	names, err := c.server.GetInstanceNames(api.InstanceTypeContainer)
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	var containers []ContainerInfo
	for _, name := range names {
		// Get full instance details for each container
		inst, _, err := c.server.GetInstance(name)
		if err != nil {
			continue // Skip containers we can't get details for
		}

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

		// Parse devices for disk and GPU information
		for deviceName, device := range inst.Devices {
			deviceType, ok := device["type"]
			if !ok {
				continue
			}

			// Check for disk devices (root disk)
			if deviceType == "disk" && deviceName == "root" {
				if size, ok := device["size"]; ok {
					info.Disk = size
				}
			}

			// Check for GPU devices
			if deviceType == "gpu" {
				// GPU device found - could be physical GPU passthrough or mdev
				if id, ok := device["id"]; ok {
					info.GPU = id
				} else if pci, ok := device["pci"]; ok {
					info.GPU = pci
				} else {
					info.GPU = "GPU" // Generic GPU indicator
				}
			}
		}

		// If no disk size found, check expanded devices (includes profile devices)
		if info.Disk == "" {
			for deviceName, device := range inst.ExpandedDevices {
				deviceType, ok := device["type"]
				if !ok {
					continue
				}
				if deviceType == "disk" && deviceName == "root" {
					if size, ok := device["size"]; ok {
						info.Disk = size
					}
				}
			}
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

	// Parse devices for disk and GPU information
	// First check instance-specific devices
	for deviceName, device := range inst.Devices {
		deviceType, ok := device["type"]
		if !ok {
			continue
		}

		// Check for disk devices (root disk)
		if deviceType == "disk" && deviceName == "root" {
			if size, ok := device["size"]; ok {
				info.Disk = size
			}
		}

		// Check for GPU devices
		if deviceType == "gpu" {
			// GPU device found - could be physical GPU passthrough or mdev
			if id, ok := device["id"]; ok {
				info.GPU = id
			} else if pci, ok := device["pci"]; ok {
				info.GPU = pci
			} else {
				info.GPU = "GPU" // Generic GPU indicator
			}
		}
	}

	// If no disk size found, check expanded devices (includes profile devices)
	if info.Disk == "" {
		for deviceName, device := range inst.ExpandedDevices {
			deviceType, ok := device["type"]
			if !ok {
				continue
			}
			if deviceType == "disk" && deviceName == "root" {
				if size, ok := device["size"]; ok {
					info.Disk = size
				}
			}
		}
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

// SystemResources holds system resource information
type SystemResources struct {
	TotalCPUs          int32
	TotalMemoryBytes   int64
	UsedMemoryBytes    int64
	TotalDiskBytes     int64
	UsedDiskBytes      int64
	UptimeSeconds      int64
}

// GetSystemResources gets system resource information from Incus
func (c *Client) GetSystemResources() (*SystemResources, error) {
	resources, err := c.server.GetServerResources()
	if err != nil {
		return nil, fmt.Errorf("failed to get server resources: %w", err)
	}

	res := &SystemResources{
		TotalMemoryBytes: int64(resources.Memory.Total),
		UsedMemoryBytes:  int64(resources.Memory.Used),
	}

	// Count total CPU cores
	for _, socket := range resources.CPU.Sockets {
		for _, core := range socket.Cores {
			res.TotalCPUs += int32(len(core.Threads))
		}
	}

	// Get storage pool info for disk usage
	pools, err := c.server.GetStoragePools()
	if err == nil {
		for _, pool := range pools {
			poolResources, err := c.server.GetStoragePoolResources(pool.Name)
			if err == nil {
				res.TotalDiskBytes += int64(poolResources.Space.Total)
				res.UsedDiskBytes += int64(poolResources.Space.Used)
			}
		}
	}

	return res, nil
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

// GetContainerMetrics gets runtime metrics for a container
func (c *Client) GetContainerMetrics(name string) (*ContainerMetrics, error) {
	state, _, err := c.server.GetInstanceState(name)
	if err != nil {
		return nil, fmt.Errorf("failed to get container state: %w", err)
	}

	metrics := &ContainerMetrics{
		Name:         name,
		ProcessCount: int32(state.Processes),
	}

	// CPU usage (in nanoseconds, convert to seconds)
	if state.CPU.Usage > 0 {
		metrics.CPUUsageSeconds = state.CPU.Usage / 1000000000
	}

	// Memory usage
	if state.Memory.Usage > 0 {
		metrics.MemoryUsageBytes = state.Memory.Usage
	}
	if state.Memory.UsagePeak > 0 {
		metrics.MemoryLimitBytes = state.Memory.UsagePeak
	}

	// Disk usage (root filesystem)
	if rootDisk, ok := state.Disk["root"]; ok {
		metrics.DiskUsageBytes = rootDisk.Usage
	}

	// Network usage (sum all interfaces except lo)
	for netName, network := range state.Network {
		if netName != "lo" {
			metrics.NetworkRxBytes += network.Counters.BytesReceived
			metrics.NetworkTxBytes += network.Counters.BytesSent
		}
	}

	return metrics, nil
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

// NetworkConfig holds configuration for creating a network
type NetworkConfig struct {
	Name        string // Network name (default: "incusbr0")
	IPv4Address string // IPv4 address with CIDR (default: "10.100.0.1/24")
	IPv4NAT     bool   // Enable NAT (default: true)
}

// DefaultNetworkConfig returns a safe default network configuration
// Uses 10.100.0.0/24 to avoid conflicts with common subnets like 10.0.0.0/8
func DefaultNetworkConfig() NetworkConfig {
	return NetworkConfig{
		Name:        "incusbr0",
		IPv4Address: "10.100.0.1/24",
		IPv4NAT:     true,
	}
}

// EnsureNetwork creates a network if it doesn't exist
// Returns the network name
func (c *Client) EnsureNetwork(config NetworkConfig) (string, error) {
	if config.Name == "" {
		config.Name = "incusbr0"
	}
	if config.IPv4Address == "" {
		config.IPv4Address = "10.100.0.1/24"
	}

	// Check if network already exists
	networks, err := c.server.GetNetworkNames()
	if err != nil {
		return "", fmt.Errorf("failed to list networks: %w", err)
	}

	for _, n := range networks {
		if n == config.Name {
			// Network exists, return it
			return config.Name, nil
		}
	}

	// Create network
	networkReq := api.NetworksPost{
		Name: config.Name,
		Type: "bridge",
		NetworkPut: api.NetworkPut{
			Config: map[string]string{
				"ipv4.address": config.IPv4Address,
				"ipv4.nat":     fmt.Sprintf("%t", config.IPv4NAT),
			},
		},
	}

	if err := c.server.CreateNetwork(networkReq); err != nil {
		return "", fmt.Errorf("failed to create network %s: %w", config.Name, err)
	}

	return config.Name, nil
}

// EnsureStorage creates a storage pool if it doesn't exist
// Returns the storage pool name
func (c *Client) EnsureStorage(name string) (string, error) {
	if name == "" {
		name = "default"
	}

	// Check if storage pool already exists
	pools, err := c.server.GetStoragePoolNames()
	if err != nil {
		return "", fmt.Errorf("failed to list storage pools: %w", err)
	}

	for _, p := range pools {
		if p == name {
			// Pool exists, return it
			return name, nil
		}
	}

	// Create storage pool (using dir driver for simplicity)
	poolReq := api.StoragePoolsPost{
		Name:   name,
		Driver: "dir",
	}

	if err := c.server.CreateStoragePool(poolReq); err != nil {
		return "", fmt.Errorf("failed to create storage pool %s: %w", name, err)
	}

	return name, nil
}

// EnsureDefaultProfile configures the default profile with network and storage
func (c *Client) EnsureDefaultProfile(networkName, storageName string) error {
	// Get current default profile
	profile, _, err := c.server.GetProfile("default")
	if err != nil {
		return fmt.Errorf("failed to get default profile: %w", err)
	}

	// Ensure devices map exists
	if profile.Devices == nil {
		profile.Devices = make(map[string]map[string]string)
	}

	needsUpdate := false

	// Add root disk device if not present
	if _, ok := profile.Devices["root"]; !ok {
		profile.Devices["root"] = map[string]string{
			"type": "disk",
			"path": "/",
			"pool": storageName,
		}
		needsUpdate = true
	}

	// Add eth0 network device if not present
	if _, ok := profile.Devices["eth0"]; !ok {
		profile.Devices["eth0"] = map[string]string{
			"type":    "nic",
			"name":    "eth0",
			"network": networkName,
		}
		needsUpdate = true
	}

	if needsUpdate {
		if err := c.server.UpdateProfile("default", profile.ProfilePut, ""); err != nil {
			return fmt.Errorf("failed to update default profile: %w", err)
		}
	}

	return nil
}

// InitializeInfrastructure ensures network, storage, and default profile are configured
// This should be called once during daemon startup
func (c *Client) InitializeInfrastructure(networkConfig NetworkConfig) error {
	// 1. Ensure storage pool exists
	storageName, err := c.EnsureStorage("default")
	if err != nil {
		return fmt.Errorf("failed to ensure storage: %w", err)
	}

	// 2. Ensure network exists
	networkName, err := c.EnsureNetwork(networkConfig)
	if err != nil {
		return fmt.Errorf("failed to ensure network: %w", err)
	}

	// 3. Configure default profile
	if err := c.EnsureDefaultProfile(networkName, storageName); err != nil {
		return fmt.Errorf("failed to configure default profile: %w", err)
	}

	return nil
}

// GetNetworkSubnet returns the IPv4 subnet of a network
func (c *Client) GetNetworkSubnet(networkName string) (string, error) {
	network, _, err := c.server.GetNetwork(networkName)
	if err != nil {
		return "", fmt.Errorf("failed to get network %s: %w", networkName, err)
	}

	if addr, ok := network.Config["ipv4.address"]; ok {
		return addr, nil
	}

	return "", fmt.Errorf("network %s has no IPv4 address configured", networkName)
}

// WriteFile writes content to a file inside a container
func (c *Client) WriteFile(containerName, path string, content []byte, mode string) error {
	// Use incus file push functionality via the API
	args := incus.InstanceFileArgs{
		Content:   bytes.NewReader(content),
		WriteMode: "overwrite",
	}

	// Set file mode if provided
	if mode != "" {
		// Parse mode string to int
		var modeInt int64
		if _, err := fmt.Sscanf(mode, "%o", &modeInt); err == nil {
			modeVal := int(modeInt)
			args.Mode = modeVal
		}
	}

	err := c.server.CreateInstanceFile(containerName, path, args)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// ReadFile reads content from a file inside a container
func (c *Client) ReadFile(containerName, path string) ([]byte, error) {
	reader, _, err := c.server.GetInstanceFile(containerName, path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	defer reader.Close()

	content, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read file content: %w", err)
	}

	return content, nil
}

// ExecWithOutput executes a command inside a container and returns stdout/stderr
func (c *Client) ExecWithOutput(containerName string, command []string) (string, string, error) {
	var stdout, stderr bytes.Buffer

	req := api.InstanceExecPost{
		Command:     command,
		WaitForWS:   true,
		Interactive: false,
		// Note: RecordOutput cannot be used with WaitForWS
		// We capture output via the args.Stdout/Stderr instead
	}

	// Create exec args with stdio handlers to capture output
	args := &incus.InstanceExecArgs{
		Stdout: &stdout,
		Stderr: &stderr,
	}

	op, err := c.server.ExecInstance(containerName, req, args)
	if err != nil {
		return "", "", fmt.Errorf("failed to execute command: %w", err)
	}

	// Wait for the operation to complete
	err = op.Wait()
	if err != nil {
		return stdout.String(), stderr.String(), fmt.Errorf("command execution failed: %w", err)
	}

	// Check exit code
	opMeta := op.Get()
	if opMeta.Metadata != nil {
		if returnVal, ok := opMeta.Metadata["return"].(float64); ok && returnVal != 0 {
			return stdout.String(), stderr.String(), fmt.Errorf("command exited with code %d", int(returnVal))
		}
	}

	return stdout.String(), stderr.String(), nil
}
