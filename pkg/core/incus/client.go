package incus

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	incus "github.com/lxc/incus/v6/client"
	"github.com/lxc/incus/v6/shared/api"
)

// detectZFSContainersDataset checks if the "incus-local/containers" ZFS dataset exists.
func detectZFSContainersDataset() bool {
	cmd := exec.Command("zfs", "list", "-H", "-o", "name", "incus-local/containers") // #nosec G204 -- hardcoded args
	return cmd.Run() == nil
}

// Client wraps the Incus API client
type Client struct {
	server incus.InstanceServer
}

// Backend is the interface satisfied by *Client. Consumers depend on it (or a
// narrower subset declared at the call site) so they can be mocked in tests.
type Backend interface {
	// Lifecycle
	CreateContainer(config ContainerConfig) error
	StartContainer(name string) error
	StopContainer(name string, force bool) error
	DeleteContainer(name string) error
	GetContainer(name string) (*ContainerInfo, error)
	ListContainers() ([]ContainerInfo, error)
	WaitForNetwork(containerName string, timeout time.Duration) (string, error)

	// Exec & file I/O
	Exec(containerName string, command []string) error
	ExecWithOutput(containerName string, command []string) (string, string, error)
	WriteFile(containerName, path string, content []byte, mode string) error
	ReadFile(containerName, path string) ([]byte, error)

	// Config & devices
	SetConfig(containerName, key, value string) error
	SetDeviceSize(containerName, deviceName, size string) error
	UpdateContainerConfig(name, key, value string) error
	GetRawInstance(name string) (map[string]string, string, error)
	ResolveGPUInputToPCI(input string) (string, error)
	CleanupDisk(containerName string) (string, int64, error)

	// Labels
	AddLabel(containerName, key, value string) error
	RemoveLabel(containerName, key string) error
	GetLabels(containerName string) (map[string]string, error)
	SetLabels(containerName string, labels map[string]string) error

	// Server info & metrics
	GetServerInfo() (*api.Server, error)
	GetContainerMetrics(name string) (*ContainerMetrics, error)
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

// GPUDevice represents a GPU device configuration for passthrough
type GPUDevice struct {
	// ID is the GPU device ID (e.g., "0" for first GPU).
	// Leave empty to pass through all GPUs.
	//
	// Deprecated for new container creation: ID maps to Incus' DRM card
	// minor index, which can shift across kernel upgrades (e.g., the
	// 6.8.0-110 → 6.8.0-111 incident on fts-5900x where the RTX 4090
	// moved from card0 to card1, breaking every container with id="0").
	// Prefer PCI, which is stable across reboots and kernel changes.
	// New code should call ResolveGPUInputToPCI() to convert a
	// user-supplied ID into a PCI address before constructing this.
	ID string
	// PCI is the PCI address (e.g., "0000:0b:00.0") for a specific GPU.
	// Takes precedence over ID if set.
	PCI string
}

// ToMap converts GPUDevice to the map format required by Incus API
func (g GPUDevice) ToMap() map[string]string {
	m := map[string]string{
		"type": "gpu",
	}
	if g.PCI != "" {
		m["pci"] = g.PCI
	} else if g.ID != "" {
		m["id"] = g.ID
	}
	return m
}

// ResolveGPUInputToPCI converts a user-supplied GPU identifier (typically
// "0", "1", or a PCI address like "0000:0b:00.0") into a PCI address by
// looking up the system's GPU list. Returns the original input unchanged
// when it's already PCI-shaped. Returns an error if the input is a
// numeric index out of range, or if no GPUs are detected.
//
// Why we do this: Incus' "id" field for GPU devices is the DRM card
// minor (the digit at the end of /dev/dri/cardN). That index can shift
// across kernel upgrades when the kernel's DRM enumeration order
// changes — the resulting "Failed to detect requested GPU device"
// error is silent (no preflight) and only surfaces on the next
// container start. PCI addresses are stable, so we resolve before
// writing the device config.
func (c *Client) ResolveGPUInputToPCI(input string) (string, error) {
	// Pure-function part is testable without an Incus daemon.
	// If the input is already PCI-shaped, no daemon call needed.
	if pci, ok, err := classifyGPUInput(input); err != nil {
		return "", err
	} else if ok {
		return pci, nil
	}
	// Numeric index path requires enumerating system GPUs.
	idx, _ := strconv.Atoi(input) // already validated by classifyGPUInput
	res, err := c.GetSystemResources()
	if err != nil {
		return "", fmt.Errorf("GPU input %q: failed to enumerate system GPUs: %w", input, err)
	}
	return resolveGPUByIndex(input, idx, res.GPUs)
}

// classifyGPUInput returns (pci, true, nil) if input is already a PCI
// address; (empty, false, nil) if it's a valid numeric index needing
// resolution; (empty, false, err) for invalid inputs (empty / bad format).
func classifyGPUInput(input string) (string, bool, error) {
	if input == "" {
		return "", false, fmt.Errorf("empty GPU input")
	}
	if strings.Contains(input, ":") {
		// "0000:0b:00.0" — pass through unchanged
		return input, true, nil
	}
	idx, err := strconv.Atoi(input)
	if err != nil || idx < 0 {
		return "", false, fmt.Errorf("GPU input %q: not a PCI address or non-negative integer", input)
	}
	_ = idx
	return "", false, nil
}

// resolveGPUByIndex picks the Nth GPU's PCI address from a list.
func resolveGPUByIndex(input string, idx int, gpus []GPUInfo) (string, error) {
	if idx >= len(gpus) {
		return "", fmt.Errorf("GPU input %q: index %d out of range (system has %d GPU(s))", input, idx, len(gpus))
	}
	pci := gpus[idx].PCIAddress
	if pci == "" {
		return "", fmt.Errorf("GPU input %q: GPU at index %d has no PCI address (vendor=%q, model=%q)", input, idx, gpus[idx].Vendor, gpus[idx].Model)
	}
	return pci, nil
}

// ContainerConfig holds configuration for creating a container
type ContainerConfig struct {
	Name                   string
	Image                  string
	CPU                    string
	Memory                 string
	Disk                   *DiskDevice    // Root disk configuration
	NIC                    *NICDevice     // Network interface configuration
	GPU                    *GPUDevice     // GPU device configuration for passthrough
	InstanceType           api.InstanceType // Container (LXC) or VM (QEMU/KVM). Defaults to Container.
	EnableNesting          bool
	EnablePodmanPrivileged bool // Full Docker support (requires privileged container + AppArmor disabled)
	AutoStart              bool

	// Env is a map of environment variables to set inside the
	// container, equivalent to `incus config set <name>
	// environment.<KEY> <value>`. Visible to every shell session and
	// to systemd-managed processes. Used today for the OTel
	// app-monitoring opt-in (OTEL_EXPORTER_OTLP_ENDPOINT etc.) and
	// can host other platform-injected env vars going forward.
	Env map[string]string
}

// LabelPrefix is the prefix used for storing labels in Incus container config
// Note: Incus requires user-defined config keys to use the "user." prefix
const LabelPrefix = "user.containarium.label."

// RoleKey is the Incus config key used to tag core containers by role.
const RoleKey = "user.containarium.role"

// Role is a typed string for core container roles.
type Role string

// Core container roles
const (
	RoleNone              Role = ""
	RolePostgres          Role = "core-postgres"
	RoleCaddy             Role = "core-caddy"
	RoleVictoriaMetrics   Role = "core-victoriametrics"
	RoleSecurity          Role = "core-security"
	RoleGuacamole         Role = "core-guacamole"
	RoleOTelCollector     Role = "core-otelcollector"
)

// IsCoreRole returns true if the role represents a core container.
func (r Role) IsCoreRole() bool {
	return r != RoleNone
}

// ContainerInfo holds information about a container
type ContainerInfo struct {
	Name         string
	State        string
	IPAddress    string
	CPU          string
	Memory       string
	Disk         string
	GPU          string // GPU device info (e.g., "nvidia.com/gpu" or GPU ID)
	InstanceType string // "container" or "virtual-machine"
	Labels       map[string]string
	Role         Role   // Core container role (e.g., RolePostgres, RoleCaddy), empty for user containers
	CreatedAt    time.Time
	BackendID    string // Backend this container runs on (populated by PeerPool fan-out)

	// MonitoringEnabled is true when the container has OTel
	// env vars stamped (OTEL_EXPORTER_OTLP_ENDPOINT non-empty in
	// the Incus environment config). Derived at read-time from
	// the Incus config map rather than tracked as a separate
	// flag — single source of truth.
	MonitoringEnabled bool

	// AutoSleepEnabled mirrors user.containarium.auto_sleep_enabled
	// on the Incus config — opt-in flag for the serverless feature.
	AutoSleepEnabled bool

	// IdleThresholdMinutes mirrors user.containarium.idle_threshold_minutes;
	// defaults to 15 when the key is missing or unparseable.
	IdleThresholdMinutes int32

	// LastStartedAt mirrors user.containarium.last_started_at, stamped by
	// StartContainer. Zero value when the key is missing or unparseable.
	// Consumed by the Phase 2 auto-sleep ticker for its anti-thrash window.
	LastStartedAt time.Time
}

// AutoSleepEnabledKey is the Incus config key storing the per-container
// auto-sleep opt-in flag (Phase 1 of the serverless feature).
const AutoSleepEnabledKey = "user.containarium.auto_sleep_enabled"

// IdleThresholdMinutesKey is the Incus config key storing the per-container
// idle threshold in minutes consumed by the Phase 2 auto-sleep ticker.
const IdleThresholdMinutesKey = "user.containarium.idle_threshold_minutes"

// LastStartedAtKey is the Incus config key storing the RFC3339 timestamp of
// the most recent StartContainer success. The Phase 2 auto-sleep ticker
// reads it to enforce its anti-thrash window (don't sleep a container
// within 2× the idle threshold of its last start).
const LastStartedAtKey = "user.containarium.last_started_at"

// DefaultIdleThresholdMinutes is the fallback used when the threshold
// config key is missing or unparseable.
const DefaultIdleThresholdMinutes = 15

// parseIdleThresholdMinutes reads the threshold key from an Incus
// config map, falling back to the default for empty/garbage values.
func parseIdleThresholdMinutes(cfg map[string]string) int32 {
	raw, ok := cfg[IdleThresholdMinutesKey]
	if !ok || raw == "" {
		return DefaultIdleThresholdMinutes
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		return DefaultIdleThresholdMinutes
	}
	return int32(n)
}

// parseLastStartedAt reads the last-started timestamp from an Incus config
// map. Missing or unparseable values yield the zero time — callers treat
// that as "unknown" rather than a real moment in epoch history.
func parseLastStartedAt(cfg map[string]string) time.Time {
	raw, ok := cfg[LastStartedAtKey]
	if !ok || raw == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}
	}
	return t
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

	// Prepare instance creation request
	instanceType := config.InstanceType
	if instanceType == "" {
		instanceType = api.InstanceTypeContainer
	}
	req := api.InstancesPost{
		Name: config.Name,
		Type: instanceType,
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
	if config.EnablePodmanPrivileged {
		req.Config["security.privileged"] = "true"
		req.Config["raw.lxc"] = "lxc.apparmor.profile=unconfined"
	}

	// Auto-start on boot
	if config.AutoStart {
		req.Config["boot.autostart"] = "true"
	}

	// Environment variables — Incus stores these as `environment.<KEY>`
	// entries in the config map. Visible to login shells and to
	// systemd-managed processes inside the container.
	for k, v := range config.Env {
		req.Config["environment."+k] = v
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

	// GPU device passthrough
	if config.GPU != nil {
		req.Devices["gpu"] = config.GPU.ToMap()
		fmt.Printf("[DEBUG] CreateContainer - GPU: id=%s, pci=%s\n", config.GPU.ID, config.GPU.PCI)
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
	// Get list of instance names (both containers and VMs)
	names, err := c.server.GetInstanceNames(api.InstanceTypeAny)
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
			Name:                 inst.Name,
			State:                inst.Status,
			InstanceType:         inst.Type,
			CreatedAt:            inst.CreatedAt,
			Labels:               extractLabelsFromConfig(inst.Config),
			Role:                 Role(inst.Config[RoleKey]),
			MonitoringEnabled:    inst.Config["environment.OTEL_EXPORTER_OTLP_ENDPOINT"] != "",
			AutoSleepEnabled:     inst.Config[AutoSleepEnabledKey] == "true",
			IdleThresholdMinutes: parseIdleThresholdMinutes(inst.Config),
			LastStartedAt:        parseLastStartedAt(inst.Config),
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
		// Priority: eth0 (Incus bridge) > other non-container interfaces > container bridge (docker0/podman0)
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

			// Second pass: if no eth0, use any non-container-bridge interface
			if info.IPAddress == "" {
				for netName, network := range state.Network {
					if netName != "docker0" && netName != "podman0" && netName != "lo" {
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

			// Last resort: use container bridge (docker0/podman0) if nothing else found
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
		Name:                 inst.Name,
		State:                inst.Status,
		CreatedAt:            inst.CreatedAt,
		Labels:               extractLabelsFromConfig(inst.Config),
		Role:                 Role(inst.Config[RoleKey]),
		MonitoringEnabled:    inst.Config["environment.OTEL_EXPORTER_OTLP_ENDPOINT"] != "",
		AutoSleepEnabled:     inst.Config[AutoSleepEnabledKey] == "true",
		IdleThresholdMinutes: parseIdleThresholdMinutes(inst.Config),
		LastStartedAt:        parseLastStartedAt(inst.Config),
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
	// Priority: eth0 (Incus bridge) > other non-container interfaces > container bridge (docker0/podman0)
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

		// Second pass: if no eth0, use any non-container-bridge interface
		if info.IPAddress == "" {
			for netName, network := range state.Network {
				if netName != "docker0" && netName != "podman0" && netName != "lo" {
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

		// Last resort: use container bridge (docker0/podman0) if nothing else found
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

// GetContainerIP returns the IP address of a container, or empty string if not found
func (c *Client) GetContainerIP(containerName string) (string, error) {
	info, err := c.GetContainer(containerName)
	if err != nil {
		return "", err
	}
	return info.IPAddress, nil
}

// FindCaddyContainerIP looks for a Caddy container and returns its IP address
// It searches for containers with "caddy" in the name (case-insensitive)
func (c *Client) FindCaddyContainerIP() (string, error) {
	containers, err := c.ListContainers()
	if err != nil {
		return "", fmt.Errorf("failed to list containers: %w", err)
	}

	// Look for containers with "caddy" in the name
	for _, container := range containers {
		nameLower := strings.ToLower(container.Name)
		if strings.Contains(nameLower, "caddy") && container.IPAddress != "" {
			return container.IPAddress, nil
		}
	}

	return "", fmt.Errorf("no running Caddy container found")
}

// FindContainerByRole finds a running container with the given role label.
// Returns the first match. Falls back to name-based matching for containers
// created before role labels were introduced.
func (c *Client) FindContainerByRole(role Role) (*ContainerInfo, error) {
	containers, err := c.ListContainers()
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	// First pass: match by role label
	for i, ct := range containers {
		if ct.State != "Running" {
			continue
		}
		inst, _, err := c.server.GetInstance(ct.Name)
		if err != nil {
			continue
		}
		if Role(inst.Config[RoleKey]) == role {
			return &containers[i], nil
		}
	}

	// Fallback: name-based matching for pre-label containers
	for i, ct := range containers {
		if ct.State != "Running" {
			continue
		}
		switch role {
		case RolePostgres:
			if ct.Name == "containarium-core-postgres" {
				return &containers[i], nil
			}
		case RoleCaddy:
			if ct.Name == "containarium-core-caddy" || strings.Contains(strings.ToLower(ct.Name), "caddy") {
				return &containers[i], nil
			}
		case RoleVictoriaMetrics:
			if ct.Name == "containarium-core-victoriametrics" {
				return &containers[i], nil
			}
		case RoleSecurity:
			if ct.Name == "containarium-core-security" {
				return &containers[i], nil
			}
		}
	}

	return nil, fmt.Errorf("no running container found with role %s", role)
}

// UpdateContainerConfig sets a single config key on a container.
func (c *Client) UpdateContainerConfig(name, key, value string) error {
	inst, etag, err := c.server.GetInstance(name)
	if err != nil {
		return fmt.Errorf("failed to get container %s: %w", name, err)
	}
	inst.Config[key] = value
	op, err := c.server.UpdateInstance(name, inst.Writable(), etag)
	if err != nil {
		return fmt.Errorf("failed to update container config: %w", err)
	}
	return op.Wait()
}

// GetRawInstance returns the raw config map for a container.
func (c *Client) GetRawInstance(name string) (map[string]string, string, error) {
	inst, etag, err := c.server.GetInstance(name)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get instance %s: %w", name, err)
	}
	return inst.Config, etag, nil
}

// GetServerInfo gets information about the Incus server
func (c *Client) GetServerInfo() (*api.Server, error) {
	server, _, err := c.server.GetServer()
	if err != nil {
		return nil, fmt.Errorf("failed to get server info: %w", err)
	}
	return server, nil
}

// GPUInfo holds information about a GPU device
type GPUInfo struct {
	Vendor        string // e.g., "NVIDIA Corporation", "AMD", "Intel"
	Model         string // e.g., "GeForce RTX 4090", "NVIDIA A100"
	PCIAddress    string // e.g., "0000:0b:00.0"
	DriverVersion string // e.g., "570.86.15"
	CUDAVersion   string // NVIDIA only
	VRAMBytes     int64  // VRAM in bytes (when available)
}

// SystemResources holds system resource information
type SystemResources struct {
	TotalCPUs          int32
	TotalMemoryBytes   int64
	UsedMemoryBytes    int64
	TotalDiskBytes     int64
	UsedDiskBytes      int64
	UptimeSeconds      int64
	// CPU load averages (from /proc/loadavg)
	CPULoad1Min  float64
	CPULoad5Min  float64
	CPULoad15Min float64
	// GPU devices
	GPUs []GPUInfo
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

	// Get CPU load averages from /proc/loadavg
	load1, load5, load15, err := getCPULoadAvg()
	if err == nil {
		res.CPULoad1Min = load1
		res.CPULoad5Min = load5
		res.CPULoad15Min = load15
	}

	// Detect GPU devices
	for _, card := range resources.GPU.Cards {
		gpu := GPUInfo{
			PCIAddress:    card.PCIAddress,
			DriverVersion: card.DriverVersion,
		}
		if card.Vendor != "" {
			gpu.Vendor = card.Vendor
		} else if card.VendorID != "" {
			gpu.Vendor = card.VendorID
		}
		if card.Product != "" {
			gpu.Model = card.Product
		} else if card.ProductID != "" {
			gpu.Model = card.ProductID
		}
		// Enrich with NVIDIA-specific info
		if card.Nvidia != nil {
			if card.Nvidia.Model != "" {
				gpu.Model = card.Nvidia.Model
			}
			gpu.CUDAVersion = card.Nvidia.CUDAVersion
			gpu.DriverVersion = card.Nvidia.NVRMVersion
			gpu.Vendor = "NVIDIA"
		}
		res.GPUs = append(res.GPUs, gpu)
	}

	return res, nil
}

// getCPULoadAvg reads CPU load averages from /proc/loadavg
func getCPULoadAvg() (load1, load5, load15 float64, err error) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0, err
	}

	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return 0, 0, 0, fmt.Errorf("unexpected /proc/loadavg format")
	}

	load1, err = strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, 0, 0, err
	}
	load5, err = strconv.ParseFloat(fields[1], 64)
	if err != nil {
		return 0, 0, 0, err
	}
	load15, err = strconv.ParseFloat(fields[2], 64)
	if err != nil {
		return 0, 0, 0, err
	}

	return load1, load5, load15, nil
}

// SetConfig sets a configuration key for a container (e.g., limits.cpu, limits.memory)
// SetEnv sets an environment variable on an existing container. Thin
// wrapper over SetConfig with the `environment.` key prefix; used by
// migration adoption to re-stamp OTel env vars at the destination's
// collector IP. Idempotent on retry.
func (c *Client) SetEnv(containerName, key, value string) error {
	return c.SetConfig(containerName, "environment."+key, value)
}

// UnsetEnv removes an environment variable from a container's Incus
// config (i.e. deletes the `environment.<KEY>` config key entirely
// rather than setting it to empty). Idempotent — missing keys are
// not an error. Used by ToggleMonitoring's disable path so the SDK
// inside the container sees an absent OTEL_EXPORTER_OTLP_ENDPOINT
// (which makes it fall back to no-endpoint defaults) rather than
// the literal empty string (which some SDKs treat as a misconfig).
func (c *Client) UnsetEnv(containerName, key string) error {
	inst, etag, err := c.server.GetInstance(containerName)
	if err != nil {
		return fmt.Errorf("failed to get container: %w", err)
	}
	configKey := "environment." + key
	if _, present := inst.Config[configKey]; !present {
		return nil
	}
	delete(inst.Config, configKey)
	op, err := c.server.UpdateInstance(containerName, inst.Writable(), etag)
	if err != nil {
		return fmt.Errorf("failed to update container config: %w", err)
	}
	return op.Wait()
}

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

	// If the disk is full, Incus cannot write backup.yaml during UpdateInstance.
	// Detect this case and temporarily expand the ZFS quota to unblock the operation.
	if deviceName == "root" {
		if err := c.ensureZFSQuotaHeadroom(containerName, device["pool"], size); err != nil {
			fmt.Printf("Warning: ZFS quota pre-expand failed (non-fatal): %v\n", err)
		}
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

// ensureZFSQuotaHeadroom checks if the container's ZFS dataset is at quota and
// temporarily expands it to the target size so Incus can write its backup.yaml.
func (c *Client) ensureZFSQuotaHeadroom(containerName, pool, targetSize string) error {
	if pool == "" {
		pool = "default"
	}

	// Determine the ZFS dataset name: <zfs-pool>/containers/containers/<name>
	// Get the ZFS pool name from the Incus storage pool source
	poolConfig, _, err := c.server.GetStoragePool(pool)
	if err != nil {
		return fmt.Errorf("failed to get storage pool %s: %w", pool, err)
	}

	zfsPool := poolConfig.Config["source"]
	if zfsPool == "" {
		// Try pool name as ZFS pool name
		zfsPool = poolConfig.Name
	}

	dataset := fmt.Sprintf("%s/containers/containers/%s", zfsPool, containerName)

	// Set the ZFS quota to the target size directly
	cmd := exec.Command("zfs", "set", fmt.Sprintf("quota=%s", targetSize), dataset)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("zfs set quota failed on %s: %w (output: %s)", dataset, err, string(output))
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

	// Disk usage (root filesystem). The ZFS / btrfs backends report
	// usage via state.Disk["root"].Usage natively. The "dir" backend
	// — used on lab boxes that don't have a zpool — leaves that
	// field at zero because the host filesystem has no per-container
	// quota accounting. Without a fallback, every dir-backed deploy
	// would show 0 B for disk usage in `list`, MCP `get_metrics`,
	// and the OTel collector, which is misleading enough that
	// operators stop trusting the field entirely. Walking the
	// container's rootfs gives us the same number `du -bs` would
	// (it IS what du does), at a cost that's acceptable for the
	// list-containers cardinality we expect.
	if rootDisk, ok := state.Disk["root"]; ok && rootDisk.Usage > 0 {
		metrics.DiskUsageBytes = rootDisk.Usage
	} else if rootfs := c.containerRootfsPath(name); rootfs != "" {
		if bytes, err := dirSize(rootfs); err == nil {
			metrics.DiskUsageBytes = bytes
		}
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

// EnsureStorage creates a storage pool if it doesn't exist.
// It auto-detects ZFS pools: if a ZFS pool named "incus-local" exists with a
// "containers" dataset, it creates a ZFS-backed Incus storage pool using it.
// Otherwise, falls back to a directory-backed pool.
// Returns the storage pool name.
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

	// Auto-detect ZFS pool: check if "incus-local/containers" dataset exists
	driver := "dir"
	config := map[string]string{}
	if detectZFSContainersDataset() {
		driver = "zfs"
		config["source"] = "incus-local/containers"
		log.Printf("  Auto-detected ZFS dataset incus-local/containers, using ZFS driver")
	} else {
		log.Printf("  No ZFS dataset found, using dir driver")
	}

	poolReq := api.StoragePoolsPost{
		Name:   name,
		Driver: driver,
		StoragePoolPut: api.StoragePoolPut{
			Config: config,
		},
	}

	if err := c.server.CreateStoragePool(poolReq); err != nil {
		return "", fmt.Errorf("failed to create storage pool %s: %w", name, err)
	}

	return name, nil
}

// GetStorageDriver returns the driver type ("zfs", "dir", etc.) for the named pool.
// Returns "unknown" if the pool cannot be found.
func (c *Client) GetStorageDriver(name string) string {
	pool, _, err := c.server.GetStoragePool(name)
	if err != nil {
		return "unknown"
	}
	return pool.Driver
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

// CleanupDisk frees disk space inside a container by removing temp files,
// package manager caches, and trimming journal logs.
// Returns a human-readable summary and the number of bytes freed.
func (c *Client) CleanupDisk(containerName string) (string, int64, error) {
	// Get disk usage before cleanup
	dfBefore, _, _ := c.ExecWithOutput(containerName, []string{"df", "-B1", "/"})
	usedBefore := parseDfUsedBytes(dfBefore)

	// Run cleanup commands (ignore individual errors — some may not apply)
	cleanupScript := `
rm -rf /tmp/* /tmp/.* 2>/dev/null
apt-get clean 2>/dev/null
dnf clean all 2>/dev/null
journalctl --vacuum-size=50M 2>/dev/null
`
	c.ExecWithOutput(containerName, []string{"/bin/bash", "-c", cleanupScript})

	// Get disk usage after cleanup
	dfAfter, _, _ := c.ExecWithOutput(containerName, []string{"df", "-B1", "/"})
	usedAfter := parseDfUsedBytes(dfAfter)

	var freedBytes int64
	if usedBefore > 0 && usedAfter > 0 && usedBefore > usedAfter {
		freedBytes = usedBefore - usedAfter
	}

	summary := fmt.Sprintf("Cleaned temp files, package cache, and trimmed journal logs. Freed %s.", formatBytesHuman(freedBytes))
	return summary, freedBytes, nil
}

// parseDfUsedBytes parses "df -B1 /" output and returns the "Used" column in bytes.
func parseDfUsedBytes(dfOutput string) int64 {
	lines := strings.Split(strings.TrimSpace(dfOutput), "\n")
	if len(lines) < 2 {
		return 0
	}
	fields := strings.Fields(lines[1])
	if len(fields) < 4 {
		return 0
	}
	used, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil {
		return 0
	}
	return used
}

// formatBytesHuman formats bytes into a human-readable string.
func formatBytesHuman(b int64) string {
	if b <= 0 {
		return "0 B"
	}
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	units := []string{"KB", "MB", "GB", "TB"}
	return fmt.Sprintf("%.1f %s", float64(b)/float64(div), units[exp])
}

// extractLabelsFromConfig extracts labels from container config
// Labels are stored with prefix "containarium.label.<key>=<value>"
func extractLabelsFromConfig(config map[string]string) map[string]string {
	labels := make(map[string]string)
	for key, value := range config {
		if strings.HasPrefix(key, LabelPrefix) {
			labelKey := key[len(LabelPrefix):]
			labels[labelKey] = value
		}
	}
	return labels
}

// GetLabels retrieves labels from a container
func (c *Client) GetLabels(containerName string) (map[string]string, error) {
	inst, _, err := c.server.GetInstance(containerName)
	if err != nil {
		return nil, fmt.Errorf("failed to get container: %w", err)
	}
	return extractLabelsFromConfig(inst.Config), nil
}

// SetLabels sets labels on a container, replacing all existing labels
func (c *Client) SetLabels(containerName string, labels map[string]string) error {
	inst, etag, err := c.server.GetInstance(containerName)
	if err != nil {
		return fmt.Errorf("failed to get container: %w", err)
	}

	// Clear existing labels
	for key := range inst.Config {
		if strings.HasPrefix(key, LabelPrefix) {
			delete(inst.Config, key)
		}
	}

	// Set new labels
	for key, value := range labels {
		inst.Config[LabelPrefix+key] = value
	}

	op, err := c.server.UpdateInstance(containerName, inst.Writable(), etag)
	if err != nil {
		return fmt.Errorf("failed to update container labels: %w", err)
	}

	return op.Wait()
}

// AddLabel adds or updates a single label on a container
func (c *Client) AddLabel(containerName, key, value string) error {
	inst, etag, err := c.server.GetInstance(containerName)
	if err != nil {
		return fmt.Errorf("failed to get container: %w", err)
	}

	inst.Config[LabelPrefix+key] = value

	op, err := c.server.UpdateInstance(containerName, inst.Writable(), etag)
	if err != nil {
		return fmt.Errorf("failed to add label: %w", err)
	}

	return op.Wait()
}

// RemoveLabel removes a single label from a container
func (c *Client) RemoveLabel(containerName, key string) error {
	inst, etag, err := c.server.GetInstance(containerName)
	if err != nil {
		return fmt.Errorf("failed to get container: %w", err)
	}

	delete(inst.Config, LabelPrefix+key)

	op, err := c.server.UpdateInstance(containerName, inst.Writable(), etag)
	if err != nil {
		return fmt.Errorf("failed to remove label: %w", err)
	}

	return op.Wait()
}

// MatchLabels checks if a container's labels match the given filter
// All filter labels must be present and have matching values
func MatchLabels(containerLabels, filter map[string]string) bool {
	for key, value := range filter {
		if containerLabels[key] != value {
			return false
		}
	}
	return true
}

// containerRootfsPath resolves the on-disk rootfs directory for the
// named container so dirSize can walk it. Returns "" when the path
// can't be resolved or doesn't exist — callers treat empty as "skip
// the fallback."
//
// Conventional layout (matches incus's "dir" + "zfs" mount layout):
//
//	<pool_source>/containers/<name>/rootfs
//
// When the pool has no explicit source config (the typical dir-
// backend case) we fall back to incus's hard-coded default of
// /var/lib/incus/storage-pools/<pool>.
func (c *Client) containerRootfsPath(containerName string) string {
	inst, _, err := c.server.GetInstance(containerName)
	if err != nil {
		return ""
	}
	pool := ""
	if rootDev, ok := inst.ExpandedDevices["root"]; ok {
		pool = rootDev["pool"]
	}
	if pool == "" {
		pool = "default"
	}
	poolCfg, _, err := c.server.GetStoragePool(pool)
	if err != nil {
		return ""
	}
	path := buildContainerRootfsPath(pool, poolCfg.Config["source"], containerName)
	if _, err := os.Stat(path); err != nil {
		return ""
	}
	return path
}

// buildContainerRootfsPath is the pure path-construction half of
// containerRootfsPath — separated so it's easy to test without an
// Incus server. The poolSource argument matches the value Incus
// stores under `Config["source"]` on a storage pool; an absolute
// path is used as-is, anything else falls through to the conventional
// /var/lib/incus/storage-pools/<pool> default.
func buildContainerRootfsPath(pool, poolSource, containerName string) string {
	base := poolSource
	if !filepath.IsAbs(base) {
		base = filepath.Join("/var/lib/incus/storage-pools", pool)
	}
	return filepath.Join(base, "containers", containerName, "rootfs")
}

// dirSize returns the cumulative size of regular files under root.
// Skips directories, symlinks, sockets, and unreadable entries —
// matches `du -bs` semantics for the metric we surface. Used as a
// fallback when Incus's per-container disk-usage field is zero
// (dir backend has no quota accounting; see GetContainerMetrics).
func dirSize(root string) (int64, error) {
	var total int64
	err := filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			// Unreadable entry — skip rather than abort. A best-
			// effort metric is more useful than no metric.
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		total += info.Size()
		return nil
	})
	return total, err
}
