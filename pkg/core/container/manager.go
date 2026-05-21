package container

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/ospkg"
	"github.com/footprintai/containarium/pkg/core/ostype"
	"github.com/footprintai/containarium/pkg/core/stacks"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	incusapi "github.com/lxc/incus/v6/shared/api"
)

// Manager handles container lifecycle operations
type Manager struct {
	incus incus.Backend
}

// CreateOptions holds options for creating a container
type CreateOptions struct {
	Username               string
	Image                  string
	CPU                    string
	Memory                 string
	Disk                   string // Disk size (e.g., "20GB")
	GPU                    string // GPU device ID for passthrough (e.g., "0", PCI address, or empty for none)
	StaticIP               string // Static IP address (e.g., "10.100.0.100") - empty for DHCP
	SSHKeys                []string
	Labels                 map[string]string // Kubernetes-style labels
	EnablePodman           bool
	EnablePodmanPrivileged bool // Full Docker support (privileged + AppArmor disabled)
	AutoStart              bool
	Verbose                bool
	Stack                  string    // Software stack to install (e.g., "nodejs", "python")
	StackParameters        map[string]string // Stack parameters — passed to install scripts as CONTAINARIUM_STACK_<name> env vars
	OSType                 pb.OSType // Operating system type for the container
	OnProvisioning         func()    // Called when container is running but still provisioning (installing packages/stack)
	RDPPassword            string    // Generated RDP password for Windows VMs (output, set by Create)

	// Monitoring toggles application-emitted OpenTelemetry. When
	// true, the container is created with OTEL_EXPORTER_OTLP_ENDPOINT
	// and related env vars pointing at the core OTel collector LXC,
	// so any OTel SDK inside ships telemetry without app-side config.
	// Default false; see docs/OTEL-COLLECTOR-DESIGN.md.
	Monitoring bool

	// OTelCollectorEndpoint is the collector's OTLP/HTTP endpoint
	// (e.g. "http://10.0.3.142:4318"). Only used when Monitoring=true.
	// Empty + Monitoring=true is logged as a warning and treated as
	// "don't inject env vars" — the collector isn't running on this
	// daemon, so injecting a dead endpoint helps no one.
	OTelCollectorEndpoint string

	// BackendID is this daemon's backend ID, stamped into
	// OTEL_RESOURCE_ATTRIBUTES so cross-VM dashboards can filter by
	// the VM that emitted the metric. Only used when Monitoring=true.
	BackendID string

	// OTelBearer is the per-deployment shared secret stamped onto
	// monitoring=true containers as OTEL_EXPORTER_OTLP_HEADERS=
	// Authorization=Bearer <secret>. Empty omits the header
	// (pre-Phase-2.5 behavior; the collector stays open). Read
	// from the daemon's `/etc/containarium/otel.bearer` via
	// LoadOrCreateOTelBearer in internal/server. Phase 2.5
	// follow-up (audit C-HIGH-5).
	OTelBearer string
}

// New creates a new container manager backed by a real Incus client.
func New() (*Manager, error) {
	client, err := incus.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create Incus client: %w", err)
	}

	return &Manager{incus: client}, nil
}

// NewWithBackend creates a new container manager backed by the given Incus
// implementation. Used by tests to inject a mock; production code uses New.
func NewWithBackend(backend incus.Backend) *Manager {
	return &Manager{incus: backend}
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

	// Resolve image: OSType takes precedence over raw image string
	image := opts.Image
	if opts.OSType != pb.OSType_OS_TYPE_UNSPECIFIED {
		image = ostype.ImageForOSType(opts.OSType)
	}

	isWindows := ostype.IsWindows(opts.OSType)

	config := incus.ContainerConfig{
		Name:                   containerName,
		Image:                  image,
		CPU:                    opts.CPU,
		Memory:                 opts.Memory,
		EnableNesting:          opts.EnablePodman,
		EnablePodmanPrivileged: opts.EnablePodmanPrivileged,
		AutoStart:              opts.AutoStart,
		Env:                    otelEnvVars(opts, containerName),
	}

	// Windows VMs: set instance type and enforce minimum resources
	if isWindows {
		config.InstanceType = incusapi.InstanceTypeVM
		config.EnableNesting = false
		config.EnablePodmanPrivileged = false
		if config.CPU == "" {
			config.CPU = "4"
		}
		if config.Memory == "" {
			config.Memory = "8GB"
		}
	}

	// Configure root disk device if disk size is specified
	diskSize := opts.Disk
	if diskSize == "" && isWindows {
		diskSize = "50GB"
	}
	if diskSize != "" {
		config.Disk = &incus.DiskDevice{
			Path: "/",
			Pool: "default",
			Size: diskSize,
		}
	}

	// Configure network interface with optional static IP
	if opts.StaticIP != "" {
		config.NIC = &incus.NICDevice{
			Name:        "eth0",
			Network:     "incusbr0",
			IPv4Address: opts.StaticIP,
		}
	}

	// Configure GPU passthrough.
	//
	// Resolve the user-supplied input ("0", "1", or a PCI address) to
	// a stable PCI address. Passing the input through as Incus' "id"
	// field is brittle: that field maps to the DRM card minor index,
	// which can shift across kernel upgrades. We hit this in production
	// when the 6.8.0-110 → 6.8.0-111 upgrade renumbered fts-5900x's
	// RTX 4090 from card0 to card1, breaking every container with
	// id="0". PCI addresses are stable, so we always pin by PCI.
	if opts.GPU != "" {
		pci, err := m.incus.ResolveGPUInputToPCI(opts.GPU)
		if err != nil {
			return nil, fmt.Errorf("GPU passthrough setup failed: %w", err)
		}
		config.GPU = &incus.GPUDevice{
			PCI: pci,
		}
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

	// Set labels (including OS type)
	if opts.Labels == nil {
		opts.Labels = make(map[string]string)
	}
	opts.Labels[ostype.OSTypeLabelKey] = ostype.LabelValue(opts.OSType)
	if opts.Verbose {
		fmt.Printf("  Setting %d label(s)...\n", len(opts.Labels))
	}
	if err := m.incus.SetLabels(containerName, opts.Labels); err != nil {
		_ = m.cleanup(containerName)
		return nil, fmt.Errorf("failed to set labels: %w", err)
	}

	// Windows VM: separate provisioning flow
	if isWindows {
		return m.provisionWindowsVM(containerName, &opts)
	}

	// --- Linux container provisioning (steps 3-7) ---

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

	// Signal provisioning state — container is running but still installing packages
	if opts.OnProvisioning != nil {
		opts.OnProvisioning()
	}

	// Step 5: Install packages
	if opts.Verbose {
		if opts.Stack != "" {
			fmt.Printf("  [5/7] Installing Podman, SSH, tools, and %s stack...\n", opts.Stack)
		} else {
			fmt.Println("  [5/7] Installing Podman, SSH, and tools...")
		}
	}

	family := ostype.FamilyForOSType(opts.OSType)
	if err := m.installPackages(containerName, opts.EnablePodman, opts.Stack, opts.StackParameters, opts.Username, family); err != nil {
		_ = m.cleanup(containerName)
		return nil, fmt.Errorf("failed to install packages: %w", err)
	}

	// Step 6: Create user
	if opts.Verbose {
		fmt.Printf("  [6/7] Creating user: %s...\n", opts.Username)
	}

	if err := m.createUser(containerName, opts.Username, family); err != nil {
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

// generatePassword generates a random password of the given byte length (hex-encoded).
func generatePassword(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random password: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// provisionWindowsVM handles the Windows-specific provisioning after the VM
// has been created, started, and labelled.
func (m *Manager) provisionWindowsVM(vmName string, opts *CreateOptions) (*incus.ContainerInfo, error) {
	if opts.Verbose {
		fmt.Println("  [3/4] Waiting for Windows VM network (this may take 1-2 minutes)...")
	}

	// Windows VMs take much longer to boot than Linux containers
	ipAddr, err := m.incus.WaitForNetwork(vmName, 120*time.Second)
	if err != nil {
		_ = m.cleanup(vmName)
		return nil, fmt.Errorf("failed to get VM IP: %w", err)
	}

	if opts.Verbose {
		fmt.Printf("  VM IP: %s\n", ipAddr)
	}

	// Signal provisioning state
	if opts.OnProvisioning != nil {
		opts.OnProvisioning()
	}

	// Generate and set Administrator password
	if opts.Verbose {
		fmt.Println("  [4/4] Setting Administrator password and verifying RDP...")
	}

	password, err := generatePassword(16)
	if err != nil {
		_ = m.cleanup(vmName)
		return nil, fmt.Errorf("failed to generate password: %w", err)
	}

	// Set Administrator password via PowerShell
	psCmd := fmt.Sprintf(
		"Set-LocalUser -Name Administrator -Password (ConvertTo-SecureString '%s' -AsPlainText -Force)",
		password,
	)
	if err := m.incus.Exec(vmName, []string{"powershell", "-Command", psCmd}); err != nil {
		_ = m.cleanup(vmName)
		return nil, fmt.Errorf("failed to set Administrator password: %w", err)
	}

	// Verify RDP is listening on port 3389
	rdpCheck := "Test-NetConnection -ComputerName localhost -Port 3389 -InformationLevel Quiet"
	if err := m.incus.Exec(vmName, []string{"powershell", "-Command", rdpCheck}); err != nil {
		if opts.Verbose {
			fmt.Println("  Warning: RDP port 3389 check failed — RDP may not be enabled in the golden image")
		}
	}

	// Store RDP password as a label on the VM for the server to retrieve
	opts.RDPPassword = password
	if err := m.incus.SetLabels(vmName, map[string]string{
		"rdp-password": password,
	}); err != nil {
		log.Printf("Warning: failed to store RDP password label: %v", err)
	}

	info, err := m.incus.GetContainer(vmName)
	if err != nil {
		return nil, fmt.Errorf("failed to get VM info: %w", err)
	}

	if opts.Verbose {
		fmt.Printf("  Windows VM ready: RDP at %s:3389 (user: Administrator)\n", ipAddr)
	}

	return info, nil
}

// installPackages installs required packages in the container
// stackEnvPrefix builds a shell fragment that exports stack parameters as
// environment variables (CONTAINARIUM_STACK_<name>) for the install script.
// Returns empty string if params is empty. Values are single-quoted with
// embedded single-quotes escaped.
func stackEnvPrefix(params map[string]string) string {
	if len(params) == 0 {
		return ""
	}
	var b strings.Builder
	for k, v := range params {
		// Single-quote escape: close, escape, reopen. 'foo'\''bar' => foo'bar
		escaped := strings.ReplaceAll(v, "'", `'\''`)
		b.WriteString("export CONTAINARIUM_STACK_")
		b.WriteString(k)
		b.WriteString("='")
		b.WriteString(escaped)
		b.WriteString("'; ")
	}
	return b.String()
}

func (m *Manager) installPackages(containerName string, enablePodman bool, stackID string, stackParams map[string]string, username string, family ostype.OSFamily) error {
	pkgMgr := ospkg.ForFamily(family)
	familyStr := string(family)

	// Wait a bit for cloud-init to finish (if present)
	time.Sleep(5 * time.Second)

	// Update package lists
	if err := m.incus.Exec(containerName, pkgMgr.UpdateCmd()); err != nil {
		return fmt.Errorf("package repo update failed: %w", err)
	}

	// Build package list from OS-specific base packages
	packages := pkgMgr.BasePackages()

	// Add Podman
	if enablePodman {
		if pkgMgr.PodmanAvailableInBaseRepos() {
			// RHEL/Rocky: podman is in base repos, just add to package list
			packages = append(packages, "podman")
		} else {
			// Debian/Ubuntu: need Kubic repo for newer Podman
			prereqCmd := pkgMgr.InstallCmd([]string{"curl", "gpg"})
			if err := m.incus.Exec(containerName, prereqCmd); err != nil {
				return fmt.Errorf("failed to install prerequisites: %w", err)
			}

			repoScript := pkgMgr.PodmanRepoScript()
			if repoScript != "" {
				if err := m.incus.Exec(containerName, []string{"/bin/bash", "-c", repoScript}); err != nil {
					log.Printf("Warning: failed to add Podman repository, using distro's podman: %v", err)
				}
			}
			packages = append(packages, "podman")
		}
	}

	// Collect base script packages and run their pre-install commands
	stackMgr := stacks.GetDefault()
	baseScripts := stackMgr.GetAllBaseScripts()
	for _, bs := range baseScripts {
		for _, cmd := range bs.GetPreInstallForFamily(familyStr) {
			cmd = strings.ReplaceAll(cmd, "{{USERNAME}}", username)
			_ = m.incus.Exec(containerName, []string{"bash", "-c", cmd})
		}
		packages = append(packages, bs.GetPackagesForFamily(familyStr)...)
	}

	// Add stack-specific packages and run pre-install commands
	envPrefix := stackEnvPrefix(stackParams)
	if stackID != "" {
		stack, err := stackMgr.GetStack(stackID)
		if err == nil {
			// Run pre-install commands as root (e.g., adding repos). Stack
			// parameters are exported as CONTAINARIUM_STACK_<name> env vars.
			for _, cmd := range stack.GetPreInstallForFamily(familyStr) {
				_ = m.incus.Exec(containerName, []string{"bash", "-c", envPrefix + cmd})
			}
			packages = append(packages, stack.GetPackagesForFamily(familyStr)...)
		}
	}

	// Install packages
	if err := m.incus.Exec(containerName, pkgMgr.InstallCmd(packages)); err != nil {
		return fmt.Errorf("package install failed: %w", err)
	}

	// Enable services and install podman-compose
	if enablePodman {
		if err := m.incus.Exec(containerName, []string{"systemctl", "enable", "podman"}); err != nil {
			return fmt.Errorf("failed to enable podman: %w", err)
		}
		if err := m.incus.Exec(containerName, []string{"systemctl", "start", "podman"}); err != nil {
			return fmt.Errorf("failed to start podman: %w", err)
		}

		// Install podman-compose via pip
		if err := m.incus.Exec(containerName, pkgMgr.PipInstallCmd()); err != nil {
			log.Printf("Warning: failed to install pip: %v", err)
		} else {
			if err := m.incus.Exec(containerName, []string{"pip3", "install", "--break-system-packages", "podman-compose"}); err != nil {
				log.Printf("Warning: failed to install podman-compose via pip: %v", err)
			}
		}
	}

	sshService := pkgMgr.SSHServiceName()
	if err := m.incus.Exec(containerName, []string{"systemctl", "enable", sshService}); err != nil {
		return fmt.Errorf("failed to enable %s: %w", sshService, err)
	}
	if err := m.incus.Exec(containerName, []string{"systemctl", "start", sshService}); err != nil {
		return fmt.Errorf("failed to start %s: %w", sshService, err)
	}

	// Run base scripts post-install commands as root
	for _, bs := range baseScripts {
		for _, cmd := range bs.GetPostInstallForFamily(familyStr) {
			cmd = strings.ReplaceAll(cmd, "{{USERNAME}}", username)
			_ = m.incus.Exec(containerName, []string{"bash", "-c", cmd})
		}
	}

	// Run stack post-install commands as the user. Stack parameters are
	// exported as CONTAINARIUM_STACK_<name> env vars (via su -c, which runs
	// a shell that evaluates the export+command).
	if stackID != "" {
		stackMgr := stacks.GetDefault()
		stack, err := stackMgr.GetStack(stackID)
		if err == nil {
			for _, cmd := range stack.GetPostInstallForFamily(familyStr) {
				userCmd := []string{"su", "-", username, "-c", envPrefix + cmd}
				_ = m.incus.Exec(containerName, userCmd)
			}
		}

		// Add user to docker group if docker stack is selected
		if stackID == "docker" || stackID == "gpu-docker" {
			_ = m.incus.Exec(containerName, []string{"usermod", "-aG", "docker", username})
		}
	}

	// Install cgroup wrappers so nested containers see LXC resource limits
	isDockerStack := stackID == "docker" || stackID == "gpu-docker"
	if err := m.installCgroupWrappers(containerName, enablePodman, isDockerStack); err != nil {
		log.Printf("Warning: failed to install cgroup wrappers: %v", err)
	}

	// Install OCI runtime for Docker so Compose v2 and API-created containers
	// also see LXC cgroup limits (CLI wrapper only catches docker CLI calls)
	if isDockerStack {
		if err := m.installDockerOCIRuntime(containerName); err != nil {
			log.Printf("Warning: failed to install Docker OCI runtime: %v", err)
		}
		// Configure NVIDIA runtime for Docker if gpu-docker stack
		if stackID == "gpu-docker" {
			_ = m.incus.Exec(containerName, []string{"nvidia-ctk", "runtime", "configure", "--runtime=docker"})
			_ = m.incus.Exec(containerName, []string{"systemctl", "restart", "docker"})
		}
	}

	return nil
}

// createUser creates a user in the container with sudo access
func (m *Manager) createUser(containerName, username string, family ostype.OSFamily) error {
	pkgMgr := ospkg.ForFamily(family)

	// Create user (OS-aware: adduser on Debian, useradd on RHEL)
	if err := m.incus.Exec(containerName, pkgMgr.CreateUserCmd(username, "")); err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	// Add to sudo group (OS-aware: "sudo" on Debian, "wheel" on RHEL)
	if err := m.incus.Exec(containerName, []string{"usermod", "-aG", pkgMgr.SudoGroup(), username}); err != nil {
		return fmt.Errorf("failed to add user to sudo: %w", err)
	}

	// Note: Podman typically runs rootless and doesn't require a group
	// But we can optionally add user to 'podman' group if it exists
	_ = m.incus.Exec(containerName, []string{"usermod", "-aG", "podman", username})

	// Allow passwordless sudo
	// SECURITY FIX: Use Incus file push API instead of shell echo
	// This prevents potential shell injection if username validation is ever relaxed
	sudoersLine := fmt.Sprintf("%s ALL=(ALL) NOPASSWD:ALL\n", username)
	sudoersPath := fmt.Sprintf("/etc/sudoers.d/%s", username)

	if err := m.incus.WriteFile(containerName, sudoersPath, []byte(sudoersLine), "0440"); err != nil {
		return fmt.Errorf("failed to configure sudo: %w", err)
	}

	return nil
}

// addSSHKeys adds SSH public keys to a user's authorized_keys
// SECURITY: Uses Incus file push API to avoid shell injection vulnerabilities
func (m *Manager) addSSHKeys(containerName, username string, sshKeys []string) error {
	sshDir := fmt.Sprintf("/home/%s/.ssh", username)
	authorizedKeysPath := fmt.Sprintf("%s/authorized_keys", sshDir)

	// Create .ssh directory
	if err := m.incus.Exec(containerName, []string{"mkdir", "-p", sshDir}); err != nil {
		return fmt.Errorf("failed to create .ssh directory: %w", err)
	}

	// Set permissions on .ssh directory
	if err := m.incus.Exec(containerName, []string{"chmod", "700", sshDir}); err != nil {
		return fmt.Errorf("failed to set .ssh permissions: %w", err)
	}

	// Build authorized_keys content safely (no shell involved).
	// Validate each key to prevent placeholder/template strings (e.g., "YOUR_KEY")
	// from being written as if they were valid SSH keys.
	var keysContent strings.Builder
	for _, key := range sshKeys {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if err := ValidateSSHPublicKey(key); err != nil {
			return fmt.Errorf("invalid SSH key: %w", err)
		}
		keysContent.WriteString(key)
		keysContent.WriteString("\n")
	}

	// SECURITY FIX: Use Incus file push API instead of shell echo
	// This prevents shell injection attacks via malicious SSH key content
	if err := m.incus.WriteFile(containerName, authorizedKeysPath, []byte(keysContent.String()), "0600"); err != nil {
		return fmt.Errorf("failed to write authorized_keys: %w", err)
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
// SetEnv sets an environment variable on an existing container.
// Thin wrapper over the incus client's SetEnv so callers in the
// internal/server layer don't need to import the incus package
// directly. Used by AdoptMigratedContainer to re-stamp OTel env
// vars at the destination's collector IP after a migration.
func (m *Manager) SetEnv(containerName, key, value string) error {
	// The Backend interface used in tests doesn't expose SetEnv, so
	// we type-assert to the concrete client. Tests using the mock
	// backend won't exercise this path (AdoptMigratedContainer is
	// not in the unit test surface today).
	if real, ok := m.incus.(*incus.Client); ok {
		return real.SetEnv(containerName, key, value)
	}
	return fmt.Errorf("SetEnv not supported on this incus backend (mock?)")
}

// UnsetEnv removes an environment variable from an existing
// container's Incus config (deletes the key rather than setting it
// to empty — empty-string OTEL_* vars are treated as misconfigured
// by some SDKs, so absence is the right "disabled" representation).
// Idempotent. Used by ToggleMonitoring's disable path.
func (m *Manager) UnsetEnv(containerName, key string) error {
	if real, ok := m.incus.(*incus.Client); ok {
		return real.UnsetEnv(containerName, key)
	}
	return fmt.Errorf("UnsetEnv not supported on this incus backend (mock?)")
}

// SetConfig writes an arbitrary Incus config key on a container.
// Used by ToggleAutoSleep to persist the user.containarium.* keys
// that Phase 2 and Phase 3 will read.
func (m *Manager) SetConfig(containerName, key, value string) error {
	return m.incus.SetConfig(containerName, key, value)
}

// GetContainerImageFingerprint returns the Incus-computed
// fingerprint of the image the container was created from
// (Phase 3.1 Phase-C). Thin delegate so the server-layer
// digest verifier doesn't need a direct reference to the
// incus backend.
func (m *Manager) GetContainerImageFingerprint(containerName string) (string, error) {
	return m.incus.GetContainerImageFingerprint(containerName)
}

// WriteFile writes a byte slice into the named container at
// `path` with `mode` (e.g. "0400"). Used by the Phase 4.3
// file-delivery secret stamper. Type-asserts to the concrete
// client like SetEnv does; the mock backend used in tests
// surfaces a descriptive error rather than silently
// no-op'ing.
func (m *Manager) WriteFile(containerName, path string, content []byte, mode string) error {
	if real, ok := m.incus.(*incus.Client); ok {
		return real.WriteFile(containerName, path, content, mode)
	}
	return fmt.Errorf("WriteFile not supported on this incus backend (mock?)")
}

// Exec runs a command inside the container. Phase 4.3 uses
// it to mkdir + chmod the /run/secrets directory once per
// stamp; broader callers like AdoptMigratedContainer already
// reach Exec directly via the incus.Client. Type-asserts to
// the concrete client.
func (m *Manager) Exec(containerName string, command []string) error {
	if real, ok := m.incus.(*incus.Client); ok {
		return real.Exec(containerName, command)
	}
	return fmt.Errorf("Exec not supported on this incus backend (mock?)")
}

func (m *Manager) Get(username string) (*incus.ContainerInfo, error) {
	containerName := username + "-container"
	return m.incus.GetContainer(containerName)
}

// Stop stops a running container
func (m *Manager) Stop(username string, force bool) error {
	containerName := username + "-container"
	return m.incus.StopContainer(containerName, force)
}

// Start starts a stopped container
func (m *Manager) Start(username string) error {
	containerName := username + "-container"
	return m.incus.StartContainer(containerName)
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
	// SECURITY FIX: Removed hardcoded developer username path
	homeDirectories := []string{
		os.Getenv("HOME"),
		"/home/ubuntu", // Common on Ubuntu systems
		"/home/admin",  // Common admin user
		"/root",        // Fallback to root
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

// Resize dynamically adjusts container resources (CPU, memory, disk) without downtime
func (m *Manager) Resize(containerName, cpu, memory, disk string, verbose bool) error {
	if verbose {
		fmt.Printf("Resizing container: %s\n", containerName)
	}

	// Check if container exists
	_, err := m.incus.GetContainer(containerName)
	if err != nil {
		return fmt.Errorf("container not found: %w", err)
	}

	changed := false

	// Resize Disk FIRST — if the container's disk is full, Incus cannot write
	// its backup.yaml for any config change. Expanding disk must happen before
	// CPU/memory changes so those updates can succeed.
	if disk != "" {
		if verbose {
			fmt.Printf("  Setting disk size: %s\n", disk)
		}
		if err := m.incus.SetDeviceSize(containerName, "root", disk); err != nil {
			return fmt.Errorf("failed to set disk size: %w", err)
		}
		changed = true
	}

	// Resize CPU
	if cpu != "" {
		if verbose {
			fmt.Printf("  Setting CPU limit: %s\n", cpu)
		}
		if err := m.incus.SetConfig(containerName, "limits.cpu", cpu); err != nil {
			if strings.Contains(err.Error(), "disk quota exceeded") || strings.Contains(err.Error(), "no space left") {
				return fmt.Errorf("container disk is full. Include a larger disk size in the resize request, or clean up disk space first")
			}
			return fmt.Errorf("failed to set CPU limit: %w", err)
		}
		changed = true
	}

	// Resize Memory
	if memory != "" {
		if verbose {
			fmt.Printf("  Setting memory limit: %s\n", memory)
		}
		if err := m.incus.SetConfig(containerName, "limits.memory", memory); err != nil {
			if strings.Contains(err.Error(), "disk quota exceeded") || strings.Contains(err.Error(), "no space left") {
				return fmt.Errorf("container disk is full. Include a larger disk size in the resize request, or clean up disk space first")
			}
			return fmt.Errorf("failed to set memory limit: %w", err)
		}
		changed = true
	}

	if !changed {
		return fmt.Errorf("no resources specified to resize")
	}

	if verbose {
		fmt.Println("  ✓ Resources updated successfully (no restart required)")
	}

	return nil
}

// CleanupDisk frees disk space inside a user's container
func (m *Manager) CleanupDisk(username string) (string, int64, error) {
	containerName := username + "-container"

	// Verify container exists
	_, err := m.incus.GetContainer(containerName)
	if err != nil {
		return "", 0, fmt.Errorf("container not found: %w", err)
	}

	return m.incus.CleanupDisk(containerName)
}

// InstallStack installs a stack or base script on a running container
func (m *Manager) InstallStack(username, stackID string) error {
	containerName := username + "-container"
	effectiveUser := username

	// Try username-container first; fall back to literal name (for core containers)
	info, err := m.incus.GetContainer(containerName)
	if err != nil {
		// Try the name directly (e.g., "containarium-core-caddy")
		info, err = m.incus.GetContainer(username)
		if err != nil {
			return fmt.Errorf("container not found: %w", err)
		}
		containerName = username
		// For non-standard containers, fall back to "ubuntu" as the user
		effectiveUser = "ubuntu"
	}
	if info.State != "Running" {
		return fmt.Errorf("container is not running (state: %s)", info.State)
	}

	// Verify the effective user exists in the container; fall back to "ubuntu"
	if err := m.incus.Exec(containerName, []string{"id", effectiveUser}); err != nil {
		log.Printf("User %q not found in %s, falling back to ubuntu", effectiveUser, containerName)
		effectiveUser = "ubuntu"
	}

	// Look up in both stacks and base_scripts
	stackMgr := stacks.GetDefault()
	stack, isBaseScript, err := stackMgr.GetStackOrBaseScript(stackID)
	if err != nil {
		return fmt.Errorf("unknown stack or base script: %s", stackID)
	}

	// Detect OS family from container label, or probe the container
	family := ostype.Debian
	if osLabel, ok := info.Labels[ostype.OSTypeLabelKey]; ok {
		family = ostype.FamilyFromLabel(osLabel)
	} else {
		family = ostype.DetectFamily(m.incus, containerName)
	}
	pkgMgr := ospkg.ForFamily(family)
	familyStr := string(family)

	// Update package repos
	if err := m.incus.Exec(containerName, pkgMgr.UpdateCmd()); err != nil {
		return fmt.Errorf("package repo update failed: %w", err)
	}

	// Run pre-install commands as root
	for _, cmd := range stack.GetPreInstallForFamily(familyStr) {
		cmd = strings.ReplaceAll(cmd, "{{USERNAME}}", effectiveUser)
		if err := m.incus.Exec(containerName, []string{"bash", "-c", cmd}); err != nil {
			log.Printf("Warning: pre-install command failed: %v", err)
		}
	}

	// Install packages
	pkgs := stack.GetPackagesForFamily(familyStr)
	if len(pkgs) > 0 {
		if err := m.incus.Exec(containerName, pkgMgr.InstallCmd(pkgs)); err != nil {
			return fmt.Errorf("package install failed: %w", err)
		}
	}

	// Run post-install commands
	for _, cmd := range stack.GetPostInstallForFamily(familyStr) {
		cmd = strings.ReplaceAll(cmd, "{{USERNAME}}", effectiveUser)
		if isBaseScript {
			// Base scripts: run as root
			if err := m.incus.Exec(containerName, []string{"bash", "-c", cmd}); err != nil {
				log.Printf("Warning: post-install command failed: %v", err)
			}
		} else {
			// Dev stacks: run as user
			userCmd := []string{"su", "-", effectiveUser, "-c", cmd}
			_ = m.incus.Exec(containerName, userCmd)
		}
	}

	// Install cgroup wrapper for docker stack so nested containers see LXC limits
	if stackID == "docker" {
		if err := m.installCgroupWrappers(containerName, false, true); err != nil {
			log.Printf("Warning: failed to install docker cgroup wrapper: %v", err)
		}
		if err := m.installDockerOCIRuntime(containerName); err != nil {
			log.Printf("Warning: failed to install Docker OCI runtime: %v", err)
		}
	}

	return nil
}

// GetInfo returns detailed information about a container
func (m *Manager) GetInfo(containerName string) (*incus.ContainerInfo, error) {
	return m.incus.GetContainer(containerName)
}

// ContainerExists checks if a container exists
func (m *Manager) ContainerExists(containerName string) bool {
	_, err := m.incus.GetContainer(containerName)
	return err == nil
}

// GetMetrics returns runtime metrics for a container
func (m *Manager) GetMetrics(username string) (*incus.ContainerMetrics, error) {
	containerName := username + "-container"
	return m.incus.GetContainerMetrics(containerName)
}

// GetAllMetrics returns runtime metrics for all containers
func (m *Manager) GetAllMetrics() ([]*incus.ContainerMetrics, error) {
	containers, err := m.incus.ListContainers()
	if err != nil {
		return nil, err
	}

	var metrics []*incus.ContainerMetrics
	for _, c := range containers {
		m, err := m.incus.GetContainerMetrics(c.Name)
		if err != nil {
			continue // Skip containers that fail
		}
		metrics = append(metrics, m)
	}

	return metrics, nil
}

// SetLabels sets labels on a container, replacing all existing labels
func (m *Manager) SetLabels(username string, labels map[string]string) error {
	containerName := username + "-container"
	return m.incus.SetLabels(containerName, labels)
}

// GetLabels retrieves labels from a container
func (m *Manager) GetLabels(username string) (map[string]string, error) {
	containerName := username + "-container"
	return m.incus.GetLabels(containerName)
}

// AddLabel adds or updates a single label on a container
func (m *Manager) AddLabel(username, key, value string) error {
	containerName := username + "-container"
	return m.incus.AddLabel(containerName, key, value)
}

// RemoveLabel removes a single label from a container
func (m *Manager) RemoveLabel(username, key string) error {
	containerName := username + "-container"
	return m.incus.RemoveLabel(containerName, key)
}

// ListWithLabels lists containers filtered by labels
func (m *Manager) ListWithLabels(labelFilter map[string]string) ([]incus.ContainerInfo, error) {
	containers, err := m.incus.ListContainers()
	if err != nil {
		return nil, err
	}

	if len(labelFilter) == 0 {
		return containers, nil
	}

	// Filter by labels
	var filtered []incus.ContainerInfo
	for _, c := range containers {
		if incus.MatchLabels(c.Labels, labelFilter) {
			filtered = append(filtered, c)
		}
	}

	return filtered, nil
}
