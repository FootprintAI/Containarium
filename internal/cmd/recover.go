package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/collaborator"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// RecoveryConfig holds the configuration for disaster recovery
type RecoveryConfig struct {
	// Network configuration
	NetworkName string `yaml:"network_name"`
	NetworkCIDR string `yaml:"network_cidr"`

	// Storage configuration
	StoragePoolName string `yaml:"storage_pool_name"`
	StorageDriver   string `yaml:"storage_driver"`
	ZFSSource       string `yaml:"zfs_source"`

	// Daemon configuration (for restoring systemd service)
	DaemonFlags DaemonConfig `yaml:"daemon"`
}

// DaemonConfig holds daemon startup flags
type DaemonConfig struct {
	Address       string `yaml:"address"`
	Port          int    `yaml:"port"`
	HTTPPort      int    `yaml:"http_port"`
	BaseDomain    string `yaml:"base_domain"`
	CaddyAdminURL string `yaml:"caddy_admin_url"`
	JWTSecretFile string `yaml:"jwt_secret_file"`
	AppHosting    bool   `yaml:"app_hosting"`
	SkipInfraInit bool   `yaml:"skip_infra_init"`
}

// DefaultRecoveryConfigPath is the default path for recovery config on persistent storage
const DefaultRecoveryConfigPath = "/mnt/incus-data/containarium-recovery.yaml"

var (
	recoverConfigFile   string
	recoverNetworkCIDR  string
	recoverNetworkName  string
	recoverStoragePool  string
	recoverStorageDriver string
	recoverZFSSource    string
	recoverDryRun       bool
	recoverSkipAccounts bool
	recoverStartAll     bool
)

var recoverCmd = &cobra.Command{
	Use:   "recover",
	Short: "Recover containers and settings after instance recreation",
	Long: `Recover containers, network, and SSH accounts after the jump server is recreated.

This command performs disaster recovery when the boot disk is lost but containers
persist on the external ZFS storage pool. It handles:

1. Network creation (incusbr0 with correct CIDR)
2. Storage pool import via 'incus admin recover'
3. Starting all recovered containers
4. Syncing jump server SSH accounts from container keys

Two modes are supported:

EXPLICIT MODE - Specify all parameters via flags:
  containarium recover \
    --network-cidr 10.0.3.1/24 \
    --zfs-source incus-pool/containers

CONFIG MODE - Load from config file on persistent disk:
  containarium recover --config /mnt/incus-data/containarium-recovery.yaml

The config file is automatically saved during normal daemon operation,
so it survives instance recreation when stored on persistent disk.

Examples:
  # Recover using config file (recommended)
  containarium recover --config /mnt/incus-data/containarium-recovery.yaml

  # Recover with explicit parameters
  containarium recover \
    --network-name incusbr0 \
    --network-cidr 10.0.3.1/24 \
    --storage-pool default \
    --storage-driver zfs \
    --zfs-source incus-pool/containers

  # Dry run - show what would be done
  containarium recover --config /mnt/incus-data/containarium-recovery.yaml --dry-run

  # Skip SSH account sync
  containarium recover --config /mnt/incus-data/containarium-recovery.yaml --skip-accounts`,
	RunE: runRecover,
}

func init() {
	rootCmd.AddCommand(recoverCmd)

	recoverCmd.Flags().StringVar(&recoverConfigFile, "config", "", "Path to recovery config file (default: "+DefaultRecoveryConfigPath+")")
	recoverCmd.Flags().StringVar(&recoverNetworkName, "network-name", "incusbr0", "Name of the network bridge to create")
	recoverCmd.Flags().StringVar(&recoverNetworkCIDR, "network-cidr", "", "Network CIDR (e.g., 10.0.3.1/24)")
	recoverCmd.Flags().StringVar(&recoverStoragePool, "storage-pool", "default", "Name of the storage pool")
	recoverCmd.Flags().StringVar(&recoverStorageDriver, "storage-driver", "zfs", "Storage driver (zfs, btrfs, dir, lvm)")
	recoverCmd.Flags().StringVar(&recoverZFSSource, "zfs-source", "", "ZFS dataset source (e.g., incus-pool/containers)")
	recoverCmd.Flags().BoolVar(&recoverDryRun, "dry-run", false, "Show what would be done without making changes")
	recoverCmd.Flags().BoolVar(&recoverSkipAccounts, "skip-accounts", false, "Skip SSH account sync")
	recoverCmd.Flags().BoolVar(&recoverStartAll, "start-all", true, "Start all containers after recovery")
}

func runRecover(cmd *cobra.Command, args []string) error {
	fmt.Println("==============================================")
	fmt.Println("  Containarium Disaster Recovery")
	fmt.Println("==============================================")
	fmt.Println()

	// Load configuration
	config, err := loadRecoveryConfig()
	if err != nil {
		return fmt.Errorf("failed to load recovery config: %w", err)
	}

	if recoverDryRun {
		fmt.Println("[DRY RUN MODE - No changes will be made]")
		fmt.Println()
	}

	// Print configuration
	fmt.Println("Recovery Configuration:")
	fmt.Printf("  Network:      %s (%s)\n", config.NetworkName, config.NetworkCIDR)
	fmt.Printf("  Storage Pool: %s (driver: %s)\n", config.StoragePoolName, config.StorageDriver)
	fmt.Printf("  ZFS Source:   %s\n", config.ZFSSource)
	fmt.Println()

	// Step 1: Create network
	if err := recoverNetwork(config); err != nil {
		return fmt.Errorf("network recovery failed: %w", err)
	}

	// Step 2: Recover storage pool and containers
	if err := recoverStorage(config); err != nil {
		return fmt.Errorf("storage recovery failed: %w", err)
	}

	// Step 3: Add network device to default profile
	if err := recoverDefaultProfile(config); err != nil {
		return fmt.Errorf("profile recovery failed: %w", err)
	}

	// Step 4: Start all containers
	if recoverStartAll {
		if err := startAllContainers(); err != nil {
			return fmt.Errorf("failed to start containers: %w", err)
		}
	}

	// Step 5: Sync SSH accounts
	if !recoverSkipAccounts {
		if err := syncSSHAccounts(); err != nil {
			// Don't fail completely if account sync fails
			fmt.Printf("Warning: SSH account sync had issues: %v\n", err)
		}
	}

	fmt.Println()
	fmt.Println("==============================================")
	fmt.Println("  Recovery Complete!")
	fmt.Println("==============================================")
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  1. Restart containarium daemon: sudo systemctl restart containarium")
	fmt.Println("  2. Reload Caddy if needed")
	fmt.Println("  3. Verify SSH jump access works")
	fmt.Println()

	return nil
}

func loadRecoveryConfig() (*RecoveryConfig, error) {
	config := &RecoveryConfig{
		NetworkName:     recoverNetworkName,
		NetworkCIDR:     recoverNetworkCIDR,
		StoragePoolName: recoverStoragePool,
		StorageDriver:   recoverStorageDriver,
		ZFSSource:       recoverZFSSource,
	}

	// If config file is specified or exists at default path, load it
	configPath := recoverConfigFile
	if configPath == "" {
		// Check if default config exists
		if _, err := os.Stat(DefaultRecoveryConfigPath); err == nil {
			configPath = DefaultRecoveryConfigPath
		}
	}

	if configPath != "" {
		fmt.Printf("Loading config from: %s\n", configPath)
		data, err := os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}

		if err := yaml.Unmarshal(data, config); err != nil {
			return nil, fmt.Errorf("failed to parse config file: %w", err)
		}
	}

	// Command-line flags override config file
	if recoverNetworkCIDR != "" {
		config.NetworkCIDR = recoverNetworkCIDR
	}
	if recoverZFSSource != "" {
		config.ZFSSource = recoverZFSSource
	}

	// Validate required fields
	if config.NetworkCIDR == "" {
		return nil, fmt.Errorf("network CIDR is required (--network-cidr or in config file)")
	}
	if config.ZFSSource == "" {
		return nil, fmt.Errorf("ZFS source is required (--zfs-source or in config file)")
	}

	return config, nil
}

func recoverNetwork(config *RecoveryConfig) error {
	fmt.Printf("Step 1: Creating network %s...\n", config.NetworkName)

	// Check if network already exists
	checkCmd := exec.Command("incus", "network", "show", config.NetworkName)
	if err := checkCmd.Run(); err == nil {
		fmt.Printf("  Network %s already exists, skipping\n", config.NetworkName)
		return nil
	}

	if recoverDryRun {
		fmt.Printf("  [DRY RUN] Would create network %s with CIDR %s\n", config.NetworkName, config.NetworkCIDR)
		return nil
	}

	// Create the network
	createCmd := exec.Command("incus", "network", "create", config.NetworkName,
		fmt.Sprintf("ipv4.address=%s", config.NetworkCIDR),
		"ipv4.nat=true",
		"ipv6.address=none",
	)
	output, err := createCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to create network: %w\nOutput: %s", err, string(output))
	}

	fmt.Printf("  ✓ Network %s created with CIDR %s\n", config.NetworkName, config.NetworkCIDR)
	return nil
}

func recoverStorage(config *RecoveryConfig) error {
	fmt.Printf("Step 2: Recovering storage pool %s...\n", config.StoragePoolName)

	// Check if storage pool already exists
	checkCmd := exec.Command("incus", "storage", "show", config.StoragePoolName)
	if err := checkCmd.Run(); err == nil {
		fmt.Printf("  Storage pool %s already exists, skipping\n", config.StoragePoolName)
		return nil
	}

	if recoverDryRun {
		fmt.Printf("  [DRY RUN] Would recover storage pool %s from %s\n", config.StoragePoolName, config.ZFSSource)
		return nil
	}

	// Run incus admin recover interactively
	fmt.Println("  Running incus admin recover...")
	fmt.Println("  (This may take a moment)")

	// Create the input for incus admin recover
	input := fmt.Sprintf("yes\n%s\n%s\n%s\n\nno\nyes\nyes\n",
		config.StoragePoolName,
		config.StorageDriver,
		config.ZFSSource,
	)

	recoverCmd := exec.Command("incus", "admin", "recover")
	recoverCmd.Stdin = strings.NewReader(input)
	output, err := recoverCmd.CombinedOutput()
	if err != nil {
		// Check if error is because containers were recovered successfully
		if strings.Contains(string(output), "Starting recovery") {
			fmt.Printf("  ✓ Storage pool and containers recovered\n")
			return nil
		}
		return fmt.Errorf("failed to recover storage: %w\nOutput: %s", err, string(output))
	}

	fmt.Printf("  ✓ Storage pool %s recovered from %s\n", config.StoragePoolName, config.ZFSSource)
	return nil
}

func recoverDefaultProfile(config *RecoveryConfig) error {
	fmt.Println("Step 3: Configuring default profile...")

	// Check if eth0 device already exists in default profile
	showCmd := exec.Command("incus", "profile", "show", "default")
	output, err := showCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to show default profile: %w", err)
	}

	if strings.Contains(string(output), "eth0:") {
		fmt.Println("  Default profile already has eth0 device, skipping")
		return nil
	}

	if recoverDryRun {
		fmt.Printf("  [DRY RUN] Would add eth0 device to default profile (network: %s)\n", config.NetworkName)
		return nil
	}

	// Add eth0 device to default profile
	addCmd := exec.Command("incus", "profile", "device", "add", "default", "eth0", "nic",
		fmt.Sprintf("network=%s", config.NetworkName),
		"name=eth0",
	)
	output, err = addCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add eth0 to default profile: %w\nOutput: %s", err, string(output))
	}

	fmt.Printf("  ✓ Added eth0 device to default profile (network: %s)\n", config.NetworkName)
	return nil
}

func startAllContainers() error {
	fmt.Println("Step 4: Starting all containers...")

	if recoverDryRun {
		fmt.Println("  [DRY RUN] Would start all containers")
		return nil
	}

	// Start all containers
	startCmd := exec.Command("incus", "start", "--all")
	output, err := startCmd.CombinedOutput()
	if err != nil {
		// Some containers might fail to start, continue anyway
		fmt.Printf("  Warning: Some containers may have failed to start: %s\n", string(output))
	}

	// Wait for containers to get IPs
	fmt.Println("  Waiting for containers to start and get IPs...")
	time.Sleep(5 * time.Second)

	// List containers to show status
	listCmd := exec.Command("incus", "list", "--format", "compact")
	output, _ = listCmd.Output()
	fmt.Println()
	fmt.Println(string(output))

	fmt.Println("  ✓ Containers started")
	return nil
}

func syncSSHAccounts() error {
	fmt.Println("Step 5: Syncing SSH accounts...")

	if recoverDryRun {
		fmt.Println("  [DRY RUN] Would sync SSH accounts from containers")
		return nil
	}

	// Use the container manager to sync accounts
	mgr, err := container.New()
	if err != nil {
		return fmt.Errorf("failed to connect to Incus: %w", err)
	}

	containers, err := mgr.List()
	if err != nil {
		return fmt.Errorf("failed to list containers: %w", err)
	}

	var restored, skipped, failed int

	for _, c := range containers {
		username := strings.TrimSuffix(c.Name, "-container")
		if username == c.Name {
			skipped++
			continue
		}

		// Check if account already exists
		if container.UserExists(username) {
			if verbose {
				fmt.Printf("  Account %s already exists, skipping\n", username)
			}
			skipped++
			continue
		}

		// Extract SSH key
		sshKey, err := container.ExtractSSHKeyFromContainer(c.Name, username, false)
		if err != nil || sshKey == "" {
			failed++
			continue
		}

		// Create account
		if err := container.CreateJumpServerAccount(username, sshKey, false); err != nil {
			failed++
			continue
		}

		fmt.Printf("  ✓ Restored account: %s\n", username)
		restored++
	}

	fmt.Printf("  Owner accounts: %d restored, %d skipped, %d failed\n", restored, skipped, failed)

	// Also sync collaborator accounts from PostgreSQL
	fmt.Println("  Syncing collaborator accounts...")
	collabStore, err := collaborator.NewStore(context.Background(), getPostgresConnString())
	if err != nil {
		fmt.Printf("  Warning: Could not connect to collaborator database: %v\n", err)
	} else {
		defer collabStore.Close()
		collaboratorMgr := container.NewCollaboratorManager(mgr, collabStore)
		cr, cs, cf := collaboratorMgr.SyncCollaboratorAccounts(verbose, false)
		fmt.Printf("  Collaborator accounts: %d restored, %d skipped, %d failed\n", cr, cs, cf)
	}

	return nil
}

// SaveRecoveryConfig saves the current recovery configuration to a file
// This should be called during daemon startup to persist config for recovery
func SaveRecoveryConfig(config *RecoveryConfig, path string) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// GenerateRecoveryConfig creates a recovery config from current system state
func GenerateRecoveryConfig() (*RecoveryConfig, error) {
	config := &RecoveryConfig{
		NetworkName:     "incusbr0",
		StoragePoolName: "default",
		StorageDriver:   "zfs",
	}

	// Try to get network CIDR
	cmd := exec.Command("incus", "network", "get", "incusbr0", "ipv4.address")
	output, err := cmd.Output()
	if err == nil {
		config.NetworkCIDR = strings.TrimSpace(string(output))
	}

	// Try to get ZFS source
	cmd = exec.Command("incus", "storage", "get", "default", "source")
	output, err = cmd.Output()
	if err == nil {
		config.ZFSSource = strings.TrimSpace(string(output))
	}

	return config, nil
}

// PromptRecoveryConfig interactively prompts for recovery configuration
func PromptRecoveryConfig() (*RecoveryConfig, error) {
	config := &RecoveryConfig{
		NetworkName:     "incusbr0",
		StoragePoolName: "default",
		StorageDriver:   "zfs",
	}

	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Network CIDR (e.g., 10.0.3.1/24): ")
	cidr, _ := reader.ReadString('\n')
	config.NetworkCIDR = strings.TrimSpace(cidr)

	fmt.Print("ZFS source dataset (e.g., incus-pool/containers): ")
	source, _ := reader.ReadString('\n')
	config.ZFSSource = strings.TrimSpace(source)

	return config, nil
}
