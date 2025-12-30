package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/footprintai/containarium/internal/container"
	"github.com/spf13/cobra"
)

var (
	exportOutputPath string
	exportKeyPath    string
	jumpServerIP     string
)

var exportCmd = &cobra.Command{
	Use:   "export <username>",
	Short: "Export SSH configuration for a user",
	Long: `Export SSH configuration snippet for accessing a user's container via ProxyJump.

The generated configuration can be added to your ~/.ssh/config file or saved to ~/.ssh/config.d/
for automatic inclusion.

Examples:
  # Export to stdout
  containarium export alice

  # Export to specific file
  containarium export alice --output ~/.ssh/config.d/containarium-alice

  # Specify SSH key path
  containarium export alice --key ~/.ssh/containarium_alice

  # Specify jump server IP
  containarium export alice --jump-ip 35.229.246.67`,
	Args: cobra.ExactArgs(1),
	RunE: runExport,
}

func init() {
	rootCmd.AddCommand(exportCmd)

	exportCmd.Flags().StringVarP(&exportOutputPath, "output", "o", "", "Output file path (default: stdout)")
	exportCmd.Flags().StringVar(&exportKeyPath, "key", "~/.ssh/id_rsa", "SSH private key path")
	exportCmd.Flags().StringVar(&jumpServerIP, "jump-ip", "", "Jump server IP address (required for export)")
	exportCmd.MarkFlagRequired("jump-ip")
}

func runExport(cmd *cobra.Command, args []string) error {
	username := args[0]

	if verbose {
		fmt.Printf("Exporting SSH configuration for user: %s\n", username)
	}

	// Get container information
	var containerIP string
	var err error

	if serverAddr != "" {
		return fmt.Errorf("export command is only available in local mode (direct Incus connection)")
	}

	// Get container info from local Incus
	mgr, err := container.New()
	if err != nil {
		return fmt.Errorf("failed to connect to Incus: %w (is Incus running?)", err)
	}

	info, err := mgr.Get(username)
	if err != nil {
		return fmt.Errorf("failed to get container info: %w\nNote: Container must exist before exporting SSH config", err)
	}

	containerIP = info.IPAddress
	if containerIP == "" {
		return fmt.Errorf("container has no IP address - is it running?")
	}

	// Generate SSH config content
	config := generateSSHConfig(username, jumpServerIP, containerIP, exportKeyPath)

	// Output to file or stdout
	if exportOutputPath != "" {
		// Expand home directory
		expandedPath := exportOutputPath
		if len(exportOutputPath) >= 2 && exportOutputPath[:2] == "~/" {
			homeDir, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("failed to get home directory: %w", err)
			}
			expandedPath = filepath.Join(homeDir, exportOutputPath[2:])
		}

		// Create parent directory if needed
		parentDir := filepath.Dir(expandedPath)
		if err := os.MkdirAll(parentDir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", parentDir, err)
		}

		// Write config to file
		if err := os.WriteFile(expandedPath, []byte(config), 0600); err != nil {
			return fmt.Errorf("failed to write config file: %w", err)
		}

		fmt.Printf("✓ SSH configuration exported to: %s\n", expandedPath)
		fmt.Println()
		fmt.Println("To use this configuration:")
		fmt.Println()
		fmt.Println("  Option 1: Include in your main SSH config")
		fmt.Printf("    echo 'Include %s' >> ~/.ssh/config\n", expandedPath)
		fmt.Println()
		fmt.Println("  Option 2: Append to your SSH config")
		fmt.Printf("    cat %s >> ~/.ssh/config\n", expandedPath)
		fmt.Println()
		fmt.Printf("Then connect with: ssh %s-dev\n", username)
	} else {
		// Output to stdout
		fmt.Println(config)
		fmt.Println()
		fmt.Println("# To use this configuration, add it to your ~/.ssh/config:")
		fmt.Println("#   containarium export " + username + " --jump-ip " + jumpServerIP + " >> ~/.ssh/config")
		fmt.Println()
		fmt.Printf("# Then connect with: ssh %s-dev\n", username)
	}

	return nil
}

func generateSSHConfig(username, jumpIP, containerIP, keyPath string) string {
	timestamp := time.Now().Format("2006-01-02 15:04:05")

	config := fmt.Sprintf(`# Containarium SSH Configuration
# User: %s
# Generated: %s

# Jump server (GCE instance with proxy-only account)
Host containarium-jump
    HostName %s
    User %s
    IdentityFile %s
    # No shell access - proxy-only account

# User's development container
Host %s-dev
    HostName %s
    User %s
    IdentityFile %s
    ProxyJump containarium-jump
    # Optional: disable strict host key checking for testing
    # StrictHostKeyChecking accept-new
`, username, timestamp, jumpIP, username, keyPath, username, containerIP, username, keyPath)

	return config
}
