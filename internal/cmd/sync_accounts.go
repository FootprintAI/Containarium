package cmd

import (
	"fmt"
	"strings"

	"github.com/footprintai/containarium/internal/container"
	"github.com/spf13/cobra"
)

var (
	syncDryRun bool
	syncForce  bool
)

var syncAccountsCmd = &cobra.Command{
	Use:   "sync-accounts",
	Short: "Sync jump server accounts from persisted containers",
	Long: `Restore jump server SSH accounts by extracting public keys from containers.

This command is useful after the jump server is recreated (e.g., spot instance
termination) when the boot disk is lost but containers persist on the ZFS pool.

It works by:
1. Listing all existing Incus containers
2. Extracting the SSH public key from inside each container
3. Creating the corresponding jump server account with that SSH key

Examples:
  # Sync all jump server accounts from containers
  containarium sync-accounts

  # Dry run - show what would be done without making changes
  containarium sync-accounts --dry-run

  # Force recreation even if accounts exist
  containarium sync-accounts --force`,
	RunE: runSyncAccounts,
}

func init() {
	rootCmd.AddCommand(syncAccountsCmd)

	syncAccountsCmd.Flags().BoolVar(&syncDryRun, "dry-run", false, "Show what would be done without making changes")
	syncAccountsCmd.Flags().BoolVar(&syncForce, "force", false, "Force recreation of accounts even if they exist")
}

func runSyncAccounts(cmd *cobra.Command, args []string) error {
	if verbose {
		fmt.Println("Syncing jump server accounts from persisted containers...")
	}

	// Create container manager
	mgr, err := container.New()
	if err != nil {
		return fmt.Errorf("failed to connect to Incus: %w (is Incus running?)", err)
	}

	// List all containers
	containers, err := mgr.List()
	if err != nil {
		return fmt.Errorf("failed to list containers: %w", err)
	}

	if len(containers) == 0 {
		fmt.Println("No containers found.")
		return nil
	}

	fmt.Printf("Found %d container(s)\n\n", len(containers))

	var restored, skipped, failed int

	for _, c := range containers {
		// Extract username from container name (format: username-container)
		username := strings.TrimSuffix(c.Name, "-container")
		if username == c.Name {
			// Container name doesn't follow our naming convention
			if verbose {
				fmt.Printf("  Skipping %s: doesn't follow naming convention\n", c.Name)
			}
			skipped++
			continue
		}

		fmt.Printf("Processing: %s (container: %s)\n", username, c.Name)

		// Check if jump server account already exists
		if !syncForce && container.UserExists(username) {
			fmt.Printf("  ✓ Jump server account already exists, skipping\n")
			skipped++
			continue
		}

		// Extract SSH key from container
		sshKey, err := container.ExtractSSHKeyFromContainer(c.Name, username, verbose)
		if err != nil {
			fmt.Printf("  ⚠ Failed to extract SSH key: %v\n", err)
			failed++
			continue
		}

		if sshKey == "" {
			fmt.Printf("  ⚠ No SSH key found in container\n")
			failed++
			continue
		}

		if verbose {
			// Show truncated key for verification
			keyPreview := sshKey
			if len(keyPreview) > 60 {
				keyPreview = keyPreview[:60] + "..."
			}
			fmt.Printf("  Found SSH key: %s\n", keyPreview)
		}

		if syncDryRun {
			fmt.Printf("  [DRY RUN] Would create jump server account for %s\n", username)
			restored++
			continue
		}

		// Create jump server account
		if err := container.CreateJumpServerAccount(username, sshKey, verbose); err != nil {
			fmt.Printf("  ✗ Failed to create jump server account: %v\n", err)
			failed++
			continue
		}

		fmt.Printf("  ✓ Jump server account restored for %s\n", username)
		restored++
	}

	// Print summary
	fmt.Println()
	fmt.Println("==========================================")
	fmt.Println("Jump Server Account Sync Summary")
	fmt.Println("==========================================")
	if syncDryRun {
		fmt.Printf("Would restore: %d accounts\n", restored)
	} else {
		fmt.Printf("Restored:      %d accounts\n", restored)
	}
	fmt.Printf("Skipped:       %d accounts\n", skipped)
	fmt.Printf("Failed:        %d accounts\n", failed)
	fmt.Println("==========================================")

	if failed > 0 {
		return fmt.Errorf("%d account(s) failed to sync", failed)
	}

	return nil
}
