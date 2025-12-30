package cmd

import (
	"fmt"

	"github.com/footprintai/containarium/internal/client"
	"github.com/footprintai/containarium/internal/container"
	"github.com/spf13/cobra"
)

var (
	forceDelete bool
)

var deleteCmd = &cobra.Command{
	Use:   "delete <username>",
	Short: "Delete a container",
	Long: `Delete a user's LXC container.

By default, the container must be stopped before deletion.
Use --force to delete a running container.

Examples:
  # Delete a stopped container
  containarium delete alice

  # Force delete a running container
  containarium delete bob --force`,
	Args:    cobra.ExactArgs(1),
	Aliases: []string{"rm", "remove"},
	RunE:    runDelete,
}

func init() {
	rootCmd.AddCommand(deleteCmd)

	deleteCmd.Flags().BoolVarP(&forceDelete, "force", "f", false, "Force delete even if container is running")
}

func runDelete(cmd *cobra.Command, args []string) error {
	username := args[0]
	containerName := username + "-container"

	if verbose {
		fmt.Printf("Deleting container: %s\n", containerName)
		if forceDelete {
			fmt.Println("Force delete enabled")
		}
	}

	// Delete container - use remote or local mode
	var err error
	if serverAddr != "" {
		// Remote mode via gRPC
		err = deleteRemote(username, forceDelete)
	} else {
		// Local mode via Incus
		err = deleteLocal(username, forceDelete)
	}

	if err != nil {
		return fmt.Errorf("failed to delete container: %w", err)
	}

	fmt.Printf("✓ Container %s deleted successfully\n", containerName)

	// Delete jump server account (only in local mode)
	// This removes the proxy-only user account from the jump server
	if serverAddr == "" {
		if verbose {
			fmt.Println("Removing jump server account...")
		}

		if err := container.DeleteJumpServerAccount(username, verbose); err != nil {
			// Don't fail the entire operation if jump server account deletion fails
			// Container is already deleted at this point
			fmt.Printf("Warning: Failed to delete jump server account for %s: %v\n", username, err)
			fmt.Println("You may need to manually remove the account with: sudo userdel -r " + username)
		} else {
			fmt.Printf("✓ Jump server account %s deleted\n", username)
		}
	}

	return nil
}

// deleteLocal deletes a container using local Incus daemon
func deleteLocal(username string, force bool) error {
	mgr, err := container.New()
	if err != nil {
		return fmt.Errorf("failed to connect to Incus: %w (is Incus running?)", err)
	}

	return mgr.Delete(username, force)
}

// deleteRemote deletes a container using remote gRPC server
func deleteRemote(username string, force bool) error {
	grpcClient, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return err
	}
	defer grpcClient.Close()

	return grpcClient.DeleteContainer(username, force)
}
