package cmd

import (
	"fmt"

	"github.com/footprintai/containarium/internal/client"
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
	if httpMode && serverAddr != "" {
		// Remote mode via HTTP
		err = deleteRemoteHTTP(username, forceDelete)
	} else if serverAddr != "" {
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
		deleteJumpServerAccountLocal(username, verbose)
	}

	return nil
}

// deleteRemote deletes a container using remote gRPC server
func deleteRemote(username string, force bool) error {
	grpcClient, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return err
	}
	defer func() { _ = grpcClient.Close() }()

	return grpcClient.DeleteContainer(username, force)
}

// deleteRemoteHTTP deletes a container using remote HTTP API
func deleteRemoteHTTP(username string, force bool) error {
	httpClient, err := client.NewHTTPClient(serverAddr, authToken)
	if err != nil {
		return err
	}
	defer func() { _ = httpClient.Close() }()

	return httpClient.DeleteContainer(username, force)
}
