package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/footprintai/containarium/internal/client"
	"github.com/spf13/cobra"
)

var (
	deleteUsername   string
	deleteForce      bool
	deleteRemoveData bool
)

var appDeleteCmd = &cobra.Command{
	Use:   "delete <app-name>",
	Short: "Delete an application",
	Long: `Delete a deployed application.

This will:
  - Stop and remove the Docker container
  - Remove the Docker image
  - Remove proxy configuration
  - Optionally remove source and data files

Examples:
  # Delete an app (will prompt for confirmation)
  containarium app delete myapp --server <host:port> --user alice

  # Delete without confirmation
  containarium app delete myapp --force

  # Delete and remove all data
  containarium app delete myapp --remove-data`,
	Args: cobra.ExactArgs(1),
	RunE: runAppDelete,
}

func init() {
	appCmd.AddCommand(appDeleteCmd)

	appDeleteCmd.Flags().StringVarP(&deleteUsername, "user", "u", "", "Username (required)")
	appDeleteCmd.Flags().BoolVar(&deleteForce, "force", false, "Skip confirmation prompt")
	appDeleteCmd.Flags().BoolVar(&deleteRemoveData, "remove-data", false, "Remove source and data files")
}

func runAppDelete(cmd *cobra.Command, args []string) error {
	appName := args[0]

	if serverAddr == "" {
		return fmt.Errorf("--server is required")
	}

	if deleteUsername == "" {
		return fmt.Errorf("--user is required")
	}

	// Confirm deletion unless --force is used
	if !deleteForce {
		fmt.Printf("Are you sure you want to delete application '%s'? [y/N]: ", appName)
		reader := bufio.NewReader(os.Stdin)
		response, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read input: %w", err)
		}

		response = strings.TrimSpace(strings.ToLower(response))
		if response != "y" && response != "yes" {
			fmt.Println("Deletion cancelled.")
			return nil
		}
	}

	grpcClient, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer grpcClient.Close()

	fmt.Printf("Deleting application %s...\n", appName)
	if err := grpcClient.DeleteApp(deleteUsername, appName, deleteRemoveData); err != nil {
		return fmt.Errorf("failed to delete app: %w", err)
	}

	fmt.Printf("Application %s deleted successfully.\n", appName)

	return nil
}
