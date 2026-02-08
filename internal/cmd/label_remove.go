package cmd

import (
	"fmt"

	"github.com/footprintai/containarium/internal/client"
	"github.com/footprintai/containarium/internal/container"
	"github.com/spf13/cobra"
)

var labelRemoveCmd = &cobra.Command{
	Use:   "remove <username> <key> [key...]",
	Short: "Remove labels from a container",
	Long: `Remove one or more labels from a container.

Specify the label keys to remove. Non-existent labels are silently ignored.

Examples:
  # Remove a single label
  containarium label remove alice env

  # Remove multiple labels at once
  containarium label remove alice env project team`,
	Aliases: []string{"rm", "delete"},
	Args:    cobra.MinimumNArgs(2),
	RunE:    runLabelRemove,
}

func init() {
	labelCmd.AddCommand(labelRemoveCmd)
}

func runLabelRemove(cmd *cobra.Command, args []string) error {
	username := args[0]
	keys := args[1:]

	// Remove labels - use remote or local mode
	if httpMode && serverAddr != "" {
		return removeLabelsRemoteHTTP(username, keys)
	} else if serverAddr != "" {
		return fmt.Errorf("label operations not yet supported via gRPC - use --http mode")
	}

	return removeLabelsLocal(username, keys)
}

func removeLabelsLocal(username string, keys []string) error {
	mgr, err := container.New()
	if err != nil {
		return fmt.Errorf("failed to connect to Incus: %w (is Incus running?)", err)
	}

	containerName := username + "-container"

	// Check if container exists
	if !mgr.ContainerExists(containerName) {
		return fmt.Errorf("container %q does not exist", containerName)
	}

	// Get current labels to show which were actually removed
	// Note: Manager methods expect username (without -container suffix)
	currentLabels, err := mgr.GetLabels(username)
	if err != nil {
		return fmt.Errorf("failed to get current labels: %w", err)
	}

	removedCount := 0
	for _, key := range keys {
		if _, exists := currentLabels[key]; exists {
			if err := mgr.RemoveLabel(username, key); err != nil {
				return fmt.Errorf("failed to remove label %q: %w", key, err)
			}
			fmt.Printf("Removed label: %s\n", key)
			removedCount++
		} else {
			if verbose {
				fmt.Printf("Label not found: %s (skipped)\n", key)
			}
		}
	}

	if removedCount > 0 {
		fmt.Printf("\nRemoved %d label(s) from container %s\n", removedCount, containerName)
	} else {
		fmt.Println("No labels were removed (none matched)")
	}
	return nil
}

func removeLabelsRemoteHTTP(username string, keys []string) error {
	httpClient, err := client.NewHTTPClient(serverAddr, authToken)
	if err != nil {
		return fmt.Errorf("failed to create HTTP client: %w", err)
	}
	defer httpClient.Close()

	// Get container first to verify it exists
	info, err := httpClient.GetContainer(username)
	if err != nil {
		return fmt.Errorf("container %q not found: %w", username, err)
	}

	// Find which keys exist
	removedCount := 0
	for _, key := range keys {
		if _, exists := info.Labels[key]; exists {
			if err := httpClient.RemoveLabel(username, key); err != nil {
				return fmt.Errorf("failed to remove label %q: %w", key, err)
			}
			fmt.Printf("Removed label: %s\n", key)
			removedCount++
		} else {
			if verbose {
				fmt.Printf("Label not found: %s (skipped)\n", key)
			}
		}
	}

	if removedCount > 0 {
		fmt.Printf("\nRemoved %d label(s) from container %s-container\n", removedCount, username)
	} else {
		fmt.Println("No labels were removed (none matched)")
	}
	return nil
}
