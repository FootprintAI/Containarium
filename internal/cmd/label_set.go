package cmd

import (
	"fmt"
	"strings"

	"github.com/footprintai/containarium/internal/client"
	"github.com/footprintai/containarium/internal/container"
	"github.com/spf13/cobra"
)

var labelOverwrite bool

var labelSetCmd = &cobra.Command{
	Use:   "set <username> <key=value> [key=value...]",
	Short: "Set labels on a container",
	Long: `Set one or more labels on a container.

Labels are specified as key=value pairs. Multiple labels can be set at once.
By default, existing labels with the same key will be overwritten.

Examples:
  # Set a single label
  containarium label set alice team=backend

  # Set multiple labels at once
  containarium label set alice team=backend project=api env=production

  # Overwrite existing labels
  containarium label set alice team=frontend`,
	Args: cobra.MinimumNArgs(2),
	RunE: runLabelSet,
}

func init() {
	labelCmd.AddCommand(labelSetCmd)
	labelSetCmd.Flags().BoolVar(&labelOverwrite, "overwrite", true, "Overwrite existing labels with the same key")
}

func runLabelSet(cmd *cobra.Command, args []string) error {
	username := args[0]
	labelArgs := args[1:]

	// Parse labels from key=value format
	labels := make(map[string]string)
	for _, arg := range labelArgs {
		parts := strings.SplitN(arg, "=", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid label format: %q (expected key=value)", arg)
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key == "" {
			return fmt.Errorf("empty label key in: %q", arg)
		}
		labels[key] = value
	}

	if len(labels) == 0 {
		return fmt.Errorf("no valid labels provided")
	}

	// Set labels - use remote or local mode
	if httpMode && serverAddr != "" {
		return setLabelsRemoteHTTP(username, labels)
	} else if serverAddr != "" {
		return fmt.Errorf("label operations not yet supported via gRPC - use --http mode")
	}

	return setLabelsLocal(username, labels)
}

func setLabelsLocal(username string, labels map[string]string) error {
	mgr, err := container.New()
	if err != nil {
		return fmt.Errorf("failed to connect to Incus: %w (is Incus running?)", err)
	}

	containerName := username + "-container"

	// Check if container exists
	if !mgr.ContainerExists(containerName) {
		return fmt.Errorf("container %q does not exist", containerName)
	}

	// Get current labels if not overwriting
	// Note: Manager methods expect username (without -container suffix)
	if !labelOverwrite {
		currentLabels, err := mgr.GetLabels(username)
		if err != nil {
			return fmt.Errorf("failed to get current labels: %w", err)
		}
		// Only set labels that don't already exist
		for key, value := range labels {
			if _, exists := currentLabels[key]; !exists {
				if err := mgr.AddLabel(username, key, value); err != nil {
					return fmt.Errorf("failed to add label %s=%s: %w", key, value, err)
				}
				fmt.Printf("Added label: %s=%s\n", key, value)
			} else {
				fmt.Printf("Skipped existing label: %s (use --overwrite to update)\n", key)
			}
		}
		return nil
	}

	// Set all labels (overwriting existing ones)
	for key, value := range labels {
		if err := mgr.AddLabel(username, key, value); err != nil {
			return fmt.Errorf("failed to set label %s=%s: %w", key, value, err)
		}
		fmt.Printf("Set label: %s=%s\n", key, value)
	}

	fmt.Printf("\nLabels set on container %s\n", containerName)
	return nil
}

func setLabelsRemoteHTTP(username string, labels map[string]string) error {
	httpClient, err := client.NewHTTPClient(serverAddr, authToken)
	if err != nil {
		return fmt.Errorf("failed to create HTTP client: %w", err)
	}
	defer httpClient.Close()

	// Get container first to verify it exists
	_, err = httpClient.GetContainer(username)
	if err != nil {
		return fmt.Errorf("container %q not found: %w", username, err)
	}

	// Set labels via HTTP API
	if err := httpClient.SetLabels(username, labels); err != nil {
		return fmt.Errorf("failed to set labels: %w", err)
	}

	for key, value := range labels {
		fmt.Printf("Set label: %s=%s\n", key, value)
	}

	fmt.Printf("\nLabels set on container %s-container\n", username)
	return nil
}
