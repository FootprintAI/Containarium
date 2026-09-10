//go:build !containarium_client

package cmd

import (
	"fmt"

	"github.com/footprintai/containarium/pkg/core/container"
)

func getLabelsLocal(username string) (map[string]string, error) {
	mgr, err := container.New()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Incus: %w (is Incus running?)", err)
	}

	containerName := username + "-container"

	// Check if container exists
	if !mgr.ContainerExists(containerName) {
		return nil, fmt.Errorf("container %q does not exist", containerName)
	}

	// Note: Manager methods expect username (without -container suffix)
	return mgr.GetLabels(username)
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
