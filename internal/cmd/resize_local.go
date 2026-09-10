//go:build !containarium_client

package cmd

import (
	"fmt"

	"github.com/footprintai/containarium/pkg/core/container"
)

func runResizeLocal(username, containerName string) error {
	// Create container manager
	mgr, err := container.New()
	if err != nil {
		return fmt.Errorf("failed to connect to Incus: %w", err)
	}

	// Resize resources
	if err := mgr.Resize(containerName, newCPU, newMemory, newDisk, verbose); err != nil {
		return fmt.Errorf("failed to resize container: %w", err)
	}

	fmt.Printf("\n✓ Container %s resized successfully!\n", containerName)

	// Show updated configuration
	if verbose {
		fmt.Println("\nUpdated configuration:")
		info, err := mgr.GetInfo(containerName)
		if err == nil {
			if newCPU != "" {
				fmt.Printf("  CPU:    %s\n", info.CPU)
			}
			if newMemory != "" {
				fmt.Printf("  Memory: %s\n", info.Memory)
			}
			if newDisk != "" {
				fmt.Printf("  Disk:   %s\n", newDisk)
			}
		}
	}

	return nil
}
