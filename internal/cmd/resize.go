package cmd

import (
	"fmt"

	"github.com/footprintai/containarium/internal/container"
	"github.com/spf13/cobra"
)

var (
	newCPU    string
	newMemory string
	newDisk   string
)

var resizeCmd = &cobra.Command{
	Use:   "resize <username>",
	Short: "Resize container resources (CPU, memory, disk)",
	Long: `Dynamically adjust container resources without downtime.

All changes take effect immediately without restarting the container.

Examples:
  # Resize CPU only
  containarium resize alice --cpu 4

  # Resize memory only
  containarium resize alice --memory 8GB

  # Resize disk only
  containarium resize alice --disk 100GB

  # Resize all at once
  containarium resize alice --cpu 4 --memory 8GB --disk 100GB

  # Remote mode
  containarium resize alice --cpu 4 --memory 8GB \
      --server 35.229.246.67:50051 \
      --certs-dir ~/.config/containarium/certs

Resource Limits:
  CPU:    Number of cores (e.g., 2, 4, 8) or range (2-4)
  Memory: Size with unit (e.g., 4GB, 8192MB, 16GiB)
  Disk:   Size with unit (e.g., 50GB, 100GB, 500GB)

Notes:
  - CPU: Always safe to increase or decrease
  - Memory: Check usage before decreasing (avoid OOM kills)
  - Disk: Can only increase (cannot shrink below usage)
  - All changes are instant with no downtime`,
	Args: cobra.ExactArgs(1),
	RunE: runResize,
}

func init() {
	resizeCmd.Flags().StringVar(&newCPU, "cpu", "", "New CPU limit (e.g., 4, 2-4, 0-3)")
	resizeCmd.Flags().StringVar(&newMemory, "memory", "", "New memory limit (e.g., 8GB, 4096MB)")
	resizeCmd.Flags().StringVar(&newDisk, "disk", "", "New disk size (e.g., 100GB, 500GB)")

	rootCmd.AddCommand(resizeCmd)
}

func runResize(cmd *cobra.Command, args []string) error {
	username := args[0]
	containerName := username + "-container"

	// Check that at least one resource flag is provided
	if newCPU == "" && newMemory == "" && newDisk == "" {
		return fmt.Errorf("at least one resource flag must be specified (--cpu, --memory, or --disk)")
	}

	if verbose {
		fmt.Printf("Resizing container: %s\n", containerName)
	}

	// Use remote client if --server is specified
	if serverAddr != "" {
		return runResizeRemote(username, containerName)
	}

	// Local mode
	return runResizeLocal(username, containerName)
}

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

func runResizeRemote(username, containerName string) error {
	// TODO: Implement remote resize via gRPC
	// For now, return not implemented error
	return fmt.Errorf("remote resize not yet implemented - please resize on the server directly:\n" +
		"  ssh admin@%s\n" +
		"  sudo containarium resize %s --cpu %s --memory %s --disk %s",
		serverAddr, username, newCPU, newMemory, newDisk)
}
