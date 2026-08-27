package cmd

import (
	"fmt"

	"github.com/footprintai/containarium/internal/client"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/spf13/cobra"
)

var (
	newCPU           string
	newMemory        string
	newDisk          string
	newMemoryRequest string
	newCPURequest    string
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

  # Adjust only the K8s scheduler reservation, leaving the ceiling alone
  containarium resize alice --cpu-request 1

  # Remote mode
  containarium resize alice --cpu 4 --memory 8GB \
      --server 35.229.246.67:50051 \
      --certs-dir ~/.config/containarium/certs

Resource Limits:
  CPU:    Number of cores (e.g., 2, 4, 8) or range (2-4)
  Memory: Size with unit (e.g., 4GB, 8192MB, 16GiB)
  Disk:   Size with unit (e.g., 50GB, 100GB, 500GB)

Notes:
  - CPU (LXC backend): raising --cpu always runs, but it only raises the
    box's ceiling. Whether it delivers any additional CPU depends on the
    host's CPU admission gate (off by default) — see "CPU is a ceiling,
    not automatically a floor" below before using resize as a remedy for
    a slow box. On the K8s backend the ceiling/floor split is instead
    --cpu (limit) vs --cpu-request (reservation) — see below.
  - Memory: Check usage before decreasing (avoid OOM kills)
  - Disk: Can only increase (cannot shrink below usage)
  - LXC backend: all changes are instant with no downtime
  - K8s backend: a running box is stopped and restarted (pod recreate) to
    apply the new limits; a stopped box picks them up at its next start
  - --cpu-request/--memory-request (K8s backend only): the scheduler
    reservation, separate from the ceiling. Left unspecified, the existing
    reservation is unchanged even when --cpu/--memory move the ceiling.
    Ignored on the LXC backend.

CPU is a ceiling, not automatically a floor (LXC backend):
  A box's declared CPU bounds what it may use, but on an oversubscribed
  host that says nothing about what it actually gets. "resize --cpu
  bigger" only helps if the host's CPU admission gate is enabled AND
  enforced AND its overcommit factor leaves headroom for the increase —
  otherwise the box was never CPU-starved by its own ceiling in the first
  place, and raising it changes nothing. See
  docs/CPU-CAPACITY-ADMISSION.md for how to check and configure this.
  On the K8s backend this gate does not apply; use --cpu-request instead
  for a guaranteed reservation.`,
	Args: cobra.ExactArgs(1),
	RunE: runResize,
}

func init() {
	resizeCmd.Flags().StringVar(&newCPU, "cpu", "", "New CPU limit (e.g., 4, 2-4, 0-3)")
	resizeCmd.Flags().StringVar(&newMemory, "memory", "", "New memory limit (e.g., 8GB, 4096MB)")
	resizeCmd.Flags().StringVar(&newDisk, "disk", "", "New disk size (e.g., 100GB, 500GB)")
	resizeCmd.Flags().StringVar(&newMemoryRequest, "memory-request", "", "K8s memory *request* (K8s backend only), separate from --memory which is always applied as the limit. Empty = no change to the existing request, even when --memory changes the limit. Ignored on the LXC backend.")
	resizeCmd.Flags().StringVar(&newCPURequest, "cpu-request", "", "K8s CPU *request* (K8s backend only), separate from --cpu which is always applied as the limit. Same defaulting and K8s-only scope as --memory-request. May be set alone to adjust only the reservation, without changing --cpu.")

	rootCmd.AddCommand(resizeCmd)
}

func runResize(cmd *cobra.Command, args []string) error {
	username := args[0]
	containerName := username + "-container"

	// Check that at least one resource flag is provided
	if newCPU == "" && newMemory == "" && newDisk == "" && newCPURequest == "" && newMemoryRequest == "" {
		return fmt.Errorf("at least one resource flag must be specified (--cpu, --memory, --disk, --cpu-request, or --memory-request)")
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
	var msg string
	var err error

	if httpMode {
		httpClient, herr := client.NewHTTPClient(serverAddr, authToken)
		if herr != nil {
			return herr
		}
		defer func() { _ = httpClient.Close() }()
		msg, err = httpClient.ResizeContainer(username, newCPU, newMemory, newDisk, newMemoryRequest, newCPURequest)
	} else {
		grpcClient, gerr := client.NewGRPCClient(serverAddr, certsDir, insecure)
		if gerr != nil {
			return gerr
		}
		defer func() { _ = grpcClient.Close() }()
		msg, err = grpcClient.ResizeContainer(username, newCPU, newMemory, newDisk, newMemoryRequest, newCPURequest)
	}
	if err != nil {
		return err
	}
	fmt.Printf("✓ Container %s resized\n", containerName)
	if msg != "" {
		fmt.Println(msg)
	}
	return nil
}
