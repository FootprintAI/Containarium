package cmd

import (
	"fmt"
	"strings"

	"github.com/footprintai/containarium/internal/client"
	"github.com/footprintai/containarium/internal/container"
	"github.com/footprintai/containarium/internal/incus"
	"github.com/spf13/cobra"
)

var (
	showMetrics bool
)

var infoCmd = &cobra.Command{
	Use:   "info [username]",
	Short: "Show container or system information",
	Long: `Show detailed information about a specific container or the entire system.

If a username is provided, shows details about that user's container.
If no username is provided, shows system-wide information.

Examples:
  # Show system information
  containarium info

  # Show information for a specific container
  containarium info alice

  # Show container information with metrics
  containarium info alice --metrics`,
	Args: cobra.MaximumNArgs(1),
	RunE: runInfo,
}

func init() {
	rootCmd.AddCommand(infoCmd)

	infoCmd.Flags().BoolVarP(&showMetrics, "metrics", "m", false, "Show resource usage metrics")
}

func runInfo(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		// Show system information
		return showSystemInfo()
	}

	// Show container information
	username := args[0]
	return showContainerInfo(username)
}

func showSystemInfo() error {
	fmt.Println("=== Containarium System Information ===")
	fmt.Println()

	// Get server info and containers - use remote or local mode
	var serverInfo *incus.ServerInfo
	var containers []incus.ContainerInfo
	var err error

	if httpMode && serverAddr != "" {
		// Remote mode via HTTP 
		var httpClient *client.HTTPClient
		httpClient, err = client.NewHTTPClient(serverAddr, authToken)
		if err != nil {
			return fmt.Errorf("failed to create HTTP client: %w", err)
		}
		defer httpClient.Close()

		serverInfo, err = httpClient.GetSystemInfo()
		if err != nil {
			return fmt.Errorf("failed to get server info: %w", err)
		}

		containers, err = httpClient.ListContainers()
		if err != nil {
			return fmt.Errorf("failed to list containers: %w", err)
		}
	} else if serverAddr != "" {
		// Remote mode via gRPC 
		var grpcClient *client.GRPCClient
		grpcClient, err = client.NewGRPCClient(serverAddr, certsDir, insecure)
		if err != nil {
			return fmt.Errorf("failed to connect to remote server: %w", err)
		}
		defer grpcClient.Close()

		serverInfo, err = grpcClient.GetSystemInfo()
		if err != nil {
			return fmt.Errorf("failed to get server info: %w", err)
		}

		containers, err = grpcClient.ListContainers()
		if err != nil {
			return fmt.Errorf("failed to list containers: %w", err)
		}
	} else {
		// Local mode via Incus
		var mgr *container.Manager
		mgr, err = container.New()
		if err != nil {
			return fmt.Errorf("failed to connect to Incus: %w (is Incus running?)", err)
		}

		serverInfo, err = mgr.GetServerInfo()
		if err != nil {
			return fmt.Errorf("failed to get server info: %w", err)
		}

		containers, err = mgr.List()
		if err != nil {
			return fmt.Errorf("failed to list containers: %w", err)
		}
	}

	fmt.Println("Incus Information:")
	fmt.Printf("  Version:         %s\n", serverInfo.Version)
	fmt.Printf("  Kernel:          %s\n", serverInfo.KernelVersion)
	fmt.Println()

	// Count by state
	running := 0
	stopped := 0
	for _, c := range containers {
		if c.State == "Running" {
			running++
		} else {
			stopped++
		}
	}

	fmt.Println("Containers:")
	fmt.Printf("  Total:           %d\n", len(containers))
	fmt.Printf("  Running:         %d\n", running)
	fmt.Printf("  Stopped:         %d\n", stopped)
	fmt.Println()

	// Show container list if any exist
	if len(containers) > 0 {
		fmt.Println("Container List:")
		for _, c := range containers {
			username := strings.TrimSuffix(c.Name, "-container")
			status := c.State
			ip := c.IPAddress
			if ip == "" {
				ip = "N/A"
			}
			fmt.Printf("  %-20s  %-10s  %s\n", username, status, ip)
		}
		fmt.Println()
	}

	return nil
}

func showContainerInfo(username string) error {
	containerName := username + "-container"

	fmt.Printf("=== Container Information: %s ===\n", containerName)
	fmt.Println()

	// Get container info - use remote or local mode
	var info *incus.ContainerInfo
	var err error

	if httpMode && serverAddr != "" {
		// Remote mode via HTTP 
		var httpClient *client.HTTPClient
		httpClient, err = client.NewHTTPClient(serverAddr, authToken)
		if err != nil {
			return fmt.Errorf("failed to create HTTP client: %w", err)
		}
		defer httpClient.Close()

		info, err = httpClient.GetContainer(username)
		if err != nil {
			return fmt.Errorf("container not found: %w", err)
		}
	} else if serverAddr != "" {
		// Remote mode via gRPC 
		var grpcClient *client.GRPCClient
		grpcClient, err = client.NewGRPCClient(serverAddr, certsDir, insecure)
		if err != nil {
			return fmt.Errorf("failed to connect to remote server: %w", err)
		}
		defer grpcClient.Close()

		info, err = grpcClient.GetContainer(username)
		if err != nil {
			return fmt.Errorf("container not found: %w", err)
		}
	} else {
		// Local mode via Incus
		var mgr *container.Manager
		mgr, err = container.New()
		if err != nil {
			return fmt.Errorf("failed to connect to Incus: %w (is Incus running?)", err)
		}

		info, err = mgr.Get(username)
		if err != nil {
			return fmt.Errorf("container not found: %w", err)
		}
	}

	fmt.Println("General:")
	fmt.Printf("  Name:            %s\n", info.Name)
	fmt.Printf("  Username:        %s\n", username)
	fmt.Printf("  State:           %s\n", info.State)
	fmt.Printf("  Created:         %s\n", info.CreatedAt.Format("2006-01-02 15:04:05 MST"))
	fmt.Println()

	fmt.Println("Resources:")
	if info.CPU != "" {
		fmt.Printf("  CPU Limit:       %s cores\n", info.CPU)
	} else {
		fmt.Println("  CPU Limit:       unlimited")
	}
	if info.Memory != "" {
		fmt.Printf("  Memory Limit:    %s\n", info.Memory)
	} else {
		fmt.Println("  Memory Limit:    unlimited")
	}
	fmt.Println()

	if info.IPAddress != "" {
		fmt.Println("Network:")
		fmt.Printf("  IP Address:      %s\n", info.IPAddress)
		fmt.Println()

		fmt.Println("SSH Access:")
		fmt.Printf("  Direct:          ssh %s@%s\n", username, info.IPAddress)
		fmt.Printf("  Via ProxyJump:   ssh -J admin@<jump-server> %s@%s\n", username, info.IPAddress)
		fmt.Println()
	}

	if showMetrics {
		fmt.Println("Note: Detailed metrics are not yet implemented.")
		fmt.Printf("Use 'incus info %s' for detailed resource usage.\n", containerName)
	}

	return nil
}
