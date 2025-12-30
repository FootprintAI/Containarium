package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/footprintai/containarium/internal/client"
	"github.com/footprintai/containarium/internal/container"
	"github.com/footprintai/containarium/internal/incus"
	"github.com/spf13/cobra"
)

var (
	outputFormat string
	filterState  string
	filterUser   string
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all containers",
	Long: `List all LXC containers with their current state, resources, and network information.

Examples:
  # List all containers
  containarium list

  # List only running containers
  containarium list --state running

  # List in JSON format
  containarium list --format json

  # List containers for a specific user
  containarium list --user alice`,
	Aliases: []string{"ls"},
	RunE:    runList,
}

func init() {
	rootCmd.AddCommand(listCmd)

	listCmd.Flags().StringVarP(&outputFormat, "format", "f", "table", "Output format: table, json, yaml")
	listCmd.Flags().StringVar(&filterState, "state", "all", "Filter by state: all, running, stopped")
	listCmd.Flags().StringVar(&filterUser, "user", "", "Filter by username")
}

func runList(cmd *cobra.Command, args []string) error {
	var containers []incus.ContainerInfo
	var err error

	// Check if using remote server
	if serverAddr != "" {
		// Use gRPC client for remote server
		containers, err = listRemote()
		if err != nil {
			return fmt.Errorf("failed to list containers from remote server: %w", err)
		}
	} else {
		// Use local Incus connection
		containers, err = listLocal()
		if err != nil {
			return fmt.Errorf("failed to list containers: %w", err)
		}
	}

	// Apply filters
	var filtered []interface{}
	runningCount := 0
	stoppedCount := 0

	for _, c := range containers {
		// Filter by user
		if filterUser != "" {
			// Extract username from container name (format: username-container)
			username := strings.TrimSuffix(c.Name, "-container")
			if username != filterUser {
				continue
			}
		}

		// Filter by state
		if filterState != "all" {
			if filterState == "running" && c.State != "Running" {
				continue
			}
			if filterState == "stopped" && c.State != "Stopped" {
				continue
			}
		}

		// Count states
		if c.State == "Running" {
			runningCount++
		} else {
			stoppedCount++
		}

		filtered = append(filtered, c)
	}

	// Output based on format
	switch outputFormat {
	case "table":
		printTableFormat(filtered, runningCount, stoppedCount)
	case "json":
		return printJSONFormat(filtered)
	case "yaml":
		printYAMLFormat(filtered)
	default:
		return fmt.Errorf("unknown format: %s (use: table, json, yaml)", outputFormat)
	}

	return nil
}

func printTableFormat(containers []interface{}, running, stopped int) {
	fmt.Printf("%-25s %-12s %-20s %-15s\n", "CONTAINER NAME", "STATUS", "IP ADDRESS", "CPU/MEMORY")
	fmt.Printf("%-25s %-12s %-20s %-15s\n", strings.Repeat("-", 25), strings.Repeat("-", 12), strings.Repeat("-", 20), strings.Repeat("-", 15))

	if len(containers) == 0 {
		fmt.Println("No containers found.")
		return
	}

	for _, item := range containers {
		c := item.(incus.ContainerInfo)
		ip := c.IPAddress
		if ip == "" {
			ip = "-"
		}

		resources := fmt.Sprintf("%sc/%s", c.CPU, c.Memory)
		if c.CPU == "" && c.Memory == "" {
			resources = "-"
		}

		fmt.Printf("%-25s %-12s %-20s %-15s\n", c.Name, c.State, ip, resources)
	}

	fmt.Println()
	fmt.Printf("Total: %d containers (%d running, %d stopped)\n", len(containers), running, stopped)
}

func printJSONFormat(containers []interface{}) error {
	output := map[string]interface{}{
		"containers":  containers,
		"total_count": len(containers),
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	fmt.Println(string(data))
	return nil
}

func printYAMLFormat(containers []interface{}) {
	fmt.Println("containers:")
	for _, item := range containers {
		c := item.(incus.ContainerInfo)
		fmt.Printf("  - name: %s\n", c.Name)
		fmt.Printf("    state: %s\n", c.State)
		fmt.Printf("    ip_address: %s\n", c.IPAddress)
		if c.CPU != "" {
			fmt.Printf("    cpu: %s\n", c.CPU)
		}
		if c.Memory != "" {
			fmt.Printf("    memory: %s\n", c.Memory)
		}
	}
	fmt.Printf("total_count: %d\n", len(containers))
}

// listLocal lists containers from local Incus daemon
func listLocal() ([]incus.ContainerInfo, error) {
	mgr, err := container.New()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Incus: %w (is Incus running?)", err)
	}

	return mgr.List()
}

// listRemote lists containers from remote gRPC server
func listRemote() ([]incus.ContainerInfo, error) {
	grpcClient, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return nil, err
	}
	defer grpcClient.Close()

	return grpcClient.ListContainers()
}
