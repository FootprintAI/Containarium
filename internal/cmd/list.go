package cmd

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/footprintai/containarium/internal/client"
	"github.com/footprintai/containarium/internal/container"
	"github.com/footprintai/containarium/internal/incus"
	"github.com/spf13/cobra"
)

var (
	outputFormat  string
	filterState   string
	filterUser    string
	filterLabels  []string
	showLabels    bool
	groupByLabel  string
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
  containarium list --user alice

  # Filter by labels
  containarium list --label team=dev --label project=web

  # Show labels in table output
  containarium list --show-labels

  # Group containers by a label
  containarium list --group-by team

  # Group by label and show all labels
  containarium list --group-by env --show-labels`,
	Aliases: []string{"ls"},
	RunE:    runList,
}

func init() {
	rootCmd.AddCommand(listCmd)

	listCmd.Flags().StringVarP(&outputFormat, "format", "f", "table", "Output format: table, json, yaml")
	listCmd.Flags().StringVar(&filterState, "state", "all", "Filter by state: all, running, stopped")
	listCmd.Flags().StringVar(&filterUser, "user", "", "Filter by username")
	listCmd.Flags().StringSliceVarP(&filterLabels, "label", "l", []string{}, "Filter by label (key=value format, can be specified multiple times)")
	listCmd.Flags().BoolVar(&showLabels, "show-labels", false, "Show labels in table output")
	listCmd.Flags().StringVarP(&groupByLabel, "group-by", "g", "", "Group containers by a label key (e.g., --group-by team)")
}

func runList(cmd *cobra.Command, args []string) error {
	var containers []incus.ContainerInfo
	var err error

	// Check if using remote server
	if httpMode && serverAddr != "" {
		// Use HTTP client for remote server 
		containers, err = listRemoteHTTP()
		if err != nil {
			return fmt.Errorf("failed to list containers from HTTP API: %w", err)
		}
	} else if serverAddr != "" {
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

	// Parse label filters
	labelFilter := parseLabelFilter(filterLabels)

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

		// Filter by labels
		if len(labelFilter) > 0 {
			if !incus.MatchLabels(c.Labels, labelFilter) {
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
		if groupByLabel != "" {
			printGroupedTableFormat(filtered, groupByLabel, showLabels)
		} else {
			printTableFormat(filtered, runningCount, stoppedCount, showLabels)
		}
	case "json":
		if groupByLabel != "" {
			return printGroupedJSONFormat(filtered, groupByLabel)
		}
		return printJSONFormat(filtered)
	case "yaml":
		if groupByLabel != "" {
			printGroupedYAMLFormat(filtered, groupByLabel)
		} else {
			printYAMLFormat(filtered)
		}
	default:
		return fmt.Errorf("unknown format: %s (use: table, json, yaml)", outputFormat)
	}

	return nil
}

func printTableFormat(containers []interface{}, running, stopped int, withLabels bool) {
	if withLabels {
		fmt.Printf("%-25s %-12s %-20s %-15s %s\n", "CONTAINER NAME", "STATUS", "IP ADDRESS", "CPU/MEMORY", "LABELS")
		fmt.Printf("%-25s %-12s %-20s %-15s %s\n", strings.Repeat("-", 25), strings.Repeat("-", 12), strings.Repeat("-", 20), strings.Repeat("-", 15), strings.Repeat("-", 30))
	} else {
		fmt.Printf("%-25s %-12s %-20s %-15s\n", "CONTAINER NAME", "STATUS", "IP ADDRESS", "CPU/MEMORY")
		fmt.Printf("%-25s %-12s %-20s %-15s\n", strings.Repeat("-", 25), strings.Repeat("-", 12), strings.Repeat("-", 20), strings.Repeat("-", 15))
	}

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

		if withLabels {
			labelStr := formatLabels(c.Labels)
			fmt.Printf("%-25s %-12s %-20s %-15s %s\n", c.Name, c.State, ip, resources, labelStr)
		} else {
			fmt.Printf("%-25s %-12s %-20s %-15s\n", c.Name, c.State, ip, resources)
		}
	}

	fmt.Println()
	fmt.Printf("Total: %d containers (%d running, %d stopped)\n", len(containers), running, stopped)
}

// formatLabels formats labels as a comma-separated string
func formatLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return "-"
	}
	var parts []string
	for k, v := range labels {
		parts = append(parts, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(parts, ",")
}

// parseLabelFilter parses label filter from key=value format
func parseLabelFilter(labelSlice []string) map[string]string {
	result := make(map[string]string)
	for _, label := range labelSlice {
		parts := strings.SplitN(label, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			if key != "" {
				result[key] = value
			}
		}
	}
	return result
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
		if len(c.Labels) > 0 {
			fmt.Printf("    labels:\n")
			for k, v := range c.Labels {
				fmt.Printf("      %s: %s\n", k, v)
			}
		}
	}
	fmt.Printf("total_count: %d\n", len(containers))
}

// groupContainersByLabel groups containers by a specific label key
func groupContainersByLabel(containers []interface{}, labelKey string) map[string][]incus.ContainerInfo {
	groups := make(map[string][]incus.ContainerInfo)
	for _, item := range containers {
		c := item.(incus.ContainerInfo)
		labelValue := "(no label)"
		if c.Labels != nil {
			if val, ok := c.Labels[labelKey]; ok {
				labelValue = val
			}
		}
		groups[labelValue] = append(groups[labelValue], c)
	}
	return groups
}

// getSortedGroupKeys returns sorted group keys with "(no label)" at the end
func getSortedGroupKeys(groups map[string][]incus.ContainerInfo) []string {
	keys := make([]string, 0, len(groups))
	hasNoLabel := false
	for k := range groups {
		if k == "(no label)" {
			hasNoLabel = true
		} else {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	if hasNoLabel {
		keys = append(keys, "(no label)")
	}
	return keys
}

func printGroupedTableFormat(containers []interface{}, labelKey string, withLabels bool) {
	groups := groupContainersByLabel(containers, labelKey)
	sortedKeys := getSortedGroupKeys(groups)

	totalCount := 0
	totalRunning := 0
	totalStopped := 0

	for _, groupValue := range sortedKeys {
		groupContainers := groups[groupValue]

		// Print group header
		fmt.Printf("\n=== %s: %s (%d containers) ===\n", labelKey, groupValue, len(groupContainers))

		// Print table header
		if withLabels {
			fmt.Printf("%-25s %-12s %-20s %-15s %s\n", "CONTAINER NAME", "STATUS", "IP ADDRESS", "CPU/MEMORY", "LABELS")
			fmt.Printf("%-25s %-12s %-20s %-15s %s\n", strings.Repeat("-", 25), strings.Repeat("-", 12), strings.Repeat("-", 20), strings.Repeat("-", 15), strings.Repeat("-", 30))
		} else {
			fmt.Printf("%-25s %-12s %-20s %-15s\n", "CONTAINER NAME", "STATUS", "IP ADDRESS", "CPU/MEMORY")
			fmt.Printf("%-25s %-12s %-20s %-15s\n", strings.Repeat("-", 25), strings.Repeat("-", 12), strings.Repeat("-", 20), strings.Repeat("-", 15))
		}

		for _, c := range groupContainers {
			ip := c.IPAddress
			if ip == "" {
				ip = "-"
			}

			resources := fmt.Sprintf("%sc/%s", c.CPU, c.Memory)
			if c.CPU == "" && c.Memory == "" {
				resources = "-"
			}

			if withLabels {
				labelStr := formatLabels(c.Labels)
				fmt.Printf("%-25s %-12s %-20s %-15s %s\n", c.Name, c.State, ip, resources, labelStr)
			} else {
				fmt.Printf("%-25s %-12s %-20s %-15s\n", c.Name, c.State, ip, resources)
			}

			totalCount++
			if c.State == "Running" {
				totalRunning++
			} else {
				totalStopped++
			}
		}
	}

	fmt.Println()
	fmt.Printf("Total: %d containers in %d groups (%d running, %d stopped)\n", totalCount, len(groups), totalRunning, totalStopped)
}

func printGroupedJSONFormat(containers []interface{}, labelKey string) error {
	groups := groupContainersByLabel(containers, labelKey)

	output := map[string]interface{}{
		"group_by":    labelKey,
		"groups":      groups,
		"group_count": len(groups),
		"total_count": len(containers),
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	fmt.Println(string(data))
	return nil
}

func printGroupedYAMLFormat(containers []interface{}, labelKey string) {
	groups := groupContainersByLabel(containers, labelKey)
	sortedKeys := getSortedGroupKeys(groups)

	fmt.Printf("group_by: %s\n", labelKey)
	fmt.Println("groups:")

	for _, groupValue := range sortedKeys {
		groupContainers := groups[groupValue]
		fmt.Printf("  %s:\n", groupValue)
		for _, c := range groupContainers {
			fmt.Printf("    - name: %s\n", c.Name)
			fmt.Printf("      state: %s\n", c.State)
			fmt.Printf("      ip_address: %s\n", c.IPAddress)
			if c.CPU != "" {
				fmt.Printf("      cpu: %s\n", c.CPU)
			}
			if c.Memory != "" {
				fmt.Printf("      memory: %s\n", c.Memory)
			}
			if len(c.Labels) > 0 {
				fmt.Printf("      labels:\n")
				for k, v := range c.Labels {
					fmt.Printf("        %s: %s\n", k, v)
				}
			}
		}
	}
	fmt.Printf("group_count: %d\n", len(groups))
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

// listRemoteHTTP lists containers from remote HTTP API 
func listRemoteHTTP() ([]incus.ContainerInfo, error) {
	httpClient, err := client.NewHTTPClient(serverAddr, authToken)
	if err != nil {
		return nil, err
	}
	defer httpClient.Close()

	return httpClient.ListContainers()
}
