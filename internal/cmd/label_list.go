package cmd

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/footprintai/containarium/internal/client"
	"github.com/footprintai/containarium/internal/container"
	"github.com/spf13/cobra"
)

var labelListFormat string

var labelListCmd = &cobra.Command{
	Use:   "list <username>",
	Short: "List labels for a container",
	Long: `List all labels for a specific container.

Shows all Kubernetes-style labels attached to the container.

Examples:
  # List labels for a container
  containarium label list alice

  # List labels in JSON format
  containarium label list alice --format json`,
	Aliases: []string{"ls", "get"},
	Args:    cobra.ExactArgs(1),
	RunE:    runLabelList,
}

func init() {
	labelCmd.AddCommand(labelListCmd)
	labelListCmd.Flags().StringVarP(&labelListFormat, "format", "f", "table", "Output format: table, json")
}

func runLabelList(cmd *cobra.Command, args []string) error {
	username := args[0]

	// Get labels - use remote or local mode
	var labels map[string]string
	var err error

	if httpMode && serverAddr != "" {
		labels, err = getLabelsRemoteHTTP(username)
	} else if serverAddr != "" {
		return fmt.Errorf("label operations not yet supported via gRPC - use --http mode")
	} else {
		labels, err = getLabelsLocal(username)
	}

	if err != nil {
		return err
	}

	// Output based on format
	switch labelListFormat {
	case "json":
		return printLabelsJSON(username, labels)
	case "table":
		printLabelsTable(username, labels)
	default:
		return fmt.Errorf("unknown format: %s (use: table, json)", labelListFormat)
	}

	return nil
}

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

func getLabelsRemoteHTTP(username string) (map[string]string, error) {
	httpClient, err := client.NewHTTPClient(serverAddr, authToken)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}
	defer httpClient.Close()

	info, err := httpClient.GetContainer(username)
	if err != nil {
		return nil, fmt.Errorf("container %q not found: %w", username, err)
	}

	return info.Labels, nil
}

func printLabelsTable(username string, labels map[string]string) {
	containerName := username + "-container"
	fmt.Printf("Labels for container %s:\n\n", containerName)

	if len(labels) == 0 {
		fmt.Println("  (no labels)")
		return
	}

	// Sort keys for consistent output
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Find max key length for alignment
	maxKeyLen := 0
	for _, k := range keys {
		if len(k) > maxKeyLen {
			maxKeyLen = len(k)
		}
	}

	fmt.Printf("  %-*s  %s\n", maxKeyLen, "KEY", "VALUE")
	fmt.Printf("  %s  %s\n", strings.Repeat("-", maxKeyLen), strings.Repeat("-", 30))

	for _, key := range keys {
		fmt.Printf("  %-*s  %s\n", maxKeyLen, key, labels[key])
	}

	fmt.Printf("\nTotal: %d label(s)\n", len(labels))
}

func printLabelsJSON(username string, labels map[string]string) error {
	output := map[string]interface{}{
		"container": username + "-container",
		"username":  username,
		"labels":    labels,
		"count":     len(labels),
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	fmt.Println(string(data))
	return nil
}
