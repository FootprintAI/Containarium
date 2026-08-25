package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

var passthroughRouteListFormat string

var passthroughRouteListCmd = &cobra.Command{
	Use:   "list",
	Short: "List daemon-level TCP/UDP passthrough routes",
	Long: `List all TCP/UDP passthrough routes configured on the Containarium daemon.

Examples:
  # List all passthrough routes
  containarium passthrough-route list --server <host:port>

  # List in JSON format
  containarium passthrough-route list --format json --server <host:port>`,
	Aliases: []string{"ls"},
	RunE:    runPassthroughRouteList,
}

func init() {
	passthroughRouteCmd.AddCommand(passthroughRouteListCmd)

	passthroughRouteListCmd.Flags().StringVarP(&passthroughRouteListFormat, "format", "f", "table", "Output format: table, json")
}

func runPassthroughRouteList(cmd *cobra.Command, args []string) error {
	if serverAddr == "" {
		return fmt.Errorf("--server is required")
	}

	apiClient, err := newRouteClient()
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer func() { _ = apiClient.Close() }()

	routes, totalCount, err := apiClient.ListPassthroughRoutes()
	if err != nil {
		return fmt.Errorf("failed to list passthrough routes: %w", err)
	}

	switch passthroughRouteListFormat {
	case "table":
		printPassthroughRouteTableFormat(routes, totalCount)
	case "json":
		return printPassthroughRouteJSONFormat(routes, totalCount)
	default:
		return fmt.Errorf("unknown format: %s (use: table, json)", passthroughRouteListFormat)
	}

	return nil
}

func printPassthroughRouteTableFormat(routes []*pb.PassthroughRoute, totalCount int32) {
	fmt.Printf("%-8s %-10s %-25s %-8s %-12s\n", "EXT PORT", "PROTOCOL", "TARGET", "STATUS", "CONTAINER")
	fmt.Printf("%-8s %-10s %-25s %-8s %-12s\n",
		strings.Repeat("-", 8),
		strings.Repeat("-", 10),
		strings.Repeat("-", 25),
		strings.Repeat("-", 8),
		strings.Repeat("-", 12))

	if len(routes) == 0 {
		fmt.Println("No passthrough routes configured.")
		return
	}

	for _, route := range routes {
		status := "active"
		if !route.GetActive() {
			status = "inactive"
		}
		target := fmt.Sprintf("%s:%d", route.GetTargetIp(), route.GetTargetPort())

		fmt.Printf("%-8d %-10s %-25s %-8s %-12s\n",
			route.GetExternalPort(),
			route.GetProtocol().String(),
			truncateRoute(target, 25),
			status,
			route.GetContainerName())
	}

	fmt.Println()
	fmt.Printf("Total: %d passthrough routes\n", totalCount)
}

func printPassthroughRouteJSONFormat(routes []*pb.PassthroughRoute, totalCount int32) error {
	output := map[string]interface{}{
		"routes":      routes,
		"total_count": totalCount,
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	fmt.Println(string(data))
	return nil
}
