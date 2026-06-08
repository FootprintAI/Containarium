package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/footprintai/containarium/internal/client"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

var (
	routeListFormat string
)

var routeListCmd = &cobra.Command{
	Use:   "list",
	Short: "List proxy routes",
	Long: `List all proxy routes configured in the reverse proxy.

Examples:
  # List all routes
  containarium route list --server <host:port>

  # List in JSON format
  containarium route list --format json`,
	Aliases: []string{"ls"},
	RunE:    runRouteList,
}

func init() {
	routeCmd.AddCommand(routeListCmd)

	routeListCmd.Flags().StringVarP(&routeListFormat, "format", "f", "table", "Output format: table, json")
}

func runRouteList(cmd *cobra.Command, args []string) error {
	if serverAddr == "" {
		return fmt.Errorf("--server is required")
	}

	grpcClient, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer func() { _ = grpcClient.Close() }()

	routes, totalCount, err := grpcClient.ListRoutes("", false)
	if err != nil {
		return fmt.Errorf("failed to list routes: %w", err)
	}

	// Output based on format
	switch routeListFormat {
	case "table":
		printRouteTableFormat(routes, totalCount)
	case "json":
		return printRouteJSONFormat(routes)
	default:
		return fmt.Errorf("unknown format: %s (use: table, json)", routeListFormat)
	}

	return nil
}

func printRouteTableFormat(routes []*pb.ProxyRoute, totalCount int32) {
	fmt.Printf("%-35s %-25s %-8s %-12s\n", "DOMAIN", "TARGET", "PORT", "STATUS")
	fmt.Printf("%-35s %-25s %-8s %-12s\n",
		strings.Repeat("-", 35),
		strings.Repeat("-", 25),
		strings.Repeat("-", 8),
		strings.Repeat("-", 12))

	if len(routes) == 0 {
		fmt.Println("No routes configured.")
		return
	}

	for _, route := range routes {
		status := "active"
		if !route.Active {
			status = "inactive"
		}

		domain := route.FullDomain
		if domain == "" {
			domain = route.Subdomain
		}

		fmt.Printf("%-35s %-25s %-8d %-12s\n",
			truncateRoute(domain, 35),
			truncateRoute(route.ContainerIp, 25),
			route.Port,
			status)
	}

	fmt.Println()
	fmt.Printf("Total: %d routes\n", totalCount)
}

func printRouteJSONFormat(routes []*pb.ProxyRoute) error {
	output := map[string]interface{}{
		"routes":      routes,
		"total_count": len(routes),
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	fmt.Println(string(data))
	return nil
}

func truncateRoute(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
