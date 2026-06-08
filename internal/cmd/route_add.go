package cmd

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/footprintai/containarium/internal/client"
	"github.com/spf13/cobra"
)

var (
	routeAddTarget      string
	routeAddContainer   string
	routeAddDescription string
)

var routeAddCmd = &cobra.Command{
	Use:   "add <domain>",
	Short: "Add a proxy route",
	Long: `Add a new proxy route (domain to container mapping).

The route maps an external domain to an internal container IP:port.

Examples:
  # Add a route
  containarium route add test.example.com --target 10.0.3.136:8080 --server <host:port>

  # Add with container name and description
  containarium route add api.example.com --target 10.0.3.140:3000 \
    --container myapp-container \
    --description "API server"`,
	Args: cobra.ExactArgs(1),
	RunE: runRouteAdd,
}

func init() {
	routeCmd.AddCommand(routeAddCmd)

	routeAddCmd.Flags().StringVarP(&routeAddTarget, "target", "t", "", "Target IP:port (required)")
	routeAddCmd.Flags().StringVarP(&routeAddContainer, "container", "c", "", "Associated container name (optional)")
	routeAddCmd.Flags().StringVarP(&routeAddDescription, "description", "d", "", "Route description (optional)")

	_ = routeAddCmd.MarkFlagRequired("target")
}

func runRouteAdd(cmd *cobra.Command, args []string) error {
	domain := args[0]

	if serverAddr == "" {
		return fmt.Errorf("--server is required")
	}

	// Parse target IP:port
	parts := strings.Split(routeAddTarget, ":")
	if len(parts) != 2 {
		return fmt.Errorf("invalid target format: expected IP:port, got %s", routeAddTarget)
	}

	targetIP := parts[0]
	targetPort, err := strconv.ParseInt(parts[1], 10, 32)
	if err != nil {
		return fmt.Errorf("invalid port: %s", parts[1])
	}

	grpcClient, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer func() { _ = grpcClient.Close() }()

	route, err := grpcClient.AddRoute(domain, targetIP, int32(targetPort), routeAddContainer, routeAddDescription)
	if err != nil {
		return fmt.Errorf("failed to add route: %w", err)
	}

	fmt.Printf("Route added successfully!\n")
	fmt.Printf("  Domain:  %s\n", domain)
	fmt.Printf("  Target:  %s:%d\n", route.ContainerIp, route.Port)
	if routeAddContainer != "" {
		fmt.Printf("  Container: %s\n", routeAddContainer)
	}

	return nil
}
