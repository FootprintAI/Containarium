package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var routeDeleteCmd = &cobra.Command{
	Use:   "delete <domain>",
	Short: "Delete a proxy route",
	Long: `Delete a proxy route by domain name.

Examples:
  # Delete a route
  containarium route delete test.example.com --server <host:port>`,
	Aliases: []string{"rm", "remove"},
	Args:    cobra.ExactArgs(1),
	RunE:    runRouteDelete,
}

func init() {
	routeCmd.AddCommand(routeDeleteCmd)
}

func runRouteDelete(cmd *cobra.Command, args []string) error {
	domain := args[0]

	if serverAddr == "" {
		return fmt.Errorf("--server is required")
	}

	apiClient, err := newRouteClient()
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer func() { _ = apiClient.Close() }()

	if err := apiClient.DeleteRoute(domain); err != nil {
		return fmt.Errorf("failed to delete route: %w", err)
	}

	fmt.Printf("Route deleted: %s\n", domain)

	return nil
}
