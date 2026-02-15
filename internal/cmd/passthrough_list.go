package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/footprintai/containarium/internal/network"
	"github.com/spf13/cobra"
)

var passthroughListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all passthrough routes",
	Long: `List all TCP/UDP passthrough routes currently configured via iptables.

Shows the external port, target IP:port, protocol, and status for each route.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runPassthroughList()
	},
}

func init() {
	passthroughCmd.AddCommand(passthroughListCmd)
}

func runPassthroughList() error {
	// Check if iptables is available
	if !network.CheckIPTablesAvailable() {
		return fmt.Errorf("iptables not available on this system")
	}

	// Create passthrough manager (network CIDR not needed for listing)
	pm := network.NewPassthroughManager("0.0.0.0/0")

	routes, err := pm.ListRoutes()
	if err != nil {
		return fmt.Errorf("failed to list passthrough routes: %w", err)
	}

	if len(routes) == 0 {
		fmt.Println("No passthrough routes configured")
		return nil
	}

	// Print routes in a table format
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "EXT PORT\tTARGET\tPROTOCOL\tSTATUS")
	fmt.Fprintln(w, "--------\t------\t--------\t------")

	for _, route := range routes {
		status := "Inactive"
		if route.Active {
			status = "Active"
		}
		fmt.Fprintf(w, "%d\t%s:%d\t%s\t%s\n",
			route.ExternalPort,
			route.TargetIP,
			route.TargetPort,
			route.Protocol,
			status,
		)
	}
	w.Flush()

	fmt.Printf("\nTotal: %d passthrough route(s)\n", len(routes))
	return nil
}
