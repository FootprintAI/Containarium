package cmd

import (
	"fmt"

	"github.com/footprintai/containarium/internal/network"
	"github.com/spf13/cobra"
)

var (
	passthroughRemovePort        int
	passthroughRemoveProtocol    string
	passthroughRemoveNetworkCIDR string
)

var passthroughRemoveCmd = &cobra.Command{
	Use:   "remove",
	Short: "Remove a passthrough route",
	Long: `Remove a TCP/UDP passthrough route from iptables.

Examples:
  # Remove TCP passthrough on port 50051
  containarium passthrough remove --port 50051

  # Remove UDP passthrough on port 53
  containarium passthrough remove --port 53 --protocol udp`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runPassthroughRemove()
	},
}

func init() {
	passthroughRemoveCmd.Flags().IntVar(&passthroughRemovePort, "port", 0, "External port to remove (required)")
	passthroughRemoveCmd.Flags().StringVar(&passthroughRemoveProtocol, "protocol", "tcp", "Protocol: tcp or udp")
	passthroughRemoveCmd.Flags().StringVar(&passthroughRemoveNetworkCIDR, "network-cidr", "10.0.3.0/24", "Container network CIDR")

	passthroughRemoveCmd.MarkFlagRequired("port")

	passthroughCmd.AddCommand(passthroughRemoveCmd)
}

func runPassthroughRemove() error {
	// Validate inputs
	if passthroughRemovePort <= 0 || passthroughRemovePort > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	if passthroughRemoveProtocol != "tcp" && passthroughRemoveProtocol != "udp" {
		return fmt.Errorf("protocol must be 'tcp' or 'udp'")
	}

	// Check if iptables is available
	if !network.CheckIPTablesAvailable() {
		return fmt.Errorf("iptables not available on this system")
	}

	// Create passthrough manager
	pm := network.NewPassthroughManager(passthroughRemoveNetworkCIDR)

	// Remove the route
	if err := pm.RemoveRoute(passthroughRemovePort, passthroughRemoveProtocol); err != nil {
		return fmt.Errorf("failed to remove passthrough route: %w", err)
	}

	fmt.Printf("✓ Passthrough route removed: %s:%d\n", passthroughRemoveProtocol, passthroughRemovePort)

	return nil
}
