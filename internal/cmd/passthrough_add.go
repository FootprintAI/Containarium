package cmd

import (
	"fmt"

	"github.com/footprintai/containarium/internal/network"
	"github.com/spf13/cobra"
)

var (
	passthroughAddPort       int
	passthroughAddTargetIP   string
	passthroughAddTargetPort int
	passthroughAddProtocol   string
	passthroughAddNetworkCIDR string
)

var passthroughAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a passthrough route",
	Long: `Add a TCP/UDP passthrough route via iptables.

Creates DNAT and MASQUERADE rules to forward traffic from an external port
directly to a container's IP and port without TLS termination.

Examples:
  # Forward port 50051 to container
  containarium passthrough add --port 50051 --target-ip 10.0.3.150 --target-port 50051

  # Forward external port 9443 to container port 50051
  containarium passthrough add --port 9443 --target-ip 10.0.3.150 --target-port 50051

  # Add UDP passthrough
  containarium passthrough add --port 53 --target-ip 10.0.3.150 --target-port 53 --protocol udp`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runPassthroughAdd()
	},
}

func init() {
	passthroughAddCmd.Flags().IntVar(&passthroughAddPort, "port", 0, "External port to expose (required)")
	passthroughAddCmd.Flags().StringVar(&passthroughAddTargetIP, "target-ip", "", "Target container IP address (required)")
	passthroughAddCmd.Flags().IntVar(&passthroughAddTargetPort, "target-port", 0, "Target port on the container (required)")
	passthroughAddCmd.Flags().StringVar(&passthroughAddProtocol, "protocol", "tcp", "Protocol: tcp or udp")
	passthroughAddCmd.Flags().StringVar(&passthroughAddNetworkCIDR, "network-cidr", "10.0.3.0/24", "Container network CIDR to exclude from forwarding")

	passthroughAddCmd.MarkFlagRequired("port")
	passthroughAddCmd.MarkFlagRequired("target-ip")
	passthroughAddCmd.MarkFlagRequired("target-port")

	passthroughCmd.AddCommand(passthroughAddCmd)
}

func runPassthroughAdd() error {
	// Validate inputs
	if passthroughAddPort <= 0 || passthroughAddPort > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	if passthroughAddTargetPort <= 0 || passthroughAddTargetPort > 65535 {
		return fmt.Errorf("target-port must be between 1 and 65535")
	}
	if passthroughAddTargetIP == "" {
		return fmt.Errorf("target-ip is required")
	}
	if passthroughAddProtocol != "tcp" && passthroughAddProtocol != "udp" {
		return fmt.Errorf("protocol must be 'tcp' or 'udp'")
	}

	// Check if iptables is available
	if !network.CheckIPTablesAvailable() {
		return fmt.Errorf("iptables not available on this system")
	}

	// Create passthrough manager
	pm := network.NewPassthroughManager(passthroughAddNetworkCIDR)

	// Add the route
	if err := pm.AddRoute(passthroughAddPort, passthroughAddTargetIP, passthroughAddTargetPort, passthroughAddProtocol); err != nil {
		return fmt.Errorf("failed to add passthrough route: %w", err)
	}

	fmt.Printf("✓ Passthrough route added: %s:%d -> %s:%d\n",
		passthroughAddProtocol, passthroughAddPort, passthroughAddTargetIP, passthroughAddTargetPort)

	return nil
}
