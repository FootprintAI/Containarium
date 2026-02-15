package cmd

import (
	"github.com/spf13/cobra"
)

// passthroughCmd represents the passthrough command
var passthroughCmd = &cobra.Command{
	Use:   "passthrough",
	Short: "Manage TCP/UDP passthrough routes via iptables",
	Long: `Manage TCP/UDP passthrough routes for direct port forwarding to containers.

Passthrough routes forward traffic directly to containers without TLS termination,
ideal for mTLS gRPC services or custom protocols where end-to-end encryption is needed.

Unlike proxy routes (which go through Caddy with TLS termination), passthrough routes
use iptables DNAT to forward traffic directly to the container.

Examples:
  # List current passthrough routes
  containarium passthrough list

  # Add a passthrough route for gRPC (port 50051)
  containarium passthrough add --port 50051 --target-ip 10.0.3.150 --target-port 50051

  # Add a passthrough route with different external/internal ports
  containarium passthrough add --port 9443 --target-ip 10.0.3.150 --target-port 50051 --protocol tcp

  # Remove a passthrough route
  containarium passthrough remove --port 50051`,
}

func init() {
	rootCmd.AddCommand(passthroughCmd)
}
