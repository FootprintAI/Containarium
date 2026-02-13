package cmd

import (
	"github.com/spf13/cobra"
)

// portforwardCmd represents the portforward command
var portforwardCmd = &cobra.Command{
	Use:   "portforward",
	Short: "Manage iptables port forwarding rules for Caddy",
	Long: `Manage iptables port forwarding rules for routing external traffic to Caddy.

Port forwarding is required when Caddy runs in a container and needs to:
- Receive Let's Encrypt HTTP-01 challenges on port 80
- Handle HTTPS traffic on port 443

The daemon automatically sets up these rules when --app-hosting is enabled,
but you can use these commands for manual management.

Examples:
  # Show current port forwarding rules
  containarium portforward show

  # Setup port forwarding to Caddy
  containarium portforward setup --caddy-ip 10.0.3.111

  # Remove port forwarding rules
  containarium portforward remove --caddy-ip 10.0.3.111`,
}

func init() {
	rootCmd.AddCommand(portforwardCmd)
}
