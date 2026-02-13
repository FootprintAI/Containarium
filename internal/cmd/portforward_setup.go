package cmd

import (
	"fmt"

	"github.com/footprintai/containarium/internal/incus"
	"github.com/footprintai/containarium/internal/network"
	"github.com/spf13/cobra"
)

var (
	portforwardCaddyIP   string
	portforwardAutoDetect bool
)

var portforwardSetupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Setup port forwarding rules for Caddy",
	Long: `Setup iptables port forwarding rules to route external traffic to Caddy.

This command will:
1. Enable IP forwarding in the kernel
2. Add PREROUTING rules to forward ports 80 and 443 to Caddy
3. Add MASQUERADE rule for return traffic

The rules exclude traffic from Caddy's own IP to allow outbound HTTPS
connections (e.g., to Let's Encrypt servers).

Examples:
  # Setup with explicit Caddy IP
  containarium portforward setup --caddy-ip 10.0.3.111

  # Setup with auto-detection (requires Incus)
  containarium portforward setup --auto`,
	RunE: runPortforwardSetup,
}

func init() {
	portforwardCmd.AddCommand(portforwardSetupCmd)
	portforwardSetupCmd.Flags().StringVar(&portforwardCaddyIP, "caddy-ip", "", "IP address of the Caddy container")
	portforwardSetupCmd.Flags().BoolVar(&portforwardAutoDetect, "auto", false, "Auto-detect Caddy container IP from Incus")
}

func runPortforwardSetup(cmd *cobra.Command, args []string) error {
	// Check if iptables is available
	if !network.CheckIPTablesAvailable() {
		return fmt.Errorf("iptables is not available on this system")
	}

	caddyIP := portforwardCaddyIP

	// Auto-detect if requested
	if portforwardAutoDetect {
		if caddyIP != "" {
			return fmt.Errorf("cannot use both --caddy-ip and --auto")
		}

		fmt.Println("Auto-detecting Caddy container IP...")
		incusClient, err := incus.New()
		if err != nil {
			return fmt.Errorf("failed to connect to Incus: %w", err)
		}

		detectedIP, err := incusClient.FindCaddyContainerIP()
		if err != nil {
			return fmt.Errorf("failed to auto-detect Caddy IP: %w", err)
		}
		caddyIP = detectedIP
		fmt.Printf("Detected Caddy at: %s\n", caddyIP)
	}

	if caddyIP == "" {
		return fmt.Errorf("--caddy-ip or --auto is required")
	}

	// Setup port forwarding
	portForwarder := network.NewPortForwarder(caddyIP)
	if err := portForwarder.SetupPortForwarding(); err != nil {
		return fmt.Errorf("failed to setup port forwarding: %w", err)
	}

	fmt.Println()
	fmt.Println("Port forwarding setup complete!")
	fmt.Printf("  Ports 80, 443 -> %s\n", caddyIP)
	fmt.Println()
	fmt.Println("Run 'containarium portforward show' to verify the rules.")

	return nil
}
