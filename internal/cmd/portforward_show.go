package cmd

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
)

var portforwardShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current port forwarding rules",
	Long: `Display the current iptables NAT rules for port forwarding.

Shows PREROUTING rules (inbound traffic forwarding) and POSTROUTING rules
(return traffic masquerading).

Examples:
  containarium portforward show`,
	RunE: runPortforwardShow,
}

func init() {
	portforwardCmd.AddCommand(portforwardShowCmd)
}

func runPortforwardShow(cmd *cobra.Command, args []string) error {
	fmt.Println("=== Port Forwarding Rules ===")
	fmt.Println()

	// Check if iptables is available
	if !checkIptablesAvailable() {
		return fmt.Errorf("iptables is not available on this system")
	}

	// Show PREROUTING rules
	fmt.Println("PREROUTING (inbound traffic forwarding):")
	fmt.Println("-----------------------------------------")
	preroutingOutput, err := exec.Command("iptables", "-t", "nat", "-L", "PREROUTING", "-n", "-v", "--line-numbers").CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to get PREROUTING rules: %w", err)
	}
	fmt.Println(string(preroutingOutput))

	// Show POSTROUTING rules
	fmt.Println("POSTROUTING (return traffic masquerading):")
	fmt.Println("-------------------------------------------")
	postroutingOutput, err := exec.Command("iptables", "-t", "nat", "-L", "POSTROUTING", "-n", "-v", "--line-numbers").CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to get POSTROUTING rules: %w", err)
	}
	fmt.Println(string(postroutingOutput))

	// Check IP forwarding status
	fmt.Println("IP Forwarding Status:")
	fmt.Println("---------------------")
	ipForwardOutput, err := exec.Command("sysctl", "net.ipv4.ip_forward").CombinedOutput()
	if err != nil {
		fmt.Println("Unable to check IP forwarding status")
	} else {
		status := strings.TrimSpace(string(ipForwardOutput))
		if strings.Contains(status, "= 1") {
			fmt.Println("IP forwarding: ENABLED")
		} else {
			fmt.Println("IP forwarding: DISABLED")
		}
	}

	return nil
}

func checkIptablesAvailable() bool {
	cmd := exec.Command("iptables", "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(output), "iptables")
}
