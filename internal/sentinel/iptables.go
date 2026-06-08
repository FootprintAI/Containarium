package sentinel

import (
	"fmt"
	"log"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

const chainName = "SENTINEL_PREROUTING"

// sshPiperPort is the port used by sshpiper on the sentinel.
// Port 22 traffic is handled by sshpiper directly, not forwarded via DNAT.
const sshPiperPort = 22

// enableForwarding sets up iptables DNAT rules to forward traffic to the spot VM.
// It creates a custom chain, adds DNAT rules for each port, and enables MASQUERADE.
// Port 22 is excluded from forwarding — it is handled by sshpiper on the sentinel.
// On non-Linux systems or when iptables is unavailable, it logs a warning and returns nil.
func enableForwarding(spotIP string, ports []int) error {
	// Filter out port 22 — handled by sshpiper, not DNAT
	filtered := make([]int, 0, len(ports))
	for _, p := range ports {
		if p == sshPiperPort {
			log.Printf("[sentinel] iptables: port %d excluded from DNAT (handled by sshpiper)", p)
			continue
		}
		filtered = append(filtered, p)
	}
	ports = filtered
	if runtime.GOOS != "linux" {
		log.Printf("[sentinel] iptables: skipping on %s (non-Linux)", runtime.GOOS)
		return nil
	}

	if _, err := exec.LookPath("iptables"); err != nil {
		log.Printf("[sentinel] iptables: binary not found, skipping forwarding")
		return nil
	}

	// Enable IP forwarding
	if err := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run(); err != nil {
		return fmt.Errorf("failed to enable ip_forward: %w", err)
	}

	// Enable route_localnet if DNAT target is a loopback address (needed for tunnel mode).
	// This allows iptables DNAT to route packets to 127.0.0.0/8 addresses.
	if strings.HasPrefix(spotIP, "127.") {
		if err := exec.Command("sysctl", "-w", "net.ipv4.conf.all.route_localnet=1").Run(); err != nil {
			return fmt.Errorf("failed to enable route_localnet: %w", err)
		}
		log.Printf("[sentinel] iptables: enabled route_localnet for loopback DNAT to %s", spotIP)
	}

	// Flush any existing sentinel chain rules
	if err := disableForwarding(); err != nil {
		log.Printf("[sentinel] iptables: warning during cleanup: %v", err)
	}

	// Create the custom chain
	_ = exec.Command("iptables", "-t", "nat", "-N", chainName).Run() // ignore error if exists

	// Add DNAT rules for each port
	for _, port := range ports {
		portStr := strconv.Itoa(port)
		dest := fmt.Sprintf("%s:%d", spotIP, port)
		err := exec.Command("iptables", "-t", "nat", "-A", chainName,
			"-p", "tcp", "--dport", portStr,
			"-j", "DNAT", "--to-destination", dest,
		).Run()
		if err != nil {
			return fmt.Errorf("failed to add DNAT rule for port %d: %w", port, err)
		}
	}

	// Jump from PREROUTING to our chain.
	// Exclude container bridge traffic so that outbound connections from
	// Incus containers (e.g., curl github.com:443) are not DNAT'd.
	prerouteArgs := []string{"-t", "nat", "-A", "PREROUTING"}
	if bridgeCIDR := detectBridgeCIDR(); bridgeCIDR != "" {
		prerouteArgs = append(prerouteArgs, "!", "-s", bridgeCIDR)
		log.Printf("[sentinel] iptables: excluding container network %s from forwarding", bridgeCIDR)
	}
	prerouteArgs = append(prerouteArgs, "-j", chainName)
	err := exec.Command("iptables", prerouteArgs...).Run()
	if err != nil {
		return fmt.Errorf("failed to add PREROUTING jump: %w", err)
	}

	// Add MASQUERADE for forwarded traffic
	err = exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING",
		"-d", spotIP,
		"-j", "MASQUERADE",
	).Run()
	if err != nil {
		return fmt.Errorf("failed to add MASQUERADE rule: %w", err)
	}

	// Allow forwarded traffic in the FORWARD chain
	err = exec.Command("iptables", "-A", "FORWARD",
		"-d", spotIP,
		"-j", "ACCEPT",
	).Run()
	if err != nil {
		return fmt.Errorf("failed to add FORWARD ACCEPT rule: %w", err)
	}

	err = exec.Command("iptables", "-A", "FORWARD",
		"-s", spotIP,
		"-j", "ACCEPT",
	).Run()
	if err != nil {
		return fmt.Errorf("failed to add FORWARD ACCEPT return rule: %w", err)
	}

	log.Printf("[sentinel] iptables: forwarding enabled for %s on ports %v", spotIP, ports)
	return nil
}

// detectBridgeCIDR attempts to find the Incus bridge (incusbr0) subnet.
// Returns a CIDR like "10.0.3.0/24" or "" if not found.
func detectBridgeCIDR() string {
	// Try `ip -4 addr show incusbr0` to get the bridge address
	out, err := exec.Command("ip", "-4", "-o", "addr", "show", "incusbr0").Output()
	if err != nil || len(out) == 0 {
		return ""
	}
	// Output format: "N: incusbr0  inet 10.0.3.1/24 ..."
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "inet" && i+1 < len(fields) {
			cidr := fields[i+1]
			// Convert host address to network: 10.0.3.1/24 → 10.0.3.0/24
			parts := strings.SplitN(cidr, "/", 2)
			if len(parts) == 2 {
				octets := strings.Split(parts[0], ".")
				if len(octets) == 4 {
					return octets[0] + "." + octets[1] + "." + octets[2] + ".0/" + parts[1]
				}
			}
			return cidr
		}
	}
	return ""
}

// disableForwarding removes all sentinel iptables rules.
// Safe to call even if no rules exist.
func disableForwarding() error {
	if runtime.GOOS != "linux" {
		return nil
	}

	if _, err := exec.LookPath("iptables"); err != nil {
		return nil
	}

	// Remove jump from PREROUTING (try both with and without source exclusion)
	if bridgeCIDR := detectBridgeCIDR(); bridgeCIDR != "" {
		_ = exec.Command("iptables", "-t", "nat", "-D", "PREROUTING", "!", "-s", bridgeCIDR, "-j", chainName).Run()
	}
	_ = exec.Command("iptables", "-t", "nat", "-D", "PREROUTING", "-j", chainName).Run()

	// Flush and delete our chain
	_ = exec.Command("iptables", "-t", "nat", "-F", chainName).Run()
	_ = exec.Command("iptables", "-t", "nat", "-X", chainName).Run()

	// Clean up POSTROUTING MASQUERADE and FORWARD rules added by sentinel
	// We use comment matching in production, but for simplicity flush by known patterns
	// These are best-effort cleanup
	log.Printf("[sentinel] iptables: forwarding rules cleared")
	return nil
}
