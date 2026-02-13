package network

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
)

// PortForwarder manages iptables port forwarding rules for Caddy
type PortForwarder struct {
	caddyIP     string
	networkCIDR string // Container network CIDR to exclude from forwarding (e.g., "10.0.3.0/24")
}

// NewPortForwarder creates a new port forwarder for the given Caddy IP
// networkCIDR is the container network to exclude from port forwarding (e.g., "10.0.3.0/24")
// If networkCIDR is empty, it will be derived from the Caddy IP (assumes /24)
func NewPortForwarder(caddyIP string) *PortForwarder {
	return NewPortForwarderWithNetwork(caddyIP, "")
}

// NewPortForwarderWithNetwork creates a new port forwarder with explicit network CIDR
func NewPortForwarderWithNetwork(caddyIP, networkCIDR string) *PortForwarder {
	// If no network CIDR provided, derive from Caddy IP (assume /24)
	if networkCIDR == "" {
		networkCIDR = deriveNetworkCIDR(caddyIP)
	}
	return &PortForwarder{
		caddyIP:     caddyIP,
		networkCIDR: networkCIDR,
	}
}

// deriveNetworkCIDR derives a /24 network CIDR from an IP address
// e.g., "10.0.3.111" -> "10.0.3.0/24"
func deriveNetworkCIDR(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ip // Return as-is if not a valid IP
	}
	return fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2])
}

// SetupPortForwarding configures iptables to forward ports 80 and 443 to Caddy
// This is required for Let's Encrypt certificate provisioning and HTTPS traffic
func (pf *PortForwarder) SetupPortForwarding() error {
	log.Printf("Setting up port forwarding to Caddy (%s)...", pf.caddyIP)
	log.Printf("  Excluding container network: %s", pf.networkCIDR)

	// Enable IP forwarding
	if err := pf.enableIPForwarding(); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %w", err)
	}

	// Check if rules already exist to avoid duplicates
	if pf.rulesExist() {
		log.Printf("  Port forwarding rules already exist, skipping")
		return nil
	}

	// Add PREROUTING rules for ports 80 and 443
	if err := pf.addPreRoutingRule(80); err != nil {
		return fmt.Errorf("failed to add port 80 forwarding: %w", err)
	}
	if err := pf.addPreRoutingRule(443); err != nil {
		return fmt.Errorf("failed to add port 443 forwarding: %w", err)
	}

	// Add MASQUERADE rule for return traffic
	if err := pf.addMasqueradeRule(); err != nil {
		return fmt.Errorf("failed to add masquerade rule: %w", err)
	}

	log.Printf("  Port forwarding configured: 80,443 -> %s", pf.caddyIP)
	return nil
}

// enableIPForwarding enables IP forwarding in the kernel
func (pf *PortForwarder) enableIPForwarding() error {
	cmd := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sysctl failed: %w, output: %s", err, string(output))
	}
	return nil
}

// rulesExist checks if port forwarding rules already exist
func (pf *PortForwarder) rulesExist() bool {
	// Check if PREROUTING rule for port 80 exists (with network CIDR exclusion)
	cmd := exec.Command("iptables", "-t", "nat", "-C", "PREROUTING",
		"-p", "tcp", "!", "-s", pf.networkCIDR, "--dport", "80",
		"-j", "DNAT", "--to-destination", fmt.Sprintf("%s:80", pf.caddyIP))
	err := cmd.Run()
	return err == nil
}

// addPreRoutingRule adds a PREROUTING DNAT rule for the specified port
// The rule excludes traffic from the container network to allow containers
// to access external HTTPS services (e.g., Docker registry, Let's Encrypt)
func (pf *PortForwarder) addPreRoutingRule(port int) error {
	cmd := exec.Command("iptables", "-t", "nat", "-A", "PREROUTING",
		"-p", "tcp", "!", "-s", pf.networkCIDR, "--dport", fmt.Sprintf("%d", port),
		"-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%d", pf.caddyIP, port))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables failed: %w, output: %s", err, string(output))
	}
	return nil
}

// addMasqueradeRule adds a POSTROUTING MASQUERADE rule for return traffic
func (pf *PortForwarder) addMasqueradeRule() error {
	// Check if rule already exists
	checkCmd := exec.Command("iptables", "-t", "nat", "-C", "POSTROUTING",
		"-d", pf.caddyIP, "-j", "MASQUERADE")
	if checkCmd.Run() == nil {
		return nil // Rule already exists
	}

	cmd := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING",
		"-d", pf.caddyIP, "-j", "MASQUERADE")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables failed: %w, output: %s", err, string(output))
	}
	return nil
}

// RemovePortForwarding removes the port forwarding rules
func (pf *PortForwarder) RemovePortForwarding() error {
	log.Printf("Removing port forwarding rules for Caddy (%s)...", pf.caddyIP)

	// Remove PREROUTING rules
	pf.removePreRoutingRule(80)
	pf.removePreRoutingRule(443)

	// Remove MASQUERADE rule
	pf.removeMasqueradeRule()

	return nil
}

// removePreRoutingRule removes a PREROUTING DNAT rule
func (pf *PortForwarder) removePreRoutingRule(port int) {
	cmd := exec.Command("iptables", "-t", "nat", "-D", "PREROUTING",
		"-p", "tcp", "!", "-s", pf.networkCIDR, "--dport", fmt.Sprintf("%d", port),
		"-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%d", pf.caddyIP, port))
	cmd.Run() // Ignore errors - rule might not exist
}

// removeMasqueradeRule removes the POSTROUTING MASQUERADE rule
func (pf *PortForwarder) removeMasqueradeRule() {
	cmd := exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING",
		"-d", pf.caddyIP, "-j", "MASQUERADE")
	cmd.Run() // Ignore errors - rule might not exist
}

// CheckIPTablesAvailable checks if iptables is available on the system
func CheckIPTablesAvailable() bool {
	cmd := exec.Command("iptables", "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(output), "iptables")
}
