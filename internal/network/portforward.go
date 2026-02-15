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

// EnableConntrackAccounting enables conntrack byte/packet accounting
// This is required for traffic monitoring to get accurate byte counters
func EnableConntrackAccounting() error {
	// Enable conntrack accounting
	cmd := exec.Command("sysctl", "-w", "net.netfilter.nf_conntrack_acct=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to enable conntrack accounting: %w, output: %s", err, string(output))
	}
	log.Printf("Conntrack accounting enabled")
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

// PassthroughRoute represents a TCP/UDP port forwarding rule
type PassthroughRoute struct {
	ExternalPort  int
	TargetIP      string
	TargetPort    int
	Protocol      string // "tcp" or "udp"
	ContainerName string
	Description   string
	Active        bool
}

// PassthroughManager manages TCP/UDP passthrough routes via iptables
type PassthroughManager struct {
	networkCIDR string // Container network CIDR (e.g., "10.0.3.0/24")
}

// NewPassthroughManager creates a new passthrough manager
func NewPassthroughManager(networkCIDR string) *PassthroughManager {
	return &PassthroughManager{
		networkCIDR: networkCIDR,
	}
}

// ListRoutes returns all passthrough routes from iptables PREROUTING chain
func (pm *PassthroughManager) ListRoutes() ([]PassthroughRoute, error) {
	var routes []PassthroughRoute

	// List NAT PREROUTING rules
	cmd := exec.Command("iptables", "-t", "nat", "-L", "PREROUTING", "-n", "--line-numbers")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to list iptables rules: %w", err)
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		route := pm.parsePassthroughRule(line)
		if route != nil {
			routes = append(routes, *route)
		}
	}

	return routes, nil
}

// parsePassthroughRule parses an iptables rule line to extract passthrough route info
// Example line: "1    DNAT       tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:50051 to:10.0.3.150:50051"
func (pm *PassthroughManager) parsePassthroughRule(line string) *PassthroughRoute {
	// Skip header lines and empty lines
	if !strings.Contains(line, "DNAT") || !strings.Contains(line, "dpt:") {
		return nil
	}

	// Skip Caddy port forwarding rules (ports 80 and 443)
	if strings.Contains(line, "dpt:80 ") || strings.Contains(line, "dpt:443 ") {
		return nil
	}

	fields := strings.Fields(line)
	if len(fields) < 7 {
		return nil
	}

	route := &PassthroughRoute{
		Active: true,
	}

	// Parse protocol
	for _, field := range fields {
		if field == "tcp" || field == "udp" {
			route.Protocol = field
			break
		}
	}

	// Parse external port (dpt:PORT)
	for _, field := range fields {
		if strings.HasPrefix(field, "dpt:") {
			port := strings.TrimPrefix(field, "dpt:")
			fmt.Sscanf(port, "%d", &route.ExternalPort)
		}
	}

	// Parse target (to:IP:PORT)
	for _, field := range fields {
		if strings.HasPrefix(field, "to:") {
			target := strings.TrimPrefix(field, "to:")
			parts := strings.Split(target, ":")
			if len(parts) == 2 {
				route.TargetIP = parts[0]
				fmt.Sscanf(parts[1], "%d", &route.TargetPort)
			}
		}
	}

	if route.ExternalPort == 0 || route.TargetIP == "" {
		return nil
	}

	return route
}

// AddRoute adds a new passthrough route via iptables
func (pm *PassthroughManager) AddRoute(externalPort int, targetIP string, targetPort int, protocol string) error {
	if protocol == "" {
		protocol = "tcp"
	}
	protocol = strings.ToLower(protocol)

	log.Printf("Adding passthrough route: %s:%d -> %s:%d", protocol, externalPort, targetIP, targetPort)

	// Check if rule already exists
	if pm.routeExists(externalPort, protocol) {
		return fmt.Errorf("passthrough route for port %d/%s already exists", externalPort, protocol)
	}

	// Enable IP forwarding
	cmd := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %w, output: %s", err, string(output))
	}

	// Add PREROUTING DNAT rule
	// Exclude traffic from container network to allow containers to use the same port externally
	cmd = exec.Command("iptables", "-t", "nat", "-A", "PREROUTING",
		"-p", protocol,
		"!", "-s", pm.networkCIDR,
		"--dport", fmt.Sprintf("%d", externalPort),
		"-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%d", targetIP, targetPort))
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to add DNAT rule: %w, output: %s", err, string(output))
	}

	// Add POSTROUTING MASQUERADE rule for return traffic
	// Check if rule already exists
	checkCmd := exec.Command("iptables", "-t", "nat", "-C", "POSTROUTING",
		"-p", protocol, "-d", targetIP, "--dport", fmt.Sprintf("%d", targetPort),
		"-j", "MASQUERADE")
	if checkCmd.Run() != nil {
		// Rule doesn't exist, add it
		cmd = exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING",
			"-p", protocol, "-d", targetIP, "--dport", fmt.Sprintf("%d", targetPort),
			"-j", "MASQUERADE")
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to add MASQUERADE rule: %w, output: %s", err, string(output))
		}
	}

	log.Printf("  Passthrough route added successfully")
	return nil
}

// routeExists checks if a passthrough route already exists
func (pm *PassthroughManager) routeExists(externalPort int, protocol string) bool {
	cmd := exec.Command("iptables", "-t", "nat", "-C", "PREROUTING",
		"-p", protocol,
		"!", "-s", pm.networkCIDR,
		"--dport", fmt.Sprintf("%d", externalPort),
		"-j", "DNAT")
	return cmd.Run() == nil
}

// RemoveRoute removes a passthrough route
func (pm *PassthroughManager) RemoveRoute(externalPort int, protocol string) error {
	if protocol == "" {
		protocol = "tcp"
	}
	protocol = strings.ToLower(protocol)

	log.Printf("Removing passthrough route: %s:%d", protocol, externalPort)

	// Get the full rule details first
	routes, err := pm.ListRoutes()
	if err != nil {
		return err
	}

	var targetIP string
	var targetPort int
	for _, route := range routes {
		if route.ExternalPort == externalPort && route.Protocol == protocol {
			targetIP = route.TargetIP
			targetPort = route.TargetPort
			break
		}
	}

	if targetIP == "" {
		return fmt.Errorf("passthrough route for port %d/%s not found", externalPort, protocol)
	}

	// Remove PREROUTING DNAT rule
	cmd := exec.Command("iptables", "-t", "nat", "-D", "PREROUTING",
		"-p", protocol,
		"!", "-s", pm.networkCIDR,
		"--dport", fmt.Sprintf("%d", externalPort),
		"-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%d", targetIP, targetPort))
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to remove DNAT rule: %w, output: %s", err, string(output))
	}

	// Remove POSTROUTING MASQUERADE rule
	cmd = exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING",
		"-p", protocol, "-d", targetIP, "--dport", fmt.Sprintf("%d", targetPort),
		"-j", "MASQUERADE")
	cmd.Run() // Ignore errors - rule might not exist or be shared

	log.Printf("  Passthrough route removed successfully")
	return nil
}
