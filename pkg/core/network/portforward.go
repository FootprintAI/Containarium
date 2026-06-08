package network

import (
	"fmt"
	"log"
	"os"
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

// SetupPortForwarding configures iptables to forward ports 80 and 443 to Caddy.
// Required for Let's Encrypt certificate provisioning and HTTPS traffic.
//
// Three iptables paths are needed:
//
//  1. PREROUTING DNAT — for traffic arriving on a non-loopback interface
//     (the normal external case via the GLB).
//  2. OUTPUT DNAT — for locally-generated traffic to 127.0.0.0/8:443.
//     This is the path taken by tunnel-promoted primaries (slice 6/8):
//     the tunnel client receives a yamux stream and dials 127.0.0.1:port
//     to forward bytes locally. PREROUTING does not match local-origin
//     packets, so OUTPUT is needed.
//  3. POSTROUTING MASQUERADE — for return traffic.
//
// Plus one sysctl: net.ipv4.conf.all.route_localnet=1. By default the
// kernel refuses to route 127.0.0.0/8 packets out a non-loopback
// interface even after DNAT, so the tunneled-primary path silently
// drops without this. Setting it system-wide is safe — the Linux man
// page calls out that this is the right knob for "DNAT 127/8 to a
// non-local address" use case.
func (pf *PortForwarder) SetupPortForwarding() error {
	log.Printf("Setting up port forwarding to Caddy (%s)...", pf.caddyIP)
	log.Printf("  Excluding container network: %s", pf.networkCIDR)

	// Enable IP forwarding
	if err := pf.enableIPForwarding(); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %w", err)
	}

	// Allow DNAT of 127.0.0.0/8 → caddyIP (required for tunneled
	// primaries; harmless otherwise).
	if err := pf.enableRouteLocalnet(); err != nil {
		log.Printf("  Warning: failed to set route_localnet=1: %v (tunneled-primary loopback path may not work)", err)
	}

	// Clear Caddy DNAT/MASQUERADE rules that point at a *different* IP than the
	// current one. When core-caddy is recreated it comes back with a new
	// container IP; the per-rule existence checks below would then ADD rules for
	// the new IP while leaving the old ones in place. The stale rule sorts first
	// in the chain and matches, so all :443 traffic is DNAT'd to a container
	// that no longer exists and the TLS handshake returns nothing (#400).
	pf.reconcileStaleRules()

	// Each rule is added independently with its own existence check.
	// An older deploy may have PREROUTING but not OUTPUT — we want to
	// add the missing one without duplicating what's already there.
	if err := pf.ensurePreRoutingRule(80); err != nil {
		return fmt.Errorf("failed to add port 80 PREROUTING: %w", err)
	}
	if err := pf.ensurePreRoutingRule(443); err != nil {
		return fmt.Errorf("failed to add port 443 PREROUTING: %w", err)
	}
	if err := pf.ensureOutputRule(80); err != nil {
		return fmt.Errorf("failed to add port 80 OUTPUT: %w", err)
	}
	if err := pf.ensureOutputRule(443); err != nil {
		return fmt.Errorf("failed to add port 443 OUTPUT: %w", err)
	}
	if err := pf.addMasqueradeRule(); err != nil {
		return fmt.Errorf("failed to add masquerade rule: %w", err)
	}

	log.Printf("  Port forwarding configured: 80,443 -> %s (PREROUTING + OUTPUT)", pf.caddyIP)
	return nil
}

// ensurePreRoutingRule adds a PREROUTING DNAT rule if it's not already present.
func (pf *PortForwarder) ensurePreRoutingRule(port int) error {
	check := exec.Command("iptables", "-t", "nat", "-C", "PREROUTING",
		"-p", "tcp", "!", "-s", pf.networkCIDR, "--dport", fmt.Sprintf("%d", port),
		"-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%d", pf.caddyIP, port))
	if check.Run() == nil {
		return nil
	}
	return pf.addPreRoutingRule(port)
}

// ensureOutputRule adds an OUTPUT DNAT rule if it's not already present.
func (pf *PortForwarder) ensureOutputRule(port int) error {
	check := exec.Command("iptables", "-t", "nat", "-C", "OUTPUT",
		"-p", "tcp", "-d", "127.0.0.0/8", "--dport", fmt.Sprintf("%d", port),
		"-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%d", pf.caddyIP, port))
	if check.Run() == nil {
		return nil
	}
	return pf.addOutputRule(port)
}

// enableRouteLocalnet sets net.ipv4.conf.all.route_localnet=1, which is
// required to DNAT 127.0.0.0/8 traffic out a non-loopback interface.
// Persisted via /etc/sysctl.d/ so it survives reboots.
func (pf *PortForwarder) enableRouteLocalnet() error {
	cmd := exec.Command("sysctl", "-w", "net.ipv4.conf.all.route_localnet=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("sysctl failed: %w, output: %s", err, string(output))
	}
	// Best-effort persistence so the setting survives reboots.
	const path = "/etc/sysctl.d/99-containarium-route-localnet.conf"
	const body = "# containarium: required for DNAT of 127.0.0.0/8 (tunneled-primary path)\nnet.ipv4.conf.all.route_localnet = 1\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		log.Printf("  Note: could not persist sysctl to %s: %v (the runtime value is set, but it'll reset on reboot)", path, err)
	}
	return nil
}

// addOutputRule mirrors addPreRoutingRule but on the OUTPUT chain, so
// locally-generated packets to 127.0.0.0/8:port get DNAT'd to the Caddy
// container. This is the path used by tunneled-primary tunnel clients
// (slice 6) which dial 127.0.0.1:port to forward inbound bytes.
func (pf *PortForwarder) addOutputRule(port int) error {
	cmd := exec.Command("iptables", "-t", "nat", "-A", "OUTPUT",
		"-p", "tcp", "-d", "127.0.0.0/8", "--dport", fmt.Sprintf("%d", port),
		"-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%d", pf.caddyIP, port))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables OUTPUT failed: %w, output: %s", err, string(output))
	}
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

	// Remove OUTPUT rules
	pf.removeOutputRule(80)
	pf.removeOutputRule(443)

	// Remove MASQUERADE rule
	pf.removeMasqueradeRule()

	return nil
}

// removePreRoutingRule removes a PREROUTING DNAT rule
func (pf *PortForwarder) removePreRoutingRule(port int) {
	cmd := exec.Command("iptables", "-t", "nat", "-D", "PREROUTING",
		"-p", "tcp", "!", "-s", pf.networkCIDR, "--dport", fmt.Sprintf("%d", port),
		"-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%d", pf.caddyIP, port))
	if err := cmd.Run(); err != nil {
		log.Printf("  removePreRoutingRule: rule may not exist (ignored): %v", err)
	}
}

// removeOutputRule removes the OUTPUT-chain DNAT rule for tunneled-primary
// loopback traffic.
func (pf *PortForwarder) removeOutputRule(port int) {
	cmd := exec.Command("iptables", "-t", "nat", "-D", "OUTPUT",
		"-p", "tcp", "-d", "127.0.0.0/8", "--dport", fmt.Sprintf("%d", port),
		"-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%d", pf.caddyIP, port))
	if err := cmd.Run(); err != nil {
		log.Printf("  removeOutputRule: rule may not exist (ignored): %v", err)
	}
}

// removeMasqueradeRule removes the POSTROUTING MASQUERADE rule
func (pf *PortForwarder) removeMasqueradeRule() {
	cmd := exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING",
		"-d", pf.caddyIP, "-j", "MASQUERADE")
	if err := cmd.Run(); err != nil {
		log.Printf("  removeMasqueradeRule: rule may not exist (ignored): %v", err)
	}
}

// reconcileStaleRules deletes Caddy port-forward DNAT/MASQUERADE rules whose
// target IP is not pf.caddyIP. Best-effort: enumerates the nat table with
// `iptables -t nat -S`, computes the stale deletions, and runs each. Failures
// are logged, not fatal — the subsequent ensure*Rule calls still install the
// current rules. See SetupPortForwarding / issue #400.
func (pf *PortForwarder) reconcileStaleRules() {
	out, err := exec.Command("iptables", "-t", "nat", "-S").CombinedOutput()
	if err != nil {
		log.Printf("  Warning: could not enumerate nat rules to clear stale Caddy targets: %v", err)
		return
	}
	for _, args := range staleCaddyNATRules(string(out), pf.caddyIP) {
		// #nosec G204 -- args are iptables rule specs read back from this host's
		// own `iptables -t nat -S` output and re-issued verbatim as -D deletes;
		// not external/user input.
		if e := exec.Command("iptables", args...).Run(); e != nil {
			log.Printf("  Warning: failed to delete stale Caddy rule (%v): %v", args, e)
		} else {
			log.Printf("  Cleared stale Caddy port-forward rule pointing away from %s: %v", pf.caddyIP, args)
		}
	}
}

// staleCaddyNATRules scans `iptables -t nat -S` output and returns the argument
// lists (ready to pass to `iptables`, with the leading `-A` turned into `-D`)
// for Caddy port-forward rules that point at an IP other than currentIP:
//
//   - PREROUTING/OUTPUT DNAT rules whose --dport is 80 or 443 (the dport gate
//     keeps passthrough-route DNATs, which use other ports, untouched), and
//   - the POSTROUTING MASQUERADE rule of the form `-d <ip> -j MASQUERADE`
//     with no -p/--dport (passthrough MASQUERADE rules carry -p/--dport, so
//     they're left alone).
//
// Pure/string-only so it can be unit-tested without touching the host firewall.
func staleCaddyNATRules(saveOutput, currentIP string) [][]string {
	var dels [][]string
	for _, raw := range strings.Split(saveOutput, "\n") {
		line := strings.TrimSpace(raw)
		if !strings.HasPrefix(line, "-A ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		chain := fields[1]

		var toIP, dport, dstIP string
		isMasq := false
		for i, f := range fields {
			switch f {
			case "--to-destination":
				if i+1 < len(fields) {
					toIP = hostOnly(fields[i+1])
				}
			case "--dport":
				if i+1 < len(fields) {
					dport = fields[i+1]
				}
			case "-d":
				if i+1 < len(fields) {
					dstIP = stripCIDR(fields[i+1])
				}
			case "MASQUERADE":
				isMasq = true
			}
		}

		stale := false
		switch {
		case (chain == "PREROUTING" || chain == "OUTPUT") && toIP != "" && (dport == "80" || dport == "443"):
			stale = toIP != currentIP
		case chain == "POSTROUTING" && isMasq && dport == "":
			stale = dstIP != "" && dstIP != currentIP
		}
		if !stale {
			continue
		}

		// Re-issue the exact rule spec as a delete: -t nat -D <chain> <rest>.
		del := append([]string{"-t", "nat", "-D"}, fields[1:]...)
		dels = append(dels, del)
	}
	return dels
}

// stripCIDR drops a trailing /prefix from an address ("10.0.3.5/32" → "10.0.3.5").
func stripCIDR(s string) string {
	if i := strings.IndexByte(s, '/'); i >= 0 {
		return s[:i]
	}
	return s
}

// hostOnly drops a trailing :port ("10.0.3.5:443" → "10.0.3.5").
func hostOnly(s string) string {
	if i := strings.LastIndexByte(s, ':'); i >= 0 {
		return s[:i]
	}
	return s
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

// PassthroughRoute is the runtime view of a passthrough route: the minimum
// data the iptables layer needs to forward packets. It does NOT carry
// persistence metadata (ID, creator, timestamps); for the durable, DB-backed
// view see PassthroughRecord in passthrough_store.go.
//
// The sync job projects PassthroughRecord values from the Store into
// PassthroughRoute values to drive iptables.
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
			if _, err := fmt.Sscanf(port, "%d", &route.ExternalPort); err != nil {
				log.Printf("  failed to parse external port %q: %v", port, err)
			}
		}
	}

	// Parse target (to:IP:PORT)
	for _, field := range fields {
		if strings.HasPrefix(field, "to:") {
			target := strings.TrimPrefix(field, "to:")
			parts := strings.Split(target, ":")
			if len(parts) == 2 {
				route.TargetIP = parts[0]
				if _, err := fmt.Sscanf(parts[1], "%d", &route.TargetPort); err != nil {
					log.Printf("  failed to parse target port %q: %v", parts[1], err)
				}
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
	if err := cmd.Run(); err != nil {
		log.Printf("  Passthrough MASQUERADE rule may not exist or be shared (ignored): %v", err)
	}

	log.Printf("  Passthrough route removed successfully")
	return nil
}
