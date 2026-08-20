package network

import "fmt"

// Passthrough iptables rules, as pure argument lists.
//
// They are pure so the rule *shape* is testable without root, iptables,
// or a host — the shells-out call sites are thin wrappers. #1459 shipped
// because the missing rule was only observable by running a cluster and
// trying to reach it.
//
// Two chains, because they see different traffic:
//
//   - PREROUTING catches packets arriving on an interface. It excludes
//     the container network so containers can still reach external
//     services on the same port.
//   - OUTPUT catches packets generated ON this host. DNAT in PREROUTING
//     never sees them, so without this rule a published endpoint answers
//     "connection refused" to anything running on the daemon host —
//     the e2e lane, and any operator curling the endpoint (#1459).
//     PortForwarder has always done both; the passthrough path did not.

// passthroughPreRoutingArgs builds the inbound DNAT rule.
func passthroughPreRoutingArgs(externalPort int, targetIP string, targetPort int, protocol, networkCIDR string) []string {
	return []string{
		"-t", "nat", "-A", "PREROUTING",
		"-p", protocol, "!", "-s", networkCIDR,
		"--dport", fmt.Sprintf("%d", externalPort),
		"-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%d", targetIP, targetPort),
	}
}

// passthroughOutputArgs builds the locally-generated DNAT rule.
//
// Scoped with `-m addrtype --dst-type LOCAL`: only traffic addressed to
// one of this host's own addresses is redirected. Without that scope the
// rule would capture every locally-originated connection to that port
// regardless of destination — including a connection to some other
// machine that happens to use it.
func passthroughOutputArgs(externalPort int, targetIP string, targetPort int, protocol string) []string {
	return []string{
		"-t", "nat", "-A", "OUTPUT",
		"-p", protocol, "-m", "addrtype", "--dst-type", "LOCAL",
		"--dport", fmt.Sprintf("%d", externalPort),
		"-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%d", targetIP, targetPort),
	}
}

// passthroughDeleteArgs builds the deletions for every chain a route
// installs. Leaving an OUTPUT rule behind would silently redirect a
// later, unrelated connection on that port.
func passthroughDeleteArgs(externalPort int, protocol string) [][]string {
	port := fmt.Sprintf("%d", externalPort)
	return [][]string{
		{"-t", "nat", "-D", "PREROUTING", "-p", protocol, "--dport", port},
		{"-t", "nat", "-D", "OUTPUT", "-p", protocol, "-m", "addrtype", "--dst-type", "LOCAL", "--dport", port},
	}
}
