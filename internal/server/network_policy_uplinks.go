package server

import (
	"bufio"
	"io"
	"net"
	"os"
	"strings"
)

// The eBPF program trusts an UNMARKED frame (one no managed veth's sender hook
// stamped) only when it is the host's own or entered on a known uplink (#2618
// B5). The uplinks are the host's default-route interfaces — where traffic from
// outside the bridge arrives — plus any the operator names in
// CONTAINARIUM_NETWORK_POLICY_UPLINKS (comma-separated). Everything else
// unmarked fails closed: an instance's veth before its first reconcile, a
// namespace someone attached to the bridge by hand, or a frame whose mark a host
// rule rewrote.

// procNetRoute is the kernel's IPv4 routing table in /proc.
const procNetRoute = "/proc/net/route"

// parseDefaultRouteIfaces returns the interface names carrying a default route
// (destination 0.0.0.0) from a /proc/net/route listing, deduplicated, in order.
func parseDefaultRouteIfaces(r io.Reader) []string {
	var out []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(r)
	first := true
	for sc.Scan() {
		if first { // header line
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 2 || f[1] != "00000000" {
			continue
		}
		if !seen[f[0]] {
			seen[f[0]] = true
			out = append(out, f[0])
		}
	}
	return out
}

// uplinkIfindexes resolves the current uplink interfaces (default routes plus
// extra) to ifindexes. A name that does not exist is skipped.
func uplinkIfindexes(extra []string) map[int]bool {
	names := extra
	if f, err := os.Open(procNetRoute); err == nil {
		names = append(parseDefaultRouteIfaces(f), extra...)
		_ = f.Close()
	}
	out := make(map[int]bool, len(names))
	for _, n := range names {
		if iface, err := net.InterfaceByName(n); err == nil {
			out[iface.Index] = true
		}
	}
	return out
}
