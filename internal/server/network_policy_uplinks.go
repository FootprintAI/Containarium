package server

import (
	"bufio"
	"io"
	"net"
	"os"
	"path/filepath"
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

// uplinkIface is one candidate uplink: a named interface and its ifindex.
type uplinkIface struct {
	Name  string
	Index int
}

// uplinkCandidates resolves the current uplink interfaces (default routes plus
// extra) to interfaces, in order and deduplicated. A name that does not exist is
// skipped.
func uplinkCandidates(extra []string) []uplinkIface {
	names := extra
	if f, err := os.Open(procNetRoute); err == nil {
		names = append(parseDefaultRouteIfaces(f), extra...)
		_ = f.Close()
	}
	var out []uplinkIface
	seen := map[int]bool{}
	for _, n := range names {
		if iface, err := net.InterfaceByName(n); err == nil && !seen[iface.Index] {
			seen[iface.Index] = true
			out = append(out, uplinkIface{Name: n, Index: iface.Index})
		}
	}
	return out
}

// sysClassNet is where the kernel exposes each interface's bridge master.
const sysClassNet = "/sys/class/net"

// masterOfIface returns the name of the bridge (or bond) iface is enslaved to,
// or "" when it has none.
func masterOfIface(iface string) string {
	target, err := os.Readlink(filepath.Join(sysClassNet, iface, "master"))
	if err != nil {
		return ""
	}
	return filepath.Base(target)
}

// refuseVethCarriers splits candidates into the ones safe to trust and the ones
// that carry managed instance veths (#3185 SF1). Trusting such an interface
// would let a frame the host routes back through the instance bridge count as
// "entered on an uplink" and seed an inbound flow without the sender-hook mark,
// reopening the unmarked-frame seed path. An interface carries managed veths
// when it is one of them or is the master a managed veth is enslaved to, whether
// it came from default-route detection or CONTAINARIUM_NETWORK_POLICY_UPLINKS.
// masterOf is injected so the decision is testable without sysfs.
func refuseVethCarriers(cands []uplinkIface, managedVeths []string, masterOf func(string) string) (trusted map[int]bool, refused []uplinkIface) {
	carriers := make(map[string]bool, len(managedVeths)*2)
	for _, v := range managedVeths {
		carriers[v] = true
		if m := masterOf(v); m != "" {
			carriers[m] = true
		}
	}
	trusted = make(map[int]bool, len(cands))
	for _, c := range cands {
		if carriers[c.Name] {
			refused = append(refused, c)
			continue
		}
		trusted[c.Index] = true
	}
	return trusted, refused
}
