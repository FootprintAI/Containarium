package server

import (
	"bufio"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The box address the eBPF program validates a box's packets against (#2618)
// must come from the HOST, never from the box: Incus's instance state reports
// the addresses the guest configured on itself, which root in the box controls,
// so a box could pick the address it wants to be "validated" as. Two host-side
// sources exist, in order of preference:
//
//  1. the NIC device's `ipv4.address` — a static assignment in the instance's
//     (profile-expanded) device config, which only the host's Incus API changes;
//  2. the bridge's DHCP lease for the NIC's hardware address — written by the
//     host's dnsmasq (`<incus dir>/networks/<bridge>/dnsmasq.leases`). A box can
//     ask DHCP for an address, but dnsmasq hands out only one from the pool, never
//     one already leased to another MAC, and the box cannot edit the file.
//
// A box whose address is known from neither has box_ip 0: the program then
// cannot validate its source, so frames from it never seed an inbound flow,
// and it cannot answer inbound connections under enforce. The guest-reported
// address is deliberately NOT a fallback.

// defaultIncusLeaseDir is where Incus keeps each managed bridge's dnsmasq lease
// file, under the same data dir as its unix socket; leaseDirFor derives it from
// the client's actual data dir.
const defaultIncusLeaseDir = "/var/lib/incus/networks"

// leaseDirFor is the lease directory under an Incus data dir.
func leaseDirFor(incusDataDir string) string { return filepath.Join(incusDataDir, "networks") }

// hostNIC is what the enforcer needs to know about an instance's primary NIC
// device, read from host-side config.
type hostNIC struct {
	Network  string // the Incus network (bridge) the NIC is on; "" when unknown
	HWAddr   string // the NIC's MAC, lower-case; "" when unknown
	StaticIP netip.Addr
}

// primaryNICDevice picks the instance's primary NIC from its expanded device
// map: `eth0` when it is a nic, else the lexicographically first nic device, so
// the choice is deterministic for an instance whose NIC has another name.
// Returns the device name and config, or "" when the instance has no nic.
func primaryNICDevice(devices map[string]map[string]string) (string, map[string]string) {
	if d, ok := devices["eth0"]; ok && d["type"] == "nic" {
		return "eth0", d
	}
	var names []string
	for name, d := range devices {
		if d["type"] == "nic" {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return "", nil
	}
	sort.Strings(names)
	return names[0], devices[names[0]]
}

// hostNICFor derives the primary NIC's host-side facts from an instance's
// config (for the `volatile.<nic>.hwaddr` Incus assigns) and its expanded
// devices (for `network`/`parent` and `ipv4.address`).
func hostNICFor(config map[string]string, devices map[string]map[string]string) hostNIC {
	name, dev := primaryNICDevice(devices)
	if name == "" {
		return hostNIC{}
	}
	n := hostNIC{
		Network: dev["network"],
		HWAddr:  strings.ToLower(strings.TrimSpace(firstNonEmpty(dev["hwaddr"], config["volatile."+name+".hwaddr"]))),
	}
	if n.Network == "" {
		n.Network = dev["parent"]
	}
	if a, err := netip.ParseAddr(strings.TrimSpace(dev["ipv4.address"])); err == nil && a.Is4() {
		n.StaticIP = a
	}
	return n
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// parseDnsmasqLeases reads a dnsmasq leases file — one lease per line,
// `<expiry-unix> <mac> <ip> <hostname> <client-id>` — and returns the IPv4 each
// lower-case MAC currently holds. An expiry of 0 is a permanent lease; a lease
// whose expiry is before now is skipped. Malformed lines are skipped, not fatal.
func parseDnsmasqLeases(r io.Reader, now time.Time) map[string]netip.Addr {
	out := make(map[string]netip.Addr)
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 3 {
			continue
		}
		expiry, err := strconv.ParseInt(f[0], 10, 64)
		if err != nil {
			continue
		}
		if expiry != 0 && time.Unix(expiry, 0).Before(now) {
			continue
		}
		ip, err := netip.ParseAddr(f[2])
		if err != nil || !ip.Is4() {
			continue
		}
		out[strings.ToLower(f[1])] = ip
	}
	return out
}

// leaseReader looks up the DHCP lease a bridge's dnsmasq holds for a MAC. The
// enforcer's reconcile creates one per pass so each lease file is read at most
// once per pass however many instances share the bridge.
type leaseReader struct {
	dir   string // defaultIncusLeaseDir, or a test override
	now   time.Time
	cache map[string]map[string]netip.Addr // network -> mac -> ip
}

func newLeaseReader(dir string, now time.Time) *leaseReader {
	return &leaseReader{dir: dir, now: now, cache: make(map[string]map[string]netip.Addr)}
}

// lookup returns the leased IPv4 for mac on network, if any.
func (l *leaseReader) lookup(network, mac string) (netip.Addr, bool) {
	if network == "" || mac == "" {
		return netip.Addr{}, false
	}
	// network is the Incus bridge name from host-side device config; a valid one
	// is a single path segment. Reject anything with a separator or "." element
	// so the join cannot escape the lease dir (defence in depth — the value is
	// host-controlled, not guest-controlled).
	if network != filepath.Base(network) || network == "." || network == ".." || strings.ContainsAny(network, `/\`) {
		return netip.Addr{}, false
	}
	leases, ok := l.cache[network]
	if !ok {
		leases = map[string]netip.Addr{}
		leasePath := filepath.Join(l.dir, network, "dnsmasq.leases")
		if f, err := os.Open(leasePath); err == nil { // #nosec G304 -- base dir is fixed; network is a validated single path segment from host-side Incus config
			leases = parseDnsmasqLeases(f, l.now)
			_ = f.Close()
		}
		l.cache[network] = leases
	}
	ip, ok := leases[strings.ToLower(mac)]
	return ip, ok
}

// hostIPv4For resolves the box address for nic from host-side sources: the
// static device address, else the bridge's DHCP lease — but a lease counts only
// when it equals the address the guest itself reports. dnsmasq moves a lease on
// a DHCP release/request that names the MAC, and a neighbour can send those on
// the bridge, so a lease alone could be made to disagree with the box's real
// address and get the box's genuine traffic flagged as spoofed (a cross-tenant
// DoS under enforce). Requiring both to agree means neither side can move the
// validated address on its own: the guest cannot (its report is not trusted
// alone) and a neighbour cannot (the lease is not trusted alone). ok is false
// when nothing host-side knows it, or the two disagree.
func hostIPv4For(nic hostNIC, leases *leaseReader, guest [4]byte, hasGuest bool) ([4]byte, bool) {
	if nic.StaticIP.IsValid() {
		return nic.StaticIP.As4(), true
	}
	if ip, ok := leases.lookup(nic.Network, nic.HWAddr); ok && hasGuest && ip.As4() == guest {
		return ip.As4(), true
	}
	return [4]byte{}, false
}
