package server

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// #2618 B1: the address the program validates a box against must come from the
// host, never from the guest's own report. These pin the two host sources.

func TestParseDnsmasqLeases(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	in := strings.Join([]string{
		"1800003600 00:16:3e:aa:bb:cc 10.100.0.10 alice-container 01:00:16:3e:aa:bb:cc", // live
		"1700000000 00:16:3e:dd:ee:ff 10.100.0.11 stale-container *",                    // expired
		"0 00:16:3E:11:22:33 10.100.0.12 pinned-container *",                            // permanent, upper-case MAC
		"not-a-number 00:16:3e:44:55:66 10.100.0.13 bad *",                              // malformed expiry
		"1800003600 00:16:3e:77:88:99 fd00::1 v6-only *",                                // not IPv4
		"short",
	}, "\n")
	got := parseDnsmasqLeases(strings.NewReader(in), now)
	want := map[string]netip.Addr{
		"00:16:3e:aa:bb:cc": netip.MustParseAddr("10.100.0.10"),
		"00:16:3e:11:22:33": netip.MustParseAddr("10.100.0.12"),
	}
	if len(got) != len(want) {
		t.Fatalf("leases = %v, want %v", got, want)
	}
	for mac, ip := range want {
		if got[mac] != ip {
			t.Errorf("lease[%s] = %v, want %v", mac, got[mac], ip)
		}
	}
}

func TestPrimaryNICDevice(t *testing.T) {
	devs := map[string]map[string]string{
		"root":  {"type": "disk", "path": "/"},
		"eth1":  {"type": "nic", "network": "other"},
		"eth0":  {"type": "nic", "network": "incusbr0"},
		"proxy": {"type": "proxy"},
	}
	if name, d := primaryNICDevice(devs); name != "eth0" || d["network"] != "incusbr0" {
		t.Errorf("primary = %q %v, want eth0 on incusbr0", name, d)
	}
	delete(devs, "eth0")
	if name, _ := primaryNICDevice(devs); name != "eth1" {
		t.Errorf("primary without eth0 = %q, want the first nic by name (eth1)", name)
	}
	delete(devs, "eth1")
	if name, d := primaryNICDevice(devs); name != "" || d != nil {
		t.Errorf("primary with no nic = %q %v, want none", name, d)
	}
	// A non-nic device named eth0 is not the NIC.
	if name, _ := primaryNICDevice(map[string]map[string]string{"eth0": {"type": "disk"}, "net0": {"type": "nic"}}); name != "net0" {
		t.Errorf("primary = %q, want net0 (eth0 is not a nic here)", name)
	}
}

func TestHostNICFor(t *testing.T) {
	cfg := map[string]string{"volatile.eth0.hwaddr": "00:16:3E:AA:BB:CC", "volatile.eth0.host_name": "vethabc"}
	nic := hostNICFor(cfg, map[string]map[string]string{"eth0": {"type": "nic", "network": "incusbr0", "ipv4.address": "10.100.0.5"}})
	if nic.Network != "incusbr0" || nic.HWAddr != "00:16:3e:aa:bb:cc" || nic.StaticIP != netip.MustParseAddr("10.100.0.5") {
		t.Errorf("hostNICFor = %+v", nic)
	}
	// parent (bridged nictype) stands in for network; a device-level hwaddr wins.
	nic = hostNICFor(cfg, map[string]map[string]string{"eth0": {"type": "nic", "nictype": "bridged", "parent": "br0", "hwaddr": "00:16:3e:00:00:01"}})
	if nic.Network != "br0" || nic.HWAddr != "00:16:3e:00:00:01" || nic.StaticIP.IsValid() {
		t.Errorf("hostNICFor(parent) = %+v", nic)
	}
	// A non-IPv4 or junk ipv4.address is ignored, not treated as the address.
	nic = hostNICFor(cfg, map[string]map[string]string{"eth0": {"type": "nic", "network": "incusbr0", "ipv4.address": "none"}})
	if nic.StaticIP.IsValid() {
		t.Errorf("junk ipv4.address parsed as %v", nic.StaticIP)
	}
	if nic = hostNICFor(cfg, nil); nic != (hostNIC{}) {
		t.Errorf("no devices = %+v, want zero", nic)
	}
}

func TestHostIPv4For_StaticThenLeaseThenNone(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "incusbr0"), 0o755); err != nil {
		t.Fatal(err)
	}
	lease := "0 00:16:3e:aa:bb:cc 10.100.0.10 alice *\n"
	if err := os.WriteFile(filepath.Join(dir, "incusbr0", "dnsmasq.leases"), []byte(lease), 0o644); err != nil {
		t.Fatal(err)
	}
	leases := newLeaseReader(dir, time.Now())

	// Static assignment wins even when a lease exists.
	ip, ok := hostIPv4For(hostNIC{Network: "incusbr0", HWAddr: "00:16:3e:aa:bb:cc", StaticIP: netip.MustParseAddr("10.100.0.5")}, leases)
	if !ok || ip != [4]byte{10, 100, 0, 5} {
		t.Errorf("static: %v %v", ip, ok)
	}
	// Else the bridge's lease for the MAC (case-insensitive).
	ip, ok = hostIPv4For(hostNIC{Network: "incusbr0", HWAddr: "00:16:3E:AA:BB:CC"}, leases)
	if !ok || ip != [4]byte{10, 100, 0, 10} {
		t.Errorf("lease: %v %v", ip, ok)
	}
	// No lease for the MAC, unknown network, or missing lease file: unknown —
	// never a guess.
	for _, nic := range []hostNIC{
		{Network: "incusbr0", HWAddr: "00:16:3e:00:00:00"},
		{Network: "nosuchbr", HWAddr: "00:16:3e:aa:bb:cc"},
		{HWAddr: "00:16:3e:aa:bb:cc"},
		{},
	} {
		if ip, ok := hostIPv4For(nic, leases); ok {
			t.Errorf("hostIPv4For(%+v) = %v, want unknown", nic, ip)
		}
	}
	// The file is read once per reader however many lookups hit the network.
	if len(leases.cache) != 2 { // incusbr0 and nosuchbr (empty)
		t.Errorf("lease cache has %d networks, want 2", len(leases.cache))
	}
}
