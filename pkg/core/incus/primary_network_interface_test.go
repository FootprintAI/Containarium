package incus

import (
	"testing"

	"github.com/lxc/incus/v7/shared/api"
)

func globalInet(addr string) []api.InstanceStateNetworkAddress {
	return []api.InstanceStateNetworkAddress{
		{Family: "inet", Scope: "global", Address: addr},
	}
}

// TestPrimaryNetworkInterface_VMWithK3sBridges is the regression test for
// containarium#1878: a VM running a k3s server has its own real NIC
// (enp5s0-style predictable name) alongside k3s's cni0/flannel.1 bridges.
// The real NIC must always win, deterministically — not by luck of Go's
// unordered map iteration.
func TestPrimaryNetworkInterface_VMWithK3sBridges(t *testing.T) {
	network := map[string]api.InstanceStateNetwork{
		"cni0":      {Addresses: globalInet("10.42.0.1")},
		"flannel.1": {Addresses: globalInet("10.42.0.0")},
		"enp5s0":    {Addresses: globalInet("10.232.21.167")},
	}
	got := primaryNetworkInterface(network)
	if got != "10.232.21.167" {
		t.Fatalf("primaryNetworkInterface() = %q, want the real NIC 10.232.21.167 (got cni0/flannel.1 instead)", got)
	}
}

// TestPrimaryNetworkInterface_ContainerEth0 is the pre-existing, still-must-
// work case: a container's default bridge device is named eth0.
func TestPrimaryNetworkInterface_ContainerEth0(t *testing.T) {
	network := map[string]api.InstanceStateNetwork{
		"lo":   {Addresses: globalInet("127.0.0.1")},
		"eth0": {Addresses: globalInet("10.100.0.42")},
	}
	got := primaryNetworkInterface(network)
	if got != "10.100.0.42" {
		t.Fatalf("primaryNetworkInterface() = %q, want eth0's 10.100.0.42", got)
	}
}

// TestPrimaryNetworkInterface_ContainerWithDockerBridge proves the existing
// docker0/podman0 exclusion (nested-Docker workloads inside a tenant
// container) still works after refactoring the three passes into one
// shared helper.
func TestPrimaryNetworkInterface_ContainerWithDockerBridge(t *testing.T) {
	network := map[string]api.InstanceStateNetwork{
		"docker0": {Addresses: globalInet("172.17.0.1")},
		"eth0":    {Addresses: globalInet("10.100.0.7")},
	}
	got := primaryNetworkInterface(network)
	if got != "10.100.0.7" {
		t.Fatalf("primaryNetworkInterface() = %q, want eth0's 10.100.0.7, not docker0's", got)
	}
}

// TestPrimaryNetworkInterface_UnrecognizedNameFallsBackButSkipsBridges
// covers an interface name pass 1 doesn't recognize (neither eth0 nor a
// VM predictable name) alongside a k3s bridge: pass 2 must still skip the
// bridge, even though it's reached by exclusion rather than a named match.
func TestPrimaryNetworkInterface_UnrecognizedNameFallsBackButSkipsBridges(t *testing.T) {
	network := map[string]api.InstanceStateNetwork{
		"cni0":     {Addresses: globalInet("10.42.0.1")},
		"wlan-vpc": {Addresses: globalInet("10.9.9.9")},
	}
	got := primaryNetworkInterface(network)
	if got != "10.9.9.9" {
		t.Fatalf("primaryNetworkInterface() = %q, want the unrecognized-but-non-bridge interface 10.9.9.9", got)
	}
}

// TestPrimaryNetworkInterface_OnlyBridgesPresentIsLastResort proves pass 3
// (true last resort) still returns something rather than "" when every
// interface is a known bridge — better than the daemon treating the VM as
// having no network at all when it plainly has an address.
func TestPrimaryNetworkInterface_OnlyBridgesPresentIsLastResort(t *testing.T) {
	network := map[string]api.InstanceStateNetwork{
		"cni0": {Addresses: globalInet("10.42.0.1")},
	}
	got := primaryNetworkInterface(network)
	if got != "10.42.0.1" {
		t.Fatalf("primaryNetworkInterface() = %q, want the last-resort bridge address 10.42.0.1", got)
	}
}

// TestPrimaryNetworkInterface_NoGlobalInetAddressReturnsEmpty covers a
// link-local-only or IPv6-only interface set: no candidate at all means "".
func TestPrimaryNetworkInterface_NoGlobalInetAddressReturnsEmpty(t *testing.T) {
	network := map[string]api.InstanceStateNetwork{
		"eth0": {Addresses: []api.InstanceStateNetworkAddress{
			{Family: "inet6", Scope: "link", Address: "fe80::1"},
		}},
	}
	got := primaryNetworkInterface(network)
	if got != "" {
		t.Fatalf("primaryNetworkInterface() = %q, want empty when no global inet address exists", got)
	}
}

// TestPrimaryNetworkInterface_VMPredictableNamePrefixes covers the other
// systemd predictable-name prefixes VMs commonly get, alongside a bridge,
// pinning that pass 1 matches by prefix, not just the exact "eth0" name.
func TestPrimaryNetworkInterface_VMPredictableNamePrefixes(t *testing.T) {
	for _, name := range []string{"enp5s0", "ens3", "eno1"} {
		t.Run(name, func(t *testing.T) {
			network := map[string]api.InstanceStateNetwork{
				"cni0": {Addresses: globalInet("10.42.0.1")},
				name:   {Addresses: globalInet("10.232.21.100")},
			}
			got := primaryNetworkInterface(network)
			if got != "10.232.21.100" {
				t.Fatalf("primaryNetworkInterface() = %q, want %s's 10.232.21.100", got, name)
			}
		})
	}
}
