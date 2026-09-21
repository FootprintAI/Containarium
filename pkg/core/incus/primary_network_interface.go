package incus

import (
	"strings"

	"github.com/lxc/incus/v7/shared/api"
)

// knownBridgeInterfaces are interfaces that are never an instance's real,
// externally-routable NIC: container-runtime bridges an instance might run
// internally (docker0, podman0), and the CNI/overlay bridges a k3s server
// creates on itself once it starts (cni0, flannel.1, flannel-v6.1, cbr0).
// The latter used to be missing from this list, which let a VM running a
// k3s server have its own primary IP resolved to one of its own internal
// bridges instead of its real NIC — an address unroutable from any other
// VM (containarium#1878).
var knownBridgeInterfaces = map[string]bool{
	"lo":           true,
	"docker0":      true,
	"podman0":      true,
	"cni0":         true,
	"flannel.1":    true,
	"flannel-v6.1": true,
	"cbr0":         true,
}

// vmPredictableNamePrefixes are the systemd predictable network-interface
// name prefixes a VM's real NIC commonly gets (as opposed to a container,
// whose default bridge device is named "eth0").
var vmPredictableNamePrefixes = []string{"enp", "ens", "eno"}

// isPrimaryNICName reports whether name is a recognized primary-NIC name:
// either "eth0" (a container's default bridge device) or a VM's systemd
// predictable name.
func isPrimaryNICName(name string) bool {
	if name == "eth0" {
		return true
	}
	for _, prefix := range vmPredictableNamePrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// firstGlobalInetAddress returns the first global-scope IPv4 address in
// addrs, or "" if none.
func firstGlobalInetAddress(addrs []api.InstanceStateNetworkAddress) string {
	for _, addr := range addrs {
		if addr.Family == "inet" && addr.Scope == "global" {
			return addr.Address
		}
	}
	return ""
}

// primaryNetworkInterface picks an instance's primary IP address out of
// its full interface set, in three passes:
//
//  1. A recognized primary-NIC name (isPrimaryNICName) — deterministic,
//     independent of map iteration order, so this is the path every
//     ordinary container or VM takes.
//  2. Any interface that isn't a known bridge (knownBridgeInterfaces).
//     Go map iteration order is unspecified, so a tie between two
//     unrecognized interface names picks nondeterministically — kept
//     only as a fallback for interface names pass 1 doesn't recognize.
//  3. True last resort: any interface with a global address at all,
//     including a bridge normally excluded above. Returning a bridge
//     address is still better than reporting no address when the
//     instance plainly has one.
//
// Returns "" if no interface has a global-scope IPv4 address.
func primaryNetworkInterface(network map[string]api.InstanceStateNetwork) string {
	for name, net := range network {
		if !isPrimaryNICName(name) {
			continue
		}
		if ip := firstGlobalInetAddress(net.Addresses); ip != "" {
			return ip
		}
	}

	for name, net := range network {
		if knownBridgeInterfaces[name] {
			continue
		}
		if ip := firstGlobalInetAddress(net.Addresses); ip != "" {
			return ip
		}
	}

	for _, net := range network {
		if ip := firstGlobalInetAddress(net.Addresses); ip != "" {
			return ip
		}
	}

	return ""
}
