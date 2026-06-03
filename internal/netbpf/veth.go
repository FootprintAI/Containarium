// Package netbpf holds the host-side plumbing for the per-tenant network
// isolation feature (#315, Phase A): resolving each container's host veth (so
// the tc-bpf TC_INGRESS program can be attached to the sender side of every
// flow — see docs/security/NETWORK-ISOLATION-DESIGN.md, "Phase 0 validation
// findings") and, on Linux, loading/attaching the BPF programs themselves.
//
// This file is the veth-discovery half and is deliberately pure Go with no
// cilium/ebpf or netlink dependency, so it builds and unit-tests on every
// platform. The Linux-only attach/load path lives behind build tags in a
// later increment.
package netbpf

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// HostVethFromConfig resolves a container's host-side veth interface name from
// its Incus instance config. Incus records the host end of each NIC's veth pair
// in a volatile key once the container has started:
//
//	volatile.eth0.host_name = "vethXXXXXXXX"
//
// Resolution order:
//  1. volatile.eth0.host_name — the conventional primary NIC.
//  2. the lexicographically-first volatile.<nic>.host_name otherwise, so a
//     container whose primary NIC isn't named eth0 still resolves.
//
// Returns "" if the config carries no veth host_name (e.g. the container is
// stopped, or its NIC is a non-veth type such as a physical/SR-IOV passthrough).
// On "" the caller falls back to the Linux-only iflink lookup (mapping the
// container's eth0 iflink to a host interface), which validate-veth.sh exercises.
func HostVethFromConfig(config map[string]string) string {
	if v := strings.TrimSpace(config["volatile.eth0.host_name"]); v != "" {
		return v
	}
	// No eth0: scan for any volatile.<nic>.host_name and pick deterministically.
	var keys []string
	for k, v := range config {
		if strings.HasPrefix(k, "volatile.") && strings.HasSuffix(k, ".host_name") && strings.TrimSpace(v) != "" {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return ""
	}
	sort.Strings(keys)
	return strings.TrimSpace(config[keys[0]])
}

// VethIndex resolves a host veth interface name to its kernel ifindex — the
// handle link.AttachTCX needs. Thin wrapper over net.InterfaceByName so the
// not-found path has a single, testable error shape.
func VethIndex(name string) (int, error) {
	if name == "" {
		return 0, fmt.Errorf("veth name is empty")
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, fmt.Errorf("resolve host veth %q: %w", name, err)
	}
	return iface.Index, nil
}
