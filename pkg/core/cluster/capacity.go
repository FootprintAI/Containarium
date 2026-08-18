package cluster

// Truthful node capacity for container-class nodes, and the containerd
// configuration that lets pods run in them at all (design Amendment 1
// in docs/architecture/cluster-container-node-pools.md, #1439).
//
// Both exist because a container node is not the machine Kubernetes
// thinks it is: containerd's CRI plugin writes a sysctl an unprivileged
// container may not touch, and cadvisor reads the OUTER host's /proc,
// so a 2-cpu node cheerfully advertises the host's 8. The first breaks
// every pod; the second breaks autoscaling silently, which is worse.

import (
	"fmt"
	"regexp"
	"strconv"
)

// ContainerdConfigTemplatePath is where k3s reads a containerd config
// template from. containerd config version 3 (k3s 1.33+) uses the
// -v3 name; the older name is ignored by these releases.
const ContainerdConfigTemplatePath = "/var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.tmpl"

// ContainerdConfigTemplate returns the containerd config template for
// container-class nodes.
//
// Without it every pod sandbox dies in an unprivileged container:
//
//	runc create failed: ... open sysctl net.ipv4.ip_unprivileged_port_start:
//	  reopen fd 8: permission denied
//
// because the CRI plugin sets net.ipv4.ip_unprivileged_port_start=0 for
// each sandbox. Turning the two toggles off stops it asking. Verified
// live on a nested host: node Ready, system pods Running, no privileged
// flag anywhere.
//
// The cost is real and documented: pods on container-class nodes cannot
// bind ports below 1024 without CAP_NET_BIND_SERVICE, and unprivileged
// ICMP is unavailable. VM-class nodes are unaffected — they never get
// this template.
func ContainerdConfigTemplate() string {
	return `{{ template "base" . }}

[plugins.'io.containerd.cri.v1.runtime']
  enable_unprivileged_ports = false
  enable_unprivileged_icmp = false
`
}

// Reserved is the slice of a node's observed capacity that does NOT
// belong to the node — the gap between what /proc reports (the outer
// host) and the size the daemon actually asked for.
type Reserved struct {
	CPU         int
	MemoryBytes int64
}

// Zero reports whether there is nothing to reserve, i.e. the node
// observes exactly its own size and the stock kubelet is already right.
func (r Reserved) Zero() bool { return r.CPU == 0 && r.MemoryBytes == 0 }

// ReservedResources computes what kubelet must reserve so that
// allocatable equals the requested size, given what the node observes.
//
// Allocatable = capacity − reserved, and the scheduler and
// cluster-autoscaler's fit simulation both read allocatable — so this
// is what stops a node claiming four times its CPU from being packed
// with pods it cannot run, and from suppressing the scale-up that
// should have happened.
//
// Observed capacity SMALLER than the requested size is an error, never
// a negative reservation: it means the node cannot host what was asked
// for, and inventing headroom would hide that.
func ReservedResources(observedCPU int, observedMemBytes int64, spec NodeSpec) (Reserved, error) {
	wantCPU, err := strconv.Atoi(spec.CPU)
	if err != nil {
		return Reserved{}, fmt.Errorf("node cpu %q: %w", spec.CPU, err)
	}
	wantMem, err := ParseSizeBytes(spec.Memory)
	if err != nil {
		return Reserved{}, fmt.Errorf("node memory %q: %w", spec.Memory, err)
	}
	if observedCPU < wantCPU || observedMemBytes < wantMem {
		return Reserved{}, fmt.Errorf(
			"node observes %d cpu / %d bytes but was sized %d cpu / %d bytes: "+
				"the host cannot honour this size, so no reservation makes allocatable truthful",
			observedCPU, observedMemBytes, wantCPU, wantMem)
	}
	return Reserved{
		CPU:         observedCPU - wantCPU,
		MemoryBytes: observedMemBytes - wantMem,
	}, nil
}

// KubeletReservedArgs renders a reservation as k3s --kubelet-arg
// flags. A zero reservation renders nothing: a node whose observed
// capacity already equals its size needs no correction, and passing
// system-reserved=cpu=0 would only add noise to the unit file.
func KubeletReservedArgs(r Reserved) []string {
	if r.Zero() {
		return nil
	}
	return []string{
		fmt.Sprintf("--kubelet-arg=system-reserved=cpu=%d,memory=%d", r.CPU, r.MemoryBytes),
		// Without this kubelet accounts the reservation but does not
		// enforce it, so allocatable moves while the cgroup does not.
		"--kubelet-arg=enforce-node-allocatable=pods",
	}
}

// sizeBytesRE matches the house size format the node-group validator
// accepts ("16GB"), decimal units.
var sizeBytesRE = regexp.MustCompile(`^([1-9][0-9]*)(MB|GB|TB)$`)

// ParseSizeBytes parses the house size format ("16GB") into bytes.
//
// Lives here rather than in internal/server because pkg/core/cluster is
// what the node sizing math needs it for, and the dependency only runs
// that way; internal/server's own copy predates this and can adopt it.
func ParseSizeBytes(s string) (int64, error) {
	m := sizeBytesRE.FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf("invalid size %q (want e.g. 16GB)", s)
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return 0, err
	}
	switch m[2] {
	case "MB":
		return n * 1_000_000, nil
	case "GB":
		return n * 1_000_000_000, nil
	default: // TB
		return n * 1_000_000_000_000, nil
	}
}
