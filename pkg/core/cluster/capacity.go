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
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// ContainerdConfigTemplatePath is where k3s reads a containerd config
// template from. containerd config version 3 (k3s 1.33+) uses the
// -v3 name; the older name is ignored by these releases.
const ContainerdConfigTemplatePath = "/var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.tmpl"

// ContainerdGeneratedConfigPath is where k3s writes the containerd
// config it generates on start. On container-class nodes the bootstrap
// derives the config template FROM this file — a hand-written template
// cannot safely extend it, because k3s's base template already
// declares [plugins.'io.containerd.cri.v1.runtime'] and re-declaring a
// TOML table is invalid, so containerd refuses the whole config and
// k3s never starts (#1444).
const ContainerdGeneratedConfigPath = "/var/lib/rancher/k3s/agent/etc/containerd/config.toml"

// containerdUnprivilegedToggles are the CRI plugin settings that make
// runc write sysctls (net.ipv4.ip_unprivileged_port_start) an
// unprivileged container may not touch. With either enabled every pod
// sandbox dies:
//
//	runc create failed: ... open sysctl net.ipv4.ip_unprivileged_port_start:
//	  reopen fd 8: permission denied
//
// Flipping both to false was verified live on a nested host: node
// Ready, system pods Running, no privileged flag anywhere (design
// Amendment 1). The cost is real and documented: pods on
// container-class nodes cannot bind ports below 1024 without
// CAP_NET_BIND_SERVICE, and unprivileged ICMP is unavailable.
// VM-class nodes are unaffected — they never get the derivation.
var containerdUnprivilegedToggles = []string{
	"enable_unprivileged_ports",
	"enable_unprivileged_icmp",
}

// ContainerdDeriveTemplateSedArgs returns the sed arguments (sans the
// input file) that turn k3s's generated containerd config into the
// config template for container-class nodes: an exact copy with the
// two unprivileged toggles flipped to false. Exported so the tests
// run the very same derivation the bootstrap embeds.
func ContainerdDeriveTemplateSedArgs() []string {
	var args []string
	for _, key := range containerdUnprivilegedToggles {
		args = append(args, "-e", fmt.Sprintf("s/%s = true/%s = false/", key, key))
	}
	return args
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

// HostCapacity reads what a container node on this host will observe as
// its own capacity: the host's /proc, because cadvisor inside the node
// reads exactly these files and lxcfs masking does not reach a nested
// Incus's own instances (design Amendment 1).
//
// sysRoot is the filesystem root ("/" in production, a fixture in
// tests). A /proc it cannot read is an error, never a zero capacity —
// zero would compute a reservation that silently starves the node.
func HostCapacity(sysRoot string) (cpu int, memBytes int64, err error) {
	cpuinfo, err := os.ReadFile(filepath.Join(sysRoot, "proc/cpuinfo"))
	if err != nil {
		return 0, 0, fmt.Errorf("read cpuinfo: %w", err)
	}
	for _, line := range strings.Split(string(cpuinfo), "\n") {
		if strings.HasPrefix(line, "processor") {
			cpu++
		}
	}
	if cpu == 0 {
		return 0, 0, fmt.Errorf("no processor lines in %s/proc/cpuinfo", sysRoot)
	}

	meminfo, err := os.ReadFile(filepath.Join(sysRoot, "proc/meminfo"))
	if err != nil {
		return 0, 0, fmt.Errorf("read meminfo: %w", err)
	}
	for _, line := range strings.Split(string(meminfo), "\n") {
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			break
		}
		kb, convErr := strconv.ParseInt(fields[1], 10, 64)
		if convErr != nil {
			return 0, 0, fmt.Errorf("MemTotal %q: %w", fields[1], convErr)
		}
		return cpu, kb * 1024, nil
	}
	return 0, 0, fmt.Errorf("no MemTotal in %s/proc/meminfo", sysRoot)
}

// CheckNodeCapacity is the create-time half of the capability probe:
// a host may satisfy every kernel precondition and still be unable to
// host the node that was asked for.
//
// It refuses when the capacity a node would observe is smaller than
// the size requested, because then no reservation makes allocatable
// truthful — and a node that lies about its size is worse than no
// node, since the scheduler and the autoscaler's fit simulation both
// believe it.
func CheckNodeCapacity(observedCPU int, observedMemBytes int64, spec NodeSpec) error {
	if _, err := ReservedResources(observedCPU, observedMemBytes, spec); err != nil {
		return fmt.Errorf("%w: %v", ErrContainerNodesUnsupported, err)
	}
	return nil
}

// DeriveContainerdTemplate turns a *generated* containerd config into
// the template a container-class node should use: the same content
// with the unprivileged-port/ICMP toggles flipped off.
//
// This is the Go-side counterpart of the sed the control-plane
// bootstrap runs, and it exists because a **worker cannot derive its
// own** (#1448): k3s agent writes config.toml only after it has
// retrieved configuration from the server, so a worker that waits for
// that file blocks on something downstream of the startup it is
// blocking. The daemon instead derives from the control plane's
// already-generated config — same pinned k3s version, same base shape
// — and pushes the result before the agent first starts.
//
// A config that does not contain a toggle is an ERROR, not a
// pass-through: silently shipping a template that leaves the toggles
// enabled would restore the failure #1444 fixed, with nothing to say
// so. #1444's loudness is the property being preserved here.
func DeriveContainerdTemplate(generated []byte) ([]byte, error) {
	out := string(generated)
	for _, key := range containerdUnprivilegedToggles {
		enabled := key + " = true"
		disabled := key + " = false"
		switch {
		case strings.Contains(out, enabled):
			out = strings.ReplaceAll(out, enabled, disabled)
		case strings.Contains(out, disabled):
			// Already off — nothing to flip, still correct.
		default:
			return nil, fmt.Errorf(
				"generated containerd config contains no %q setting to disable; "+
					"the config shape changed and a container node would run with pod sandboxes broken", key)
		}
	}
	return []byte(out), nil
}

// ContainerKubeletArgs are the kubelet flags every container-class node
// needs, with any additional args (e.g. a reservation) appended.
//
// kubelet's ContainerManager writes kernel sysctls at startup —
// /proc/sys/kernel/panic_on_oops, /proc/sys/vm/overcommit_memory,
// /proc/sys/kernel/panic — which an unprivileged container may not
// touch. It fails with "Failed to start ContainerManager" and names the
// remedy itself: the KubeletInUserNamespace feature gate makes it skip
// those writes (#1452).
//
// This applies to BOTH roles: k3s server runs an embedded kubelet, so a
// control plane fails identically to a worker without it — which is why
// the control plane could report `ready` (its files exist) while its
// supervisor never finished starting and no agent could ever join.
func ContainerKubeletArgs(extra []string) []string {
	args := []string{"--kubelet-arg=feature-gates=KubeletInUserNamespace=true"}
	return append(args, extra...)
}
