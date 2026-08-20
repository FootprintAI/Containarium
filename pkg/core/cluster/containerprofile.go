package cluster

// Container node profile and capability probe (#1429): THE one place
// holding the "k3s node inside an Incus system container" knowledge.
// Design: docs/architecture/cluster-container-node-pools.md
// ("The container node profile").
//
// The profile is deliberately three facts and a hard line:
//
//   - security.nesting=true — containerd runs pods inside the node.
//   - cgroup v2 delegation — Incus's default for system containers;
//     nothing to set here, the host-side requirement (a unified
//     cgroup v2 hierarchy) is asserted by ContainerNodeCapable.
//   - a boot-time /dev/kmsg shim rendered into the bootstrap unit
//     (KmsgShimCommand below).
//   - NO security.privileged — if a future k8s feature turns out to
//     need it, that is a new design conversation, not a config tweak.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ContainerNodeConfig returns the Incus instance config applied to a
// k3s node container by CreateNode on the container path. Golden-
// pinned (testdata/container-node-config.golden): what a tenant's node
// container is granted changes only as a reviewable golden diff.
func ContainerNodeConfig() map[string]string {
	return map[string]string{
		// containerd runs pods inside the node container.
		"security.nesting": "true",
	}
}

// KmsgShimCommand is the boot-time /dev/kmsg shim: k3s's kubelet wants
// /dev/kmsg, which an unprivileged container does not get — the
// k3d-proven workaround links it to the console. It renders into the
// k3s systemd unit as an ExecStartPre so it re-applies on every boot
// (/dev is a fresh tmpfs each start), rather than being mounted from
// the host, whose own /dev/kmsg may not exist (nested case).
const KmsgShimCommand = `/bin/sh -c '[ -e /dev/kmsg ] || ln -s /dev/console /dev/kmsg'`

// kmsgShimUnitLine renders the shim into a unit's [Service] section:
// one ExecStartPre line on the container path, nothing on the VM path
// — VM units stay byte-identical to their pre-#1429 goldens.
func kmsgShimUnitLine(iso Isolation) string {
	if iso != IsolationContainer {
		return ""
	}
	return "ExecStartPre=" + KmsgShimCommand + "\n"
}

// --- capability probe -------------------------------------------------

// ErrContainerNodesUnsupported heads every ContainerNodeCapable
// refusal — the container-class counterpart of ErrVMsUnsupported.
var ErrContainerNodesUnsupported = errors.New("this backend cannot run container nodes")

// ProbeState is one precondition's observed state.
type ProbeState int

const (
	// ProbeOK: the precondition was verified present.
	ProbeOK ProbeState = iota
	// ProbeMissing: the precondition was verified absent.
	ProbeMissing
	// ProbeUnknown: the precondition could not be observed. Never
	// treated as OK — an unverified boundary requirement refuses,
	// with the refusal saying what could not be checked and why.
	ProbeUnknown
)

// Probe is one precondition's observation: its state plus, for
// anything other than OK, the incusenv "which step, which error"
// detail an operator needs to act on it.
type Probe struct {
	State  ProbeState
	Detail string
}

// ContainerNodeFacts is everything ContainerNodeCapable observes about
// the host, one Probe per design-named precondition. Split from the
// verdict (CheckContainerNodeFacts) so the fold is a pure,
// table-testable function.
type ContainerNodeFacts struct {
	// Nesting: the Incus server can create system containers (lxc
	// driver present) — the carrier for security.nesting. On a nested
	// host, a responding Incus is itself the evidence that nesting was
	// granted to this environment.
	Nesting Probe
	// CgroupV2: the (shared) kernel exposes a unified cgroup v2
	// hierarchy, which Incus delegates to system containers.
	CgroupV2 Probe
	// BrNetfilter / Overlay: kernel modules k3s networking and
	// containerd's snapshotter need, present on the shared kernel.
	BrNetfilter Probe
	Overlay     Probe
}

// CheckContainerNodeFacts folds the observations into the create-time
// verdict: nil only when every precondition was VERIFIED present.
// Missing and unprobeable preconditions both refuse — each named with
// its own detail, an unprobeable one explicitly as "could not be
// verified" rather than assumed green.
func CheckContainerNodeFacts(f ContainerNodeFacts) error {
	items := []struct {
		name string
		p    Probe
	}{
		{"nesting", f.Nesting},
		{"cgroup v2", f.CgroupV2},
		{"br_netfilter", f.BrNetfilter},
		{"overlay", f.Overlay},
	}
	var problems []string
	for _, it := range items {
		switch it.p.State {
		case ProbeOK:
		case ProbeMissing:
			problems = append(problems, fmt.Sprintf("%s: %s", it.name, it.p.Detail))
		default: // ProbeUnknown and anything unrecognized fail closed
			problems = append(problems, fmt.Sprintf("%s: could not be verified (%s)", it.name, it.p.Detail))
		}
	}
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrContainerNodesUnsupported, strings.Join(problems, "; "))
}

// GatherContainerNodeFacts probes the daemon host. sysRoot is the host
// filesystem root ("/" in production, a fixture in tests); driver
// reports the Incus server's instance drivers (IncusHost wires
// GetServerInfo). Every probe distinguishes verified-absent from
// could-not-observe.
func GatherContainerNodeFacts(sysRoot string, driver func() (string, error)) ContainerNodeFacts {
	nested := hostIsContainer(sysRoot)
	return ContainerNodeFacts{
		Nesting:     probeNesting(driver),
		CgroupV2:    probeCgroupV2(sysRoot),
		BrNetfilter: probeModule(sysRoot, "br_netfilter", nested),
		Overlay:     probeModule(sysRoot, "overlay", nested),
	}
}

// hostIsContainer reports whether the daemon host is itself a
// container (the nested rung): systemd writes /run/systemd/container
// in any container it boots in.
func hostIsContainer(sysRoot string) bool {
	_, err := os.Stat(filepath.Join(sysRoot, "run/systemd/container"))
	return err == nil
}

func probeNesting(driver func() (string, error)) Probe {
	d, err := driver()
	if err != nil {
		return Probe{State: ProbeUnknown, Detail: fmt.Sprintf("query incus server drivers: %v", err)}
	}
	if !strings.Contains(d, "lxc") {
		return Probe{State: ProbeMissing, Detail: fmt.Sprintf("incus reports no system-container (lxc) driver, only %q", d)}
	}
	// lxc driver present: system containers can be created and
	// security.nesting is per-instance config this server applies. On
	// a nested host, this very answer is the transitive evidence that
	// nesting was granted — the outer instance's config cannot be
	// read from in here.
	return Probe{State: ProbeOK}
}

func probeCgroupV2(sysRoot string) Probe {
	p := filepath.Join(sysRoot, "sys/fs/cgroup/cgroup.controllers")
	_, err := os.Stat(p)
	switch {
	case err == nil:
		return Probe{State: ProbeOK}
	case os.IsNotExist(err):
		return Probe{State: ProbeMissing,
			Detail: fmt.Sprintf("host cgroup hierarchy is not unified cgroup v2 (%s not found); k3s-in-container needs cgroup v2 delegation", p)}
	default:
		return Probe{State: ProbeUnknown, Detail: fmt.Sprintf("stat %s: %v", p, err)}
	}
}

func probeModule(sysRoot, module string, nested bool) Probe {
	p := filepath.Join(sysRoot, "sys/module", module)
	_, err := os.Stat(p)
	switch {
	case err == nil:
		return Probe{State: ProbeOK}
	case os.IsNotExist(err):
		detail := fmt.Sprintf("kernel module %s not present (%s not found)", module, p)
		if nested {
			// The shared kernel belongs to the outer host; a nested
			// daemon can neither load the module nor probe beyond
			// /sys — say so instead of guessing.
			detail += "; this host is itself a container sharing the outer kernel — the module cannot be loaded from here, load it on the physical host"
		} else {
			detail += "; load it (modprobe " + module + ")"
		}
		return Probe{State: ProbeMissing, Detail: detail}
	default:
		return Probe{State: ProbeUnknown, Detail: fmt.Sprintf("stat %s: %v", p, err)}
	}
}
