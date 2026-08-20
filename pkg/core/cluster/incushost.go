package cluster

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lxc/incus/v6/shared/api"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// ErrVMsUnsupported is the typed create-time refusal for hosts that
// cannot run Incus VMs (the design's hard requirement — no silent
// degrade to shared-kernel containers).
var ErrVMsUnsupported = errors.New("this backend cannot run virtual machines (KVM/qemu unavailable); managed clusters require VM capability")

// IncusHost adapts pkg/core/incus.Client to the VMHost seam. Thin by
// design: every method is one client call plus shaping; the sequences
// that matter are in Manager and tested against a fake.
type IncusHost struct {
	client *incus.Client
}

// NewIncusHost wraps an incus client.
func NewIncusHost(c *incus.Client) *IncusHost { return &IncusHost{client: c} }

func (h *IncusHost) VMCapable() error {
	info, err := h.client.GetServerInfo()
	if err != nil {
		return fmt.Errorf("query incus server: %w", err)
	}
	// Incus reports VM support by listing "qemu" among its drivers.
	if !strings.Contains(info.Environment.Driver, "qemu") {
		return ErrVMsUnsupported
	}
	return nil
}

// ContainerNodeCapable probes the container-node preconditions on the
// real host (#1429): the observation lives in GatherContainerNodeFacts
// and the verdict in CheckContainerNodeFacts, both in
// containerprofile.go — the one place holding this knowledge.
func (h *IncusHost) ContainerNodeCapable() error {
	return CheckContainerNodeFacts(GatherContainerNodeFacts("/", func() (string, error) {
		info, err := h.client.GetServerInfo()
		if err != nil {
			return "", err
		}
		return info.Environment.Driver, nil
	}))
}

// NodeCapacityCapable is the per-node half of the container probe
// (#1439): the kernel preconditions can all hold on a host that still
// cannot honour the size this node asked for. Refusing here beats
// creating a node that would advertise capacity it does not have —
// the scheduler and the autoscaler both believe node allocatable.
func (h *IncusHost) NodeCapacityCapable(spec NodeSpec) error {
	cpu, mem, err := HostCapacity("/")
	if err != nil {
		// Fail closed: an unreadable /proc means the lie cannot be
		// measured, not that there is no lie.
		return fmt.Errorf("%w: cannot read host capacity, so a container node's advertised size cannot be made truthful: %v",
			ErrContainerNodesUnsupported, err)
	}
	return CheckNodeCapacity(cpu, mem, spec)
}

// nodeContainerConfig is the Incus config one cluster node is created
// from. Pure (no Incus calls) so the shape Incus validates is
// unit-testable — see nodeconfig_test.go and #1435.
func nodeContainerConfig(spec NodeSpec, isolation Isolation, pool string) incus.ContainerConfig {
	cfg := incus.ContainerConfig{
		Name:         spec.Name,
		Image:        "images:ubuntu/24.04", // the nodevm default; VM image bake is a later phase
		CPU:          spec.CPU,
		Memory:       spec.Memory,
		InstanceType: api.InstanceTypeVM,
		AutoStart:    true,
	}
	if isolation == IsolationContainer {
		// The container node profile — nesting, no privileged — comes
		// from ContainerNodeConfig; anything that is not the explicit
		// weaker class provisions a VM (never default to the weaker
		// boundary).
		cfg.InstanceType = api.InstanceTypeContainer
		cfg.ExtraConfig = ContainerNodeConfig()
	}
	if spec.Disk != "" {
		// Path and Pool alongside the size, as every other caller in the
		// tree does: Incus refuses a root disk that carries only a size
		// ("Disk entry is missing the required source or path property"),
		// and it refuses it at instance creation — inside the
		// reconciler's provisioning loop, not at config time (#1435).
		cfg.Disk = &incus.DiskDevice{Path: "/", Pool: pool, Size: spec.Disk}
	}
	return cfg
}

func (h *IncusHost) CreateNode(spec NodeSpec, isolation Isolation) error {
	cfg := nodeContainerConfig(spec, isolation, h.client.StoragePool())
	if err := h.client.CreateContainer(cfg); err != nil {
		return err
	}
	if err := h.client.SetLabels(spec.Name, spec.Labels); err != nil {
		return fmt.Errorf("label %s: %w", spec.Name, err)
	}
	return h.client.StartContainer(spec.Name)
}

func (h *IncusHost) Start(name string) error { return h.client.StartContainer(name) }

// Stop halts an instance, forcing it: a cluster node being removed is
// not asked politely, and a graceful stop that hangs would block the
// autoscaler's scale-down behind a 30s timeout per node.
func (h *IncusHost) Stop(name string) error { return h.client.StopContainer(name, true) }

func (h *IncusHost) Delete(name string) error { return h.client.DeleteContainer(name) }

func (h *IncusHost) WaitReady(name string, timeout time.Duration) (string, error) {
	return h.client.WaitForNetwork(name, timeout)
}

func (h *IncusHost) Push(name, path string, content []byte, mode string) error {
	return h.client.WriteFile(name, path, content, mode)
}

func (h *IncusHost) Read(name, path string) ([]byte, error) {
	return h.client.ReadFile(name, path)
}

func (h *IncusHost) Exec(name string, cmd []string) (string, error) {
	stdout, stderr, err := h.client.ExecWithOutput(name, cmd)
	if err != nil {
		return stdout, fmt.Errorf("%w (stderr: %s)", err, strings.TrimSpace(stderr))
	}
	return stdout, nil
}

func (h *IncusHost) ClusterVMs(tenant, clusterName string) (Observed, error) {
	all, err := h.client.ListContainers()
	if err != nil {
		return Observed{}, err
	}
	obs := Observed{Workers: map[string][]ObservedVM{}}
	for i := range all {
		c := &all[i]
		if c.Labels[LabelCluster] != clusterName || c.Labels[LabelClusterOwner] != tenant {
			continue
		}
		vm := ObservedVM{Name: c.Name, Running: strings.EqualFold(c.State, "running")}
		switch c.Labels[LabelClusterRole] {
		case RoleControlPlane:
			cp := vm
			obs.CP = &cp
		case RoleWorker:
			g := c.Labels[LabelNodeGroup]
			obs.Workers[g] = append(obs.Workers[g], vm)
		}
	}
	return obs, nil
}
