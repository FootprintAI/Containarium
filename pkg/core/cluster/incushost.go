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

func (h *IncusHost) CreateVM(spec NodeSpec) error {
	cfg := incus.ContainerConfig{
		Name:         spec.Name,
		Image:        "images:ubuntu/24.04", // the nodevm default; VM image bake is a later phase
		CPU:          spec.CPU,
		Memory:       spec.Memory,
		InstanceType: api.InstanceTypeVM,
		AutoStart:    true,
	}
	if spec.Disk != "" {
		cfg.Disk = &incus.DiskDevice{Size: spec.Disk}
	}
	if err := h.client.CreateContainer(cfg); err != nil {
		return err
	}
	if err := h.client.SetLabels(spec.Name, spec.Labels); err != nil {
		return fmt.Errorf("label %s: %w", spec.Name, err)
	}
	return h.client.StartContainer(spec.Name)
}

func (h *IncusHost) Start(name string) error  { return h.client.StartContainer(name) }
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
