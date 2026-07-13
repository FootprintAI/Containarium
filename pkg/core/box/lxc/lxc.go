// Package lxc implements box.BoxBackend over the existing LXC/incus
// container.Manager. It is a pure adapter: every method delegates to the
// Manager that the daemon already uses, so behavior is unchanged. The package
// exists to give the daemon a runtime-neutral seam (box.BoxBackend) it can
// hold instead of a concrete *container.Manager — see
// docs/K8S-AGENT-BOX-RUNTIME-DESIGN.md.
package lxc

import (
	"context"
	"strings"

	"github.com/footprintai/containarium/pkg/core/box"
	"github.com/footprintai/containarium/pkg/core/container"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Backend adapts a *container.Manager to box.BoxBackend.
type Backend struct {
	mgr *container.Manager
}

// Compile-time assertions: Backend satisfies the core interface and the
// optional capabilities LXC supports.
var (
	_ box.BoxBackend     = (*Backend)(nil)
	_ box.ExecCapable    = (*Backend)(nil)
	_ box.MetricsCapable = (*Backend)(nil)
)

// New returns an LXC backend wrapping the given Manager.
func New(mgr *container.Manager) *Backend {
	return &Backend{mgr: mgr}
}

// Kind reports the LXC substrate.
func (b *Backend) Kind() box.BackendKind { return box.KindLXC }

// Create makes a container matching spec exist and returns its status.
func (b *Backend) Create(_ context.Context, spec box.BoxSpec) (*box.BoxStatus, error) {
	info, err := b.mgr.Create(specToCreateOptions(spec))
	if err != nil {
		return nil, err
	}
	st := StatusFromInfo(info)
	return &st, nil
}

// Start starts a stopped container.
func (b *Backend) Start(_ context.Context, ref box.BoxRef) error {
	return b.mgr.Start(ref.Tenant)
}

// Stop stops a running container.
func (b *Backend) Stop(_ context.Context, ref box.BoxRef, force bool) error {
	return b.mgr.Stop(ref.Tenant, force)
}

// Delete removes a container, stopping it first if running.
func (b *Backend) Delete(_ context.Context, ref box.BoxRef, force bool) error {
	return b.mgr.Delete(ref.Tenant, force)
}

// Get returns the status of a container, or (nil, nil) if it does not exist.
func (b *Backend) Get(_ context.Context, ref box.BoxRef) (*box.BoxStatus, error) {
	info, err := b.mgr.Get(ref.Tenant)
	if err != nil {
		return nil, err
	}
	if info == nil {
		return nil, nil
	}
	st := StatusFromInfo(info)
	return &st, nil
}

// List returns the status of every container the Manager sees.
func (b *Backend) List(_ context.Context) ([]box.BoxStatus, error) {
	infos, err := b.mgr.List()
	if err != nil {
		return nil, err
	}
	out := make([]box.BoxStatus, 0, len(infos))
	for i := range infos {
		out = append(out, StatusFromInfo(&infos[i]))
	}
	return out, nil
}

// Resolve reports how an agent reaches the container over SSH. The LXC backend
// knows only the box's direct IP and routing user; the gateway/sentinel host
// is stamped above the seam by the server (from the daemon's --ssh-host flag).
func (b *Backend) Resolve(ctx context.Context, ref box.BoxRef) (*box.BoxEndpoint, error) {
	st, err := b.Get(ctx, ref)
	if err != nil {
		return nil, err
	}
	if st == nil {
		return nil, nil
	}
	return &box.BoxEndpoint{
		SSHUser:    st.Ref.Tenant,
		DirectIP:   st.IPAddress,
		AccessType: pb.AccessType_ACCESS_TYPE_SSH,
	}, nil
}

// SetAuthorizedKeys sets the container's authorized SSH keys to exactly the
// given set.
func (b *Backend) SetAuthorizedKeys(_ context.Context, ref box.BoxRef, keys []string) error {
	return b.mgr.SetAuthorizedKeys(ref.Tenant, keys)
}

// Resize updates the container's resource limits; empty fields are unchanged.
func (b *Backend) Resize(_ context.Context, ref box.BoxRef, r box.ResourceLimits) error {
	return b.mgr.Resize(containerName(ref), r.CPU, r.Memory, r.Disk, false)
}

// SetMeta replaces the container's labels (the runtime-neutral metadata LXC
// supports today; TTL/delete-policy route through dedicated server methods
// pending follow-up).
func (b *Backend) SetMeta(_ context.Context, ref box.BoxRef, meta map[string]string) error {
	return b.mgr.SetLabels(ref.Tenant, meta)
}

// GetMeta reads the container's labels.
func (b *Backend) GetMeta(_ context.Context, ref box.BoxRef) (map[string]string, error) {
	return b.mgr.GetLabels(ref.Tenant)
}

// Exec runs a command inside the container and returns its output.
// Implements box.ExecCapable.
func (b *Backend) Exec(_ context.Context, ref box.BoxRef, cmd []string) (string, string, error) {
	return b.mgr.ExecWithOutput(containerName(ref), cmd)
}

// WriteFile writes a file inside the container. Implements box.ExecCapable.
func (b *Backend) WriteFile(_ context.Context, ref box.BoxRef, path string, content []byte, mode string) error {
	return b.mgr.WriteFile(containerName(ref), path, content, mode)
}

// Metrics returns runtime metrics for the container. Implements
// box.MetricsCapable.
func (b *Backend) Metrics(_ context.Context, ref box.BoxRef) (*box.BoxMetrics, error) {
	m, err := b.mgr.GetMetrics(ref.Tenant)
	if err != nil {
		return nil, err
	}
	if m == nil {
		return nil, nil
	}
	return &box.BoxMetrics{
		CPUUsageSeconds:  m.CPUUsageSeconds,
		MemoryUsageBytes: m.MemoryUsageBytes,
		MemoryLimitBytes: m.MemoryLimitBytes,
		DiskUsageBytes:   m.DiskUsageBytes,
		NetworkRxBytes:   m.NetworkRxBytes,
		NetworkTxBytes:   m.NetworkTxBytes,
		ProcessCount:     m.ProcessCount,
	}, nil
}

// --- pure mapping helpers (unit-tested directly) ---

// specToCreateOptions maps the runtime-neutral spec onto the Manager's
// CreateOptions.
func specToCreateOptions(spec box.BoxSpec) container.CreateOptions {
	return container.CreateOptions{
		Username:               spec.Ref.Tenant,
		Image:                  spec.Image,
		CPU:                    spec.Resources.CPU,
		Memory:                 spec.Resources.Memory,
		Disk:                   spec.Resources.Disk,
		GPUs:                   spec.GPUs,
		SSHKeys:                spec.SSHKeys,
		Labels:                 spec.Labels,
		StaticIP:               spec.StaticIP,
		EnablePodman:           spec.EnablePodman,
		EnablePodmanPrivileged: spec.EnablePodmanPrivileged,
		OSType:                 spec.OSType,
		Monitoring:             spec.Monitoring,
		OTelCollectorEndpoint:  spec.OTelCollectorEndpoint,
		BackendID:              spec.OTelBackendID,
		OTelBearer:             spec.OTelBearer,
		Stack:                  spec.Stack,
		StackParameters:        spec.StackParams,
		GitSource:              spec.GitSource,
		GitRef:                 spec.GitRef,
		GitCredential:          spec.GitCredential,
		WorkspacePath:          spec.WorkspacePath,
		AutoStart:              spec.AutoStart,
		OnProvisioning:         spec.OnProvisioning,
	}
}

// StatusFromInfo maps incus.ContainerInfo onto the runtime-neutral BoxStatus.
func StatusFromInfo(info *incus.ContainerInfo) box.BoxStatus {
	return box.BoxStatus{
		Ref:                       box.BoxRef{Tenant: tenantOf(info), Name: info.Name},
		State:                     parseState(info.State),
		IPAddress:                 info.IPAddress,
		Resources:                 box.ResourceLimits{CPU: info.CPU, Memory: info.Memory, Disk: info.Disk},
		Labels:                    info.Labels,
		GPU:                       info.GPU,
		GPUs:                      info.GPUs,
		BackendID:                 info.BackendID,
		CreatedAt:                 info.CreatedAt,
		IsCore:                    info.Role.IsCoreRole(),
		MonitoringEnabled:         info.MonitoringEnabled,
		AutoSleepEnabled:          info.AutoSleepEnabled,
		IdleThresholdMinutes:      info.IdleThresholdMinutes,
		TTLExpiresAt:              info.TTLExpiresAt,
		StoppedAt:                 info.StoppedAt,
		DeleteAfterStoppedSeconds: info.DeleteAfterStoppedSeconds,
		DeletePolicy:              info.DeletePolicy,
		Image:                     info.Image,
	}
}

// parseState maps an incus state string to the proto enum. Mirrors the
// daemon's toProtoContainer mapping so the seam reports identical states.
func parseState(s string) pb.ContainerState {
	switch s {
	case "Running":
		return pb.ContainerState_CONTAINER_STATE_RUNNING
	case "Stopped":
		return pb.ContainerState_CONTAINER_STATE_STOPPED
	case "Frozen":
		return pb.ContainerState_CONTAINER_STATE_FROZEN
	default:
		return pb.ContainerState_CONTAINER_STATE_UNSPECIFIED
	}
}

// tenantOf recovers the routing user/tenant from container info: the daemon's
// reported Username when present, else the name with the "-container" suffix
// stripped (the create-time naming convention).
func tenantOf(info *incus.ContainerInfo) string {
	if info.Username != "" {
		return info.Username
	}
	return strings.TrimSuffix(info.Name, "-container")
}

// containerName resolves the substrate-level container name for a ref: the
// explicit Name when set, else derived from Tenant via the naming convention.
func containerName(ref box.BoxRef) string {
	if ref.Name != "" {
		return ref.Name
	}
	return ref.Tenant + "-container"
}
