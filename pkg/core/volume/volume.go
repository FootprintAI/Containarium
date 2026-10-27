// Package volume defines the runtime-neutral shared-volume service and the
// existing Incus/CephFS implementation (#384).
//
// The Incus Manager is capability-gated: create/attach are rejected unless
// the host has a `cephfs` Incus storage pool. The Kubernetes box backend
// implements Backend using an operator-selected RWX-capable CSI class.
//
// The Manager shells out to the `incus` CLI (the project's existing
// storage path). The command construction, CSV parsing, and capability
// detection are pure functions; the actual exec requires a live Ceph-backed
// Incus cluster.
package volume

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// ContentTypeFilesystem is the Incus content type of a shared volume.
const ContentTypeFilesystem = "filesystem"

// cephfsDriver is the Incus storage driver that supports concurrent RW.
const cephfsDriver = "cephfs"

// Runner executes `incus <args...>` and returns combined output. Injected
// so tests can supply a fake without a live cluster.
type Runner interface {
	Run(args ...string) (string, error)
}

// Attachment is one container a volume is mounted into.
type Attachment struct {
	Container string
	MountPath string
	ReadOnly  bool
}

// Volume is a CephFS custom filesystem volume.
type Volume struct {
	Name        string
	Pool        string
	SizeBytes   int64
	ContentType string
	Attachments []Attachment
}

// Backend is the runtime-neutral shared-volume service used by the gRPC
// surface. tenant scopes volumes on backends whose storage is namespaced.
type Backend interface {
	SharedVolumesSupported(ctx context.Context, tenant string) (pool string, ok bool, detail string)
	CreateVolume(ctx context.Context, tenant, name string, sizeBytes int64, pool string) (*Volume, error)
	ListVolumes(ctx context.Context, tenant, pool string) ([]Volume, error)
	GetVolume(ctx context.Context, tenant, name, pool string) (*Volume, error)
	DeleteVolume(ctx context.Context, tenant, name, pool string, force bool) error
	AttachVolume(ctx context.Context, tenant, name, pool, container, mountPath string, readOnly bool) error
	DetachVolume(ctx context.Context, tenant, name, container string) error
}

// Manager orchestrates volume lifecycle over the incus CLI.
type Manager struct {
	run Runner
}

// NewManager constructs a Manager.
func NewManager(r Runner) *Manager { return &Manager{run: r} }

// IncusBackend adapts the existing CephFS Manager to the runtime-neutral
// shared-volume service. Incus volumes are host-scoped, so tenant is ignored.
type IncusBackend struct{ Manager *Manager }

func (b IncusBackend) SharedVolumesSupported(_ context.Context, _ string) (string, bool, string) {
	return b.Manager.SharedVolumesSupported()
}

func (b IncusBackend) CreateVolume(_ context.Context, _ string, name string, sizeBytes int64, pool string) (*Volume, error) {
	return b.Manager.Create(name, sizeBytes, pool)
}

func (b IncusBackend) ListVolumes(_ context.Context, _ string, pool string) ([]Volume, error) {
	return b.Manager.List(pool)
}

func (b IncusBackend) GetVolume(_ context.Context, _ string, name, pool string) (*Volume, error) {
	return b.Manager.Get(name, pool)
}

func (b IncusBackend) DeleteVolume(_ context.Context, _ string, name, pool string, force bool) error {
	return b.Manager.Delete(name, pool, force)
}

func (b IncusBackend) AttachVolume(_ context.Context, _ string, name, pool, container, mountPath string, readOnly bool) error {
	return b.Manager.Attach(name, pool, container, mountPath, readOnly)
}

func (b IncusBackend) DetachVolume(_ context.Context, _ string, name, container string) error {
	return b.Manager.Detach(name, container)
}

// CephfsPools returns the names of cephfs-backed storage pools on this host.
func (m *Manager) CephfsPools() ([]string, error) {
	out, err := m.run.Run("storage", "list", "--format", "csv")
	if err != nil {
		return nil, fmt.Errorf("list storage pools: %w", err)
	}
	return parseCephfsPools(out), nil
}

// SharedVolumesSupported reports whether this host can serve shared volumes
// (a cephfs pool exists), returning the first such pool and a human detail.
func (m *Manager) SharedVolumesSupported() (pool string, ok bool, detail string) {
	pools, err := m.CephfsPools()
	if err != nil {
		return "", false, fmt.Sprintf("could not query storage pools: %v", err)
	}
	if len(pools) == 0 {
		return "", false, "no CephFS storage pool on this backend; shared (multi-writer) volumes require an Incus cluster on Ceph"
	}
	return pools[0], true, "CephFS pool: " + pools[0]
}

// resolvePool returns the pool to operate on: the requested one if given,
// else the detected default cephfs pool. Errors when shared volumes are
// unsupported — the capability gate.
func (m *Manager) resolvePool(requested string) (string, error) {
	if requested != "" {
		return requested, nil
	}
	pool, ok, detail := m.SharedVolumesSupported()
	if !ok {
		return "", fmt.Errorf("%s", detail)
	}
	return pool, nil
}

// Create provisions a CephFS custom filesystem volume with a quota.
func (m *Manager) Create(name string, sizeBytes int64, pool string) (*Volume, error) {
	if name == "" {
		return nil, fmt.Errorf("volume name is required")
	}
	if sizeBytes <= 0 {
		return nil, fmt.Errorf("size_bytes must be > 0 (a shared scratch space needs a quota)")
	}
	p, err := m.resolvePool(pool)
	if err != nil {
		return nil, err
	}
	if _, err := m.run.Run(createVolumeArgs(p, name, sizeBytes)...); err != nil {
		return nil, fmt.Errorf("create volume: %w", err)
	}
	return &Volume{Name: name, Pool: p, SizeBytes: sizeBytes, ContentType: ContentTypeFilesystem}, nil
}

// List returns the custom volumes in the pool (or detected default).
func (m *Manager) List(pool string) ([]Volume, error) {
	p, err := m.resolvePool(pool)
	if err != nil {
		return nil, err
	}
	out, err := m.run.Run("storage", "volume", "list", p, "--format", "csv")
	if err != nil {
		return nil, fmt.Errorf("list volumes: %w", err)
	}
	return parseVolumeList(out, p), nil
}

// Get returns a single volume by name.
func (m *Manager) Get(name, pool string) (*Volume, error) {
	if name == "" {
		return nil, fmt.Errorf("volume name is required")
	}
	vols, err := m.List(pool)
	if err != nil {
		return nil, err
	}
	for i := range vols {
		if vols[i].Name == name {
			return &vols[i], nil
		}
	}
	return nil, fmt.Errorf("volume %q not found", name)
}

// Delete removes a volume. Without force it refuses while the volume is
// still attached (Incus also refuses, but we surface a clearer error).
func (m *Manager) Delete(name, pool string, force bool) error {
	if name == "" {
		return fmt.Errorf("volume name is required")
	}
	p, err := m.resolvePool(pool)
	if err != nil {
		return err
	}
	if !force {
		if v, err := m.Get(name, p); err == nil && len(v.Attachments) > 0 {
			return fmt.Errorf("volume %q is still attached to %d container(s); detach first or pass force", name, len(v.Attachments))
		}
	}
	if _, err := m.run.Run("storage", "volume", "delete", p, name); err != nil {
		return fmt.Errorf("delete volume: %w", err)
	}
	return nil
}

// Attach mounts a volume into a container. Read-write by default; multiple
// containers may attach the same volume RW concurrently (CephFS coordinates).
func (m *Manager) Attach(volume, pool, container, mountPath string, readOnly bool) error {
	if volume == "" || container == "" || mountPath == "" {
		return fmt.Errorf("volume, container, and mount_path are required")
	}
	p, err := m.resolvePool(pool)
	if err != nil {
		return err
	}
	if _, err := m.run.Run(attachArgs(container, DeviceName(volume), p, volume, mountPath, readOnly)...); err != nil {
		return fmt.Errorf("attach volume: %w", err)
	}
	return nil
}

// Detach removes a volume's mount from a container.
func (m *Manager) Detach(volume, container string) error {
	if volume == "" || container == "" {
		return fmt.Errorf("volume and container are required")
	}
	if _, err := m.run.Run("config", "device", "remove", container, DeviceName(volume)); err != nil {
		return fmt.Errorf("detach volume: %w", err)
	}
	return nil
}

// --- pure helpers (unit-tested) ---

// createVolumeArgs builds the `incus storage volume create` argv. The
// `size=` config maps to ceph.quota.max_bytes for a cephfs volume.
func createVolumeArgs(pool, name string, sizeBytes int64) []string {
	return []string{"storage", "volume", "create", pool, name, "size=" + strconv.FormatInt(sizeBytes, 10)}
}

// attachArgs builds the `incus config device add` argv that mounts a
// custom volume into a container as a disk device.
func attachArgs(container, device, pool, volume, mountPath string, readOnly bool) []string {
	args := []string{
		"config", "device", "add", container, device, "disk",
		"pool=" + pool,
		"source=" + volume,
		"path=" + mountPath,
	}
	if readOnly {
		args = append(args, "readonly=true")
	}
	return args
}

// DeviceName is the deterministic Incus device name used for a volume's
// mount, so Attach/Detach agree without extra bookkeeping.
func DeviceName(volume string) string {
	return "vol-" + volume
}

// parseCephfsPools extracts cephfs pool names from `incus storage list
// --format csv` output. The CSV has no header; column 0 is the pool name,
// column 1 the driver.
func parseCephfsPools(csv string) []string {
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(csv), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Split(line, ",")
		if len(fields) >= 2 && strings.TrimSpace(fields[1]) == cephfsDriver {
			out = append(out, strings.TrimSpace(fields[0]))
		}
	}
	return out
}

// parseVolumeList extracts custom volumes from `incus storage volume list
// <pool> --format csv`. The CSV has no header; columns are
// TYPE,NAME,DESCRIPTION,CONTENT-TYPE,USED-BY. Only custom volumes are
// returned. Size and attachments are not parsed here (they need a
// per-volume `storage volume show`); callers treat them as best-effort.
func parseVolumeList(csv, pool string) []Volume {
	var out []Volume
	for _, line := range strings.Split(strings.TrimSpace(csv), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Split(line, ",")
		if len(fields) < 2 || strings.TrimSpace(fields[0]) != "custom" {
			continue
		}
		v := Volume{Name: strings.TrimSpace(fields[1]), Pool: pool, ContentType: ContentTypeFilesystem}
		if len(fields) >= 4 && strings.TrimSpace(fields[3]) != "" {
			v.ContentType = strings.TrimSpace(fields[3])
		}
		out = append(out, v)
	}
	return out
}
