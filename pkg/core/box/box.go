// Package box defines the runtime-neutral seam between the daemon and the
// substrate a box runs on. Today the only implementation is LXC/incus
// (pkg/core/box/lxc), which wraps the existing container.Manager with no
// behavior change. A Kubernetes implementation lands against this same
// contract behind a build tag — see docs/K8S-AGENT-BOX-RUNTIME-DESIGN.md.
//
// The seam sits one altitude *above* incus.Backend on purpose: incus.Backend
// is a leaky, LXC-shaped interface (Exec, WriteFile, ResolveGPUInputToPCI,
// raw config-key writes) that a non-incus runtime cannot implement cleanly.
// BoxBackend is coarse-grained — lifecycle, addressing, SSH identity, and
// metadata — and lets each runtime realize those however it must.
package box

import (
	"context"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// BackendKind identifies the substrate a BoxBackend manages.
type BackendKind string

const (
	// KindLXC is the LXC/incus backend (today's default).
	KindLXC BackendKind = "lxc"
	// KindK8s is the Kubernetes backend (behind the `k8s` build tag).
	KindK8s BackendKind = "k8s"
)

// BoxRef names a box independent of runtime. Tenant is the routing key / SSH
// username the daemon's SSH front routes by; Name is the substrate-level
// object name (LXC: "<tenant>-container"; K8s: the StatefulSet pod "box-0").
// Name may be empty on input — an implementation derives it from Tenant via
// its own naming convention — and is always populated on values returned by
// the backend.
type BoxRef struct {
	Tenant string
	Name   string
}

// ResourceLimits is the runtime-neutral form of a box's CPU/memory/disk
// request. Values are substrate-native strings (e.g. "2", "4GB", "20GB"); an
// empty field means "leave unchanged" on mutation and "unset" on read.
type ResourceLimits struct {
	CPU    string
	Memory string
	Disk   string
	// StorageClass is the K8s StorageClass for the box's data PVC.
	// Empty = use the backend's default (Config.StorageClass).
	// Only meaningful on the K8s backend; ignored by LXC.
	StorageClass string
}

// BoxSpec is the declarative input to Create. The backend makes a box matching
// the spec exist and returns a BoxStatus. Create must be idempotent on
// re-create (the agent-skills bring-up taught us this the hard way, #669).
type BoxSpec struct {
	Ref        BoxRef
	Image      string
	OSType     pb.OSType
	Resources  ResourceLimits
	GPUs       []string // empty on K8s v1 (deferred)
	SSHKeys    []string
	Labels     map[string]string
	StaticIP   string // empty = DHCP
	Monitoring bool

	// EnablePodman / EnablePodmanPrivileged request Docker/Podman support
	// inside the box (the privileged variant is gated by policy at the server
	// layer before it reaches here).
	EnablePodman           bool
	EnablePodmanPrivileged bool

	// Provisioning intent — NOT an exec script. The backend decides how to
	// realize it: LXC runs incus exec; K8s bakes it into the image / an init
	// container. Keeps stack-install runtime-specific, below the seam.
	Stack       string
	StackParams map[string]string

	// Git source provisioning (optional): the backend fetches the repo into
	// WorkspacePath at create time, no caller→box SSH.
	GitSource     string
	GitRef        string
	GitCredential string
	WorkspacePath string

	// Monitoring wiring, only meaningful when Monitoring is true. These are
	// daemon-runtime values the server supplies per-create (collector
	// endpoint, the originating backend's id for OTel resource attributes,
	// and the collector bearer). A K8s backend may ignore them.
	OTelCollectorEndpoint string
	OTelBackendID         string
	OTelBearer            string

	// AutoStart requests the box be started as part of Create.
	AutoStart bool

	// OnProvisioning, if set, is called once the box is running but still
	// installing packages/stack — the daemon uses it to flip async-create
	// state to "provisioning". A K8s backend may never call it.
	OnProvisioning func()
}

// BoxEndpoint describes how an agent reaches a box over SSH. The server turns
// it into Container.ssh_host and the displayed ssh command.
type BoxEndpoint struct {
	// SSHHost is the gateway/sentinel public host an agent connects to. Empty
	// means "direct IP mode" (no gateway in front) — the server may stamp the
	// daemon's configured gateway host above the seam when this is empty.
	SSHHost string
	// SSHPort is the gateway SSH port (22 via sshpiper); 0 means default.
	SSHPort int
	// SSHUser is the routing key the SSH front (sshpiper) routes by — the
	// tenant.
	SSHUser string
	// DirectIP is the box's own address, used when no gateway is in front.
	DirectIP string
	// AccessType distinguishes SSH from RDP (Windows VMs).
	AccessType pb.AccessType
}

// BoxStatus is the runtime-neutral view of a box, returned by Create / Get /
// List. It carries the box concepts the daemon reasons about (lifecycle,
// addressing, resources, and the metadata that LXC stores in
// user.containarium.* config keys and K8s would store in pod annotations).
// The backend is responsible for translating its substrate's native form into
// this shape — the server depends on BoxStatus, not on any incus type.
type BoxStatus struct {
	Ref       BoxRef
	State     pb.ContainerState
	IPAddress string
	Resources ResourceLimits
	Labels    map[string]string
	GPU       string   // first GPU device, for display/back-compat
	GPUs      []string // all attached GPU devices
	BackendID string   // which backend/peer the box runs on
	CreatedAt time.Time
	// IsCore marks an infrastructure box (the platform's own core services)
	// rather than a user/tenant box. The server's user-facing guards (TTL,
	// delete-policy, monitoring, auto-sleep are "for user containers only")
	// key off this. On LXC it's derived from the incus core-role label.
	IsCore bool

	// Lifecycle metadata (LXC: user.containarium.* config keys).
	MonitoringEnabled         bool
	AutoSleepEnabled          bool
	IdleThresholdMinutes      int32
	TTLExpiresAt              time.Time
	StoppedAt                 time.Time
	DeleteAfterStoppedSeconds int64
	DeletePolicy              string // "protected" or "" (unprotected)
}

// BoxMetrics is the runtime-neutral form of a box's runtime metrics.
type BoxMetrics struct {
	CPUUsageSeconds  int64
	MemoryUsageBytes int64
	MemoryLimitBytes int64
	DiskUsageBytes   int64
	NetworkRxBytes   int64
	NetworkTxBytes   int64
	ProcessCount     int32
}

// BoxBackend is the runtime-neutral seam. LXC/incus and Kubernetes both
// implement it. It is coarse-grained on purpose — no Exec/WriteFile/config-key
// leakage. ctx is threaded for the K8s client; the LXC implementation ignores
// it (its incus client predates ctx plumbing).
type BoxBackend interface {
	// Kind reports which substrate this backend manages.
	Kind() BackendKind

	// Create makes a box matching spec exist and returns its status.
	// Idempotent on re-create.
	Create(ctx context.Context, spec BoxSpec) (*BoxStatus, error)
	// Start starts a stopped box.
	Start(ctx context.Context, ref BoxRef) error
	// Stop stops a running box; force skips graceful shutdown.
	Stop(ctx context.Context, ref BoxRef, force bool) error
	// Delete removes a box; force stops it first if running.
	Delete(ctx context.Context, ref BoxRef, force bool) error

	// Get returns the current status of a box, or (nil, nil) if it does not
	// exist.
	Get(ctx context.Context, ref BoxRef) (*BoxStatus, error)
	// List returns the status of every box this backend manages.
	List(ctx context.Context) ([]BoxStatus, error)

	// Resolve reports how an agent reaches the box over SSH. This is the
	// method that makes the K8s value real (gateway host + routing user); on
	// LXC it reports the direct IP, with the gateway host stamped above the
	// seam.
	Resolve(ctx context.Context, ref BoxRef) (*BoxEndpoint, error)

	// SetAuthorizedKeys sets the box's authorized SSH keys to exactly the
	// given set. Lives below the seam because the mechanism differs per
	// runtime: LXC writes the box's authorized_keys; K8s reconciles the
	// per-tenant Secret + PiperUpstream.
	SetAuthorizedKeys(ctx context.Context, ref BoxRef, keys []string) error

	// Resize updates the box's resource limits; empty fields are left
	// unchanged.
	Resize(ctx context.Context, ref BoxRef, r ResourceLimits) error

	// SetMeta replaces the box's runtime-neutral metadata.
	SetMeta(ctx context.Context, ref BoxRef, meta map[string]string) error
	// GetMeta reads the box's runtime-neutral metadata.
	GetMeta(ctx context.Context, ref BoxRef) (map[string]string, error)
}

// ExecCapable is an optional capability for in-box exec and file seeding.
// LXC implements it (incus exec / file push). The K8s agent-box is pinned by
// ForceCommand, so a K8s backend may NOT implement it — provisioning is
// image-baked. Discover support with a type assertion.
type ExecCapable interface {
	Exec(ctx context.Context, ref BoxRef, cmd []string) (stdout, stderr string, err error)
	WriteFile(ctx context.Context, ref BoxRef, path string, content []byte, mode string) error
}

// MetricsCapable is an optional capability for per-box runtime metrics.
type MetricsCapable interface {
	Metrics(ctx context.Context, ref BoxRef) (*BoxMetrics, error)
}

// GPUCapable is an optional capability for resolving a user-supplied GPU
// identifier to a stable device ID. LXC implements it; K8s GPU support is
// deferred.
type GPUCapable interface {
	ResolveGPU(ctx context.Context, input string) (deviceID string, err error)
}
