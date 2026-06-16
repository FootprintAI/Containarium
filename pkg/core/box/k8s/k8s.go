//go:build k8s

package k8s

import (
	"context"
	"errors"

	"github.com/footprintai/containarium/pkg/core/box"
)

// ErrNotImplemented is returned by every Backend method until the real
// reconciliation lands. It lets the skeleton satisfy box.BoxBackend (and
// compile under -tags k8s) without pulling in client-go yet.
var ErrNotImplemented = errors.New("k8s box backend: not implemented (skeleton)")

// Config is the K8s backend's wiring. It is supplied at daemon start when the
// `k8s` build variant selects this backend. Field values map onto the design
// note's topology (docs/K8S-AGENT-BOX-RUNTIME-DESIGN.md).
type Config struct {
	// Kubeconfig is the path to a kubeconfig file. Empty means in-cluster
	// config (the daemon runs as a pod with a mounted ServiceAccount).
	Kubeconfig string

	// GatewayNamespace is where the in-cluster sshpiper Deployment + its
	// LoadBalancer Service live (the `agent-gateway` namespace).
	GatewayNamespace string

	// GatewayHost / GatewaySSHPort is the public SSH endpoint agents connect
	// to — the sshpiper LB. Surfaced in BoxEndpoint.SSHHost/SSHPort so the
	// server can build the connect target without inferring it.
	GatewayHost    string
	GatewaySSHPort int

	// TenantNamespacePrefix prefixes the per-tenant namespace
	// (e.g. "tenant-" → "tenant-<tenant>"); namespace-per-tenant +
	// default-deny NetworkPolicy is the v1 isolation model.
	TenantNamespacePrefix string

	// BoxImage is the agent-box image (sshd + agent-box, ForceCommand-pinned)
	// the per-tenant StatefulSet runs.
	BoxImage string

	// StorageClass is the StorageClass for the box's PVC (empty = cluster
	// default).
	StorageClass string
}

// Backend implements box.BoxBackend on Kubernetes.
//
// Capability note: this backend deliberately does NOT implement
// box.ExecCapable — the K8s agent-box is pinned by sshd ForceCommand and its
// provisioning is image-baked, so there is no in-box exec/file-push seam (the
// LXC backend's incus-exec path has no K8s analog). box.MetricsCapable and
// box.GPUCapable are likewise deferred. Callers discover all of this by type
// assertion, exactly as the seam intends.
type Backend struct {
	cfg Config
	// clientset kubernetes.Interface — wired when client-go lands (follow-up).
}

// Compile-time assertion: the skeleton satisfies the core interface.
var _ box.BoxBackend = (*Backend)(nil)

// New constructs a K8s backend from cfg. The real implementation builds a
// client-go clientset (in-cluster or from cfg.Kubeconfig) and verifies the
// gateway namespace + PiperUpstream CRD are present; the skeleton just holds
// the config.
func New(cfg Config) (*Backend, error) {
	return &Backend{cfg: cfg}, nil
}

// Kind reports the Kubernetes substrate.
func (b *Backend) Kind() box.BackendKind { return box.KindK8s }

// Create will template the per-tenant namespace + StatefulSet (box-0) +
// headless Service + default-deny NetworkPolicy + per-tenant key Secret, and
// program the sshpiper PiperUpstream so the gateway routes username→pod.
func (b *Backend) Create(ctx context.Context, spec box.BoxSpec) (*box.BoxStatus, error) {
	return nil, ErrNotImplemented
}

// Start will scale the tenant's StatefulSet to 1 replica.
func (b *Backend) Start(ctx context.Context, ref box.BoxRef) error {
	return ErrNotImplemented
}

// Stop will scale the tenant's StatefulSet to 0 replicas.
func (b *Backend) Stop(ctx context.Context, ref box.BoxRef, force bool) error {
	return ErrNotImplemented
}

// Delete will remove the StatefulSet/Service/Secret/NetworkPolicy and the
// PiperUpstream entry (and the tenant namespace when the backend owns it).
func (b *Backend) Delete(ctx context.Context, ref box.BoxRef, force bool) error {
	return ErrNotImplemented
}

// Get will read the StatefulSet pod + its annotations into a BoxStatus.
func (b *Backend) Get(ctx context.Context, ref box.BoxRef) (*box.BoxStatus, error) {
	return nil, ErrNotImplemented
}

// List will enumerate every per-tenant StatefulSet this backend manages.
func (b *Backend) List(ctx context.Context) ([]box.BoxStatus, error) {
	return nil, ErrNotImplemented
}

// Resolve will report the gateway SSH endpoint (cfg.GatewayHost:GatewaySSHPort,
// SSHUser = tenant) that sshpiper routes to the tenant's pod.
func (b *Backend) Resolve(ctx context.Context, ref box.BoxRef) (*box.BoxEndpoint, error) {
	return nil, ErrNotImplemented
}

// SetAuthorizedKeys will reconcile the tenant's authorized key into the
// per-tenant Secret (and ensure the matching PiperUpstream entry).
func (b *Backend) SetAuthorizedKeys(ctx context.Context, ref box.BoxRef, keys []string) error {
	return ErrNotImplemented
}

// Resize will patch the StatefulSet pod template's resource requests/limits.
func (b *Backend) Resize(ctx context.Context, ref box.BoxRef, r box.ResourceLimits) error {
	return ErrNotImplemented
}

// SetMeta will write the runtime-neutral metadata as pod annotations/labels.
func (b *Backend) SetMeta(ctx context.Context, ref box.BoxRef, meta map[string]string) error {
	return ErrNotImplemented
}

// GetMeta will read the pod's annotations/labels back into the metadata map.
func (b *Backend) GetMeta(ctx context.Context, ref box.BoxRef) (map[string]string, error) {
	return nil, ErrNotImplemented
}
