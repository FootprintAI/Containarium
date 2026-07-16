package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	sandboxv1beta1 "sigs.k8s.io/agent-sandbox/api/v1beta1"
	sandboxclient "sigs.k8s.io/agent-sandbox/clients/k8s/clientset/versioned"

	"github.com/footprintai/containarium/pkg/core/box"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Config is the K8s backend's wiring, supplied at daemon start when
// CONTAINARIUM_RUNTIME=k8s selects this backend. See
// docs/K8S-AGENT-BOX-RUNTIME-DESIGN.md.
type Config struct {
	// Kubeconfig is the path to a kubeconfig file. Empty means: try in-cluster
	// config, then the ambient loading rules ($KUBECONFIG / ~/.kube/config).
	Kubeconfig string

	// GatewayNamespace is where the sshpiper Deployment + its LB Service live.
	GatewayNamespace string

	// GatewayHost / GatewaySSHPort is the public SSH endpoint agents connect to
	// (the sshpiper LB), surfaced in BoxEndpoint so the server builds the
	// connect target without inferring it.
	GatewayHost    string
	GatewaySSHPort int

	// GatewayService is the in-cluster sshpiper Service name in
	// GatewayNamespace, used to resolve the node's SSH ingress (NodePort)
	// advertised to the sentinel. Defaults to "sshpiper".
	GatewayService string

	// GatewayAdvertisePort overrides the resolved ingress port advertised
	// to the sentinel (0 = resolve from GatewayService).
	GatewayAdvertisePort int

	// TenantNamespacePrefix prefixes the per-tenant namespace
	// (e.g. "tenant-" → "tenant-<tenant>"). Defaults to "tenant-".
	TenantNamespacePrefix string

	// BoxImage is the agent-box image (sshd + agent-box) the box runs.
	BoxImage string

	// BoxMode is passed to the box as the AGENTBOX_MODE env var: "" or "mcp"
	// keeps the forced-command MCP session (default), "shell" gives the box an
	// interactive login shell (developer-box). Empty leaves the image default.
	BoxMode string

	// StorageClass is reserved for the box PVC (not wired in this slice).
	StorageClass string

	// DefaultMemoryRequest / DefaultMemoryLimit override the built-in per-box
	// memory floor applied when a box's spec carries no valid memory quantity.
	// The request (scheduler reservation) is kept below the limit (hard cap) so
	// idle boxes pack densely on the shared host kernel while the limit stops any
	// one box ballooning and pressuring its neighbors (noisy-neighbor). Empty →
	// the built-in defaults (defaultMemoryRequest / defaultMemoryLimit); a value
	// that isn't a valid K8s quantity also falls back to the built-in default.
	// These are cluster-size specific — tune to the node pool (e.g. "512Mi",
	// "2Gi"). Ignored when DisableDefaultMemoryFloor is set.
	DefaultMemoryRequest string
	DefaultMemoryLimit   string

	// DisableDefaultMemoryFloor turns the automatic per-box memory floor off
	// entirely: boxes with no explicit memory run unconstrained (the pre-floor
	// behavior). An escape hatch for dedicated / single-tenant nodes; on shared
	// nodes it lets a box balloon, so it is not recommended there.
	DisableDefaultMemoryFloor bool

	// Gateway upstream credential (sshpiper → box hop). sshpiper terminates the
	// client connection and opens a NEW connection to the box as user `agent`,
	// authenticating with its own key. So:
	//   - GatewayUpstreamPublicKey is authorized ON each box (sshpiper logs in).
	//   - GatewayUpstreamKeySecret is the Secret in GatewayNamespace holding the
	//     matching private key, referenced by each Pipe's spec.to.private_key_secret.
	// The agent's own keys (spec.SSHKeys) authenticate client→gateway via the
	// Pipe's spec.from.authorized_keys_data. When these are unset, boxes
	// authorize the agent keys directly (no-gateway / direct-SSH mode).
	GatewayUpstreamPublicKey string
	GatewayUpstreamKeySecret string

	// InsecureIgnoreHostKey keeps the pre-pinning behavior (the Pipe sets
	// ignore_hostkey instead of pinning the box's host key via known_hosts_data).
	// Default false = pin. An escape hatch, not the recommended posture.
	InsecureIgnoreHostKey bool
}

// Backend implements box.BoxBackend on Kubernetes, on top of the
// kubernetes-sigs/agent-sandbox Sandbox CRD: the daemon owns the per-tenant
// namespace, Secrets, NetworkPolicy, data PVC, and gateway Pipe, and declares
// one Sandbox CR per box — the agent-sandbox controller owns the pod and the
// headless Service under it. The controller must be installed in the cluster
// (its v0.5.1 release asset `manifest.yaml`).
//
// Capability note: it deliberately does NOT implement box.ExecCapable — the
// K8s agent-box is ForceCommand-pinned and provisioning is image-baked, so
// there is no in-box exec seam. box.MetricsCapable / box.GPUCapable are
// deferred.
type Backend struct {
	cfg       Config
	clientset kubernetes.Interface
	sandboxes sandboxclient.Interface
	dyn       dynamic.Interface // for the sshpiper Pipe CRD; nil disables gateway routing
	router    gatewayRouter     // SSH-gateway routing seam; sshpiperRouter today
}

var _ box.BoxBackend = (*Backend)(nil)

// New constructs a K8s backend: it builds a client-go clientset, the
// agent-sandbox typed clientset, and a dynamic client (in-cluster, an explicit
// kubeconfig, or the ambient rules) and applies config defaults.
func New(cfg Config) (*Backend, error) {
	restCfg, err := buildRestConfig(cfg.Kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("k8s: build rest config: %w", err)
	}
	cs, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("k8s: build clientset: %w", err)
	}
	sc, err := sandboxclient.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("k8s: build agent-sandbox clientset: %w", err)
	}
	dyn, err := dynamic.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("k8s: build dynamic client: %w", err)
	}
	return newBackend(cs, sc, dyn, cfg), nil
}

// NewWithClientset builds a Backend over injected clientsets, with gateway
// (Pipe) routing disabled (no dynamic client). Used by lifecycle unit tests.
func NewWithClientset(cs kubernetes.Interface, sc sandboxclient.Interface, cfg Config) *Backend {
	return newBackend(cs, sc, nil, cfg)
}

// NewWithClients builds a Backend over injected clientsets + dynamic client
// (fakes for unit tests, a kind cluster for e2e), exercising gateway routing.
func NewWithClients(cs kubernetes.Interface, sc sandboxclient.Interface, dyn dynamic.Interface, cfg Config) *Backend {
	return newBackend(cs, sc, dyn, cfg)
}

func newBackend(cs kubernetes.Interface, sc sandboxclient.Interface, dyn dynamic.Interface, cfg Config) *Backend {
	if cfg.TenantNamespacePrefix == "" {
		cfg.TenantNamespacePrefix = "tenant-"
	}
	if cfg.GatewaySSHPort == 0 {
		cfg.GatewaySSHPort = 22
	}
	if cfg.GatewayService == "" {
		cfg.GatewayService = "sshpiper"
	}
	// Resolve the default memory floor once: built-in defaults when unset, the
	// built-in default when an operator value isn't a valid K8s quantity (a typo
	// degrades to the safe floor rather than silently leaving boxes unconstrained),
	// or cleared entirely when explicitly disabled. The object builders then
	// consume the resolved, pre-validated strings via b.memDefaults().
	if cfg.DisableDefaultMemoryFloor {
		cfg.DefaultMemoryRequest, cfg.DefaultMemoryLimit = "", ""
	} else {
		cfg.DefaultMemoryRequest = resolveQuantity(cfg.DefaultMemoryRequest, defaultMemoryRequest)
		cfg.DefaultMemoryLimit = resolveQuantity(cfg.DefaultMemoryLimit, defaultMemoryLimit)
	}
	b := &Backend{cfg: cfg, clientset: cs, sandboxes: sc, dyn: dyn}
	b.router = &sshpiperRouter{b: b}
	return b
}

// resolveQuantity returns v when it is a valid K8s resource quantity, else the
// fallback. Used to validate operator-supplied Config defaults at construction
// so the object builders can MustParse them safely.
func resolveQuantity(v, fallback string) string {
	if v == "" {
		return fallback
	}
	if _, err := resource.ParseQuantity(v); err != nil {
		return fallback
	}
	return v
}

// memDefaults returns the resolved cluster-wide default memory floor consumed by
// the object builders. An empty limit (when DisableDefaultMemoryFloor is set)
// disables the floor.
func (b *Backend) memDefaults() memDefaults {
	return memDefaults{request: b.cfg.DefaultMemoryRequest, limit: b.cfg.DefaultMemoryLimit}
}

func buildRestConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	if c, err := rest.InClusterConfig(); err == nil {
		return c, nil
	}
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{}).ClientConfig()
}

func (b *Backend) Kind() box.BackendKind { return box.KindK8s }

func (b *Backend) namespaceFor(tenant string) string {
	return b.cfg.TenantNamespacePrefix + tenant
}

// Create reconciles the per-tenant namespace + Secrets + default-deny
// NetworkPolicy + the Sandbox CR, then returns the box's status. The
// agent-sandbox controller creates the pod and the headless Service from the
// Sandbox. Each step is idempotent (AlreadyExists is success) so re-create
// reuses the box rather than erroring (#669).
func (b *Backend) Create(ctx context.Context, spec box.BoxSpec) (*box.BoxStatus, error) {
	ns := b.namespaceFor(spec.Ref.Tenant)
	tenant := spec.Ref.Tenant
	if spec.Image == "" {
		spec.Image = b.cfg.BoxImage // default to the configured agent-box image
	}

	if _, err := b.clientset.CoreV1().Namespaces().Create(ctx, namespaceObject(ns, tenant), metav1.CreateOptions{}); ignoreExists(err) != nil {
		return nil, fmt.Errorf("k8s: ensure namespace: %w", err)
	}
	// Provision the data PVC before the Sandbox so the pod can mount it on
	// first start. Per-box spec.Resources.StorageClass takes precedence over the
	// global Config.StorageClass; skipped when both are empty (backward compat).
	storageClass := b.cfg.StorageClass
	if spec.Resources.StorageClass != "" {
		storageClass = spec.Resources.StorageClass
	}
	if storageClass != "" {
		pvc := pvcObject(ns, tenant, storageClass, spec.Resources.Disk)
		if _, err := b.clientset.CoreV1().PersistentVolumeClaims(ns).Create(ctx, pvc, metav1.CreateOptions{}); ignoreExists(err) != nil {
			return nil, fmt.Errorf("k8s: ensure pvc: %w", err)
		}
	}
	if _, err := b.clientset.CoreV1().Secrets(ns).Create(ctx, secretObject(ns, tenant, b.boxAuthorizedKeys(spec.SSHKeys), spec.SSHKeys), metav1.CreateOptions{}); ignoreExists(err) != nil {
		return nil, fmt.Errorf("k8s: ensure secret: %w", err)
	}
	if _, err := b.clientset.NetworkingV1().NetworkPolicies(ns).Create(ctx, networkPolicyObject(ns, tenant), metav1.CreateOptions{}); ignoreExists(err) != nil {
		return nil, fmt.Errorf("k8s: ensure networkpolicy: %w", err)
	}
	// Stable per-box host key Secret — created before the Sandbox, whose pod
	// mounts it (and dropbear uses it so the gateway can pin it).
	if _, err := b.ensureHostKey(ctx, tenant); err != nil {
		return nil, fmt.Errorf("k8s: ensure host key: %w", err)
	}
	if _, err := b.sandboxes.AgentsV1beta1().Sandboxes(ns).Create(ctx, sandboxObject(ns, spec, storageClass != "", b.memDefaults(), b.cfg.BoxMode), metav1.CreateOptions{}); ignoreExists(err) != nil {
		return nil, fmt.Errorf("k8s: ensure sandbox: %w", err)
	}
	// Program the SSH gateway so username=<tenant> routes to this box (no-op
	// when the gateway isn't configured).
	if err := b.router.ProgramRoute(ctx, tenant, spec.SSHKeys); err != nil {
		return nil, fmt.Errorf("k8s: ensure gateway pipe: %w", err)
	}
	return b.Get(ctx, spec.Ref)
}

// Get reads the box's Sandbox CR into a BoxStatus, or (nil, nil) when the box
// does not exist.
func (b *Backend) Get(ctx context.Context, ref box.BoxRef) (*box.BoxStatus, error) {
	ns := b.namespaceFor(ref.Tenant)
	sb, err := b.sandboxes.AgentsV1beta1().Sandboxes(ns).Get(ctx, sandboxName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return b.statusOf(ref.Tenant, sb), nil
}

// List returns every box this backend manages (all namespaces, by label).
func (b *Backend) List(ctx context.Context) ([]box.BoxStatus, error) {
	sbl, err := b.sandboxes.AgentsV1beta1().Sandboxes("").List(ctx, metav1.ListOptions{
		LabelSelector: managedByLabel + "=" + managedByValue,
	})
	if err != nil {
		return nil, err
	}
	out := make([]box.BoxStatus, 0, len(sbl.Items))
	for i := range sbl.Items {
		sb := &sbl.Items[i]
		out = append(out, *b.statusOf(sb.Labels[tenantLabel], sb))
	}
	return out, nil
}

// statusOf maps a Sandbox CR onto the runtime-neutral BoxStatus.
func (b *Backend) statusOf(tenant string, sb *sandboxv1beta1.Sandbox) *box.BoxStatus {
	st := &box.BoxStatus{
		Ref:       box.BoxRef{Tenant: tenant, Name: sandboxName},
		State:     stateOf(sb),
		Resources: resourcesOf(sb),
		Labels:    metaFromAnnotations(sb.Annotations),
		BackendID: "k8s",
	}
	// Pod IP, populated by the controller once the pod is scheduled.
	if len(sb.Status.PodIPs) > 0 {
		st.IPAddress = sb.Status.PodIPs[0]
	}
	return st
}

// Delete removes the box's compute objects (the Sandbox CR — which cascades
// to its pod and Service — plus Secrets, NetworkPolicy, gateway Pipe) but
// retains the PVC and namespace so the persistent data survives. Call Purge
// to permanently remove the PVC and namespace.
//
// When StorageClass is unset (no PVC), Delete falls back to removing the entire
// namespace (original behaviour, backward compat).
func (b *Backend) Delete(ctx context.Context, ref box.BoxRef, force bool) error {
	ns := b.namespaceFor(ref.Tenant)
	if err := b.router.RemoveRoute(ctx, ref.Tenant); err != nil {
		return fmt.Errorf("k8s: delete gateway pipe: %w", err)
	}
	// No persistent storage: delete the whole namespace (original behaviour).
	if b.cfg.StorageClass == "" {
		err := b.clientset.CoreV1().Namespaces().Delete(ctx, ns, metav1.DeleteOptions{})
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}
	// Persistent storage: delete compute objects individually; keep namespace+PVC.
	// Deleting the Sandbox cascades to its controller-owned children (pod +
	// headless Service) via owner references; the daemon-owned data PVC carries
	// no owner reference and survives.
	dels := []func() error{
		func() error {
			return ignoreNotFound(b.sandboxes.AgentsV1beta1().Sandboxes(ns).Delete(ctx, sandboxName, metav1.DeleteOptions{}))
		},
		func() error {
			return ignoreNotFound(b.clientset.NetworkingV1().NetworkPolicies(ns).Delete(ctx, "default-deny", metav1.DeleteOptions{}))
		},
		func() error {
			return ignoreNotFound(b.clientset.CoreV1().Secrets(ns).Delete(ctx, secretName(ref.Tenant), metav1.DeleteOptions{}))
		},
		func() error {
			return ignoreNotFound(b.clientset.CoreV1().Secrets(ns).Delete(ctx, hostKeySecretName(ref.Tenant), metav1.DeleteOptions{}))
		},
	}
	for _, del := range dels {
		if err := del(); err != nil {
			return err
		}
	}
	return nil
}

// Purge permanently removes the box's PVC and namespace. Call after Delete
// when the box's data should be discarded (e.g. DeletePolicy=DeleteOnStop).
// No-op when the namespace does not exist.
func (b *Backend) Purge(ctx context.Context, ref box.BoxRef) error {
	ns := b.namespaceFor(ref.Tenant)
	if b.cfg.StorageClass != "" {
		if err := ignoreNotFound(b.clientset.CoreV1().PersistentVolumeClaims(ns).Delete(ctx, pvcName, metav1.DeleteOptions{})); err != nil {
			return fmt.Errorf("k8s: purge pvc: %w", err)
		}
	}
	err := b.clientset.CoreV1().Namespaces().Delete(ctx, ns, metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}

// Start resumes the box: operatingMode=Running makes the agent-sandbox
// controller (re)create the pod, reattaching the retained PVC and identity.
func (b *Backend) Start(ctx context.Context, ref box.BoxRef) error {
	return b.setOperatingMode(ctx, ref, sandboxv1beta1.SandboxOperatingModeRunning)
}

// Stop suspends the box: operatingMode=Suspended makes the controller delete
// only the pod — PVC, Service, Secrets, and the Sandbox identity all persist.
func (b *Backend) Stop(ctx context.Context, ref box.BoxRef, force bool) error {
	return b.setOperatingMode(ctx, ref, sandboxv1beta1.SandboxOperatingModeSuspended)
}

// setOperatingMode merge-patches spec.operatingMode. A merge patch (not
// strategic) — CRDs don't support strategic merge, and for a scalar field the
// two are equivalent.
func (b *Backend) setOperatingMode(ctx context.Context, ref box.BoxRef, mode sandboxv1beta1.SandboxOperatingMode) error {
	patch := []byte(fmt.Sprintf(`{"spec":{"operatingMode":%q}}`, mode))
	_, err := b.sandboxes.AgentsV1beta1().Sandboxes(b.namespaceFor(ref.Tenant)).
		Patch(ctx, sandboxName, types.MergePatchType, patch, metav1.PatchOptions{})
	return err
}

// Resolve reports the gateway SSH endpoint sshpiper routes to the tenant's pod.
func (b *Backend) Resolve(ctx context.Context, ref box.BoxRef) (*box.BoxEndpoint, error) {
	return &box.BoxEndpoint{
		SSHHost:    b.cfg.GatewayHost,
		SSHPort:    b.cfg.GatewaySSHPort,
		SSHUser:    ref.Tenant,
		AccessType: pb.AccessType_ACCESS_TYPE_SSH,
	}, nil
}

// SetAuthorizedKeys rotates the keys that authenticate the agent.
//
// In the gateway path (sshpiper authenticates to the box with its own upstream
// key) the box's authorized_keys stays the gateway key — the agent's keys live
// in the Pipe's spec.from, so we only re-program the Pipe. In the direct path
// the agent's keys authorize the box itself, so we update the box Secret too.
func (b *Backend) SetAuthorizedKeys(ctx context.Context, ref box.BoxRef, keys []string) error {
	// The Secret is always rewritten: the box-authorized half follows the
	// access mode (gateway key vs client keys) and the client_keys record
	// must track rotations in both modes — the sentinel sync reads it.
	if err := b.upsertTenantSecret(ctx, ref.Tenant, b.boxAuthorizedKeys(keys), keys); err != nil {
		return err
	}
	// Re-program the gateway Pipe so the rotated client keys take effect at the
	// front (no-op when the gateway isn't configured).
	return b.router.ProgramRoute(ctx, ref.Tenant, keys)
}

// boxAuthorizedKeys returns the keys the box itself should authorize: the
// gateway's upstream key when routing through sshpiper, else the agent's keys
// (direct access).
func (b *Backend) boxAuthorizedKeys(agentKeys []string) []string {
	if b.router.Enabled() && b.cfg.GatewayUpstreamPublicKey != "" {
		return []string{b.cfg.GatewayUpstreamPublicKey}
	}
	return agentKeys
}

// Resize updates the box container's resource limits on the Sandbox's pod
// template. Unparseable (incus-native) quantities are skipped; a no-op resize
// returns nil.
//
// Get→mutate→Update rather than a patch: CRDs don't support strategic merge,
// and a plain merge patch would replace the whole containers list.
//
// Behavioral note vs the old StatefulSet path: the agent-sandbox controller
// does not recreate a live pod on template drift, so a resize takes effect at
// the NEXT pod creation (the next Stop→Start cycle), not immediately. The
// server-side dispatch layer decides whether to bounce the box.
func (b *Backend) Resize(ctx context.Context, ref box.BoxRef, r box.ResourceLimits) error {
	// Resize does not change GPU count, and passes no memory default: the floor
	// is a create-time concern, so an explicit resize honors "empty = unchanged"
	// rather than re-stamping the default.
	res := resourceRequirements(r, 0, memDefaults{})
	if res == nil {
		return nil
	}
	ns := b.namespaceFor(ref.Tenant)
	sb, err := b.sandboxes.AgentsV1beta1().Sandboxes(ns).Get(ctx, sandboxName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	for i := range sb.Spec.PodTemplate.Spec.Containers {
		if sb.Spec.PodTemplate.Spec.Containers[i].Name == "agent-box" {
			sb.Spec.PodTemplate.Spec.Containers[i].Resources = *res
		}
	}
	_, err = b.sandboxes.AgentsV1beta1().Sandboxes(ns).Update(ctx, sb, metav1.UpdateOptions{})
	return err
}

// SetMeta writes the runtime-neutral metadata as prefixed Sandbox annotations.
func (b *Backend) SetMeta(ctx context.Context, ref box.BoxRef, meta map[string]string) error {
	ann := map[string]string{}
	for k, v := range meta {
		ann[metaAnnotationPrefix+k] = v
	}
	patch, err := json.Marshal(map[string]any{"metadata": map[string]any{"annotations": ann}})
	if err != nil {
		return err
	}
	_, err = b.sandboxes.AgentsV1beta1().Sandboxes(b.namespaceFor(ref.Tenant)).
		Patch(ctx, sandboxName, types.MergePatchType, patch, metav1.PatchOptions{})
	return err
}

// GetMeta reads the prefixed annotations back into the metadata map.
func (b *Backend) GetMeta(ctx context.Context, ref box.BoxRef) (map[string]string, error) {
	sb, err := b.sandboxes.AgentsV1beta1().Sandboxes(b.namespaceFor(ref.Tenant)).Get(ctx, sandboxName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return metaFromAnnotations(sb.Annotations), nil
}

// stateOf maps a Sandbox onto the proto state. spec.operatingMode is the
// desired state (Suspended → STOPPED, the CR-native replicas=0); within
// Running, the controller-set conditions distinguish a Ready pod (RUNNING)
// from one still coming up (PROVISIONING). Finished means the pod hit a
// terminal phase — for a long-lived SSH box that is effectively stopped.
func stateOf(sb *sandboxv1beta1.Sandbox) pb.ContainerState {
	if sb.Spec.OperatingMode == sandboxv1beta1.SandboxOperatingModeSuspended {
		return pb.ContainerState_CONTAINER_STATE_STOPPED
	}
	if apimeta.IsStatusConditionTrue(sb.Status.Conditions, string(sandboxv1beta1.SandboxConditionFinished)) {
		return pb.ContainerState_CONTAINER_STATE_STOPPED
	}
	if apimeta.IsStatusConditionTrue(sb.Status.Conditions, string(sandboxv1beta1.SandboxConditionReady)) {
		return pb.ContainerState_CONTAINER_STATE_RUNNING
	}
	return pb.ContainerState_CONTAINER_STATE_PROVISIONING
}

// resourcesOf reads the box container's limits back into the runtime-neutral
// shape (K8s quantity strings, e.g. "2"/"4Gi").
func resourcesOf(sb *sandboxv1beta1.Sandbox) box.ResourceLimits {
	var r box.ResourceLimits
	for _, c := range sb.Spec.PodTemplate.Spec.Containers {
		if c.Name != "agent-box" {
			continue
		}
		if q, ok := c.Resources.Limits[corev1.ResourceCPU]; ok {
			r.CPU = q.String()
		}
		if q, ok := c.Resources.Limits[corev1.ResourceMemory]; ok {
			r.Memory = q.String()
		}
	}
	return r
}

// ignoreExists turns an AlreadyExists error into nil (idempotent reconcile).
func ignoreExists(err error) error {
	if apierrors.IsAlreadyExists(err) {
		return nil
	}
	return err
}

// ignoreNotFound turns a NotFound error into nil (idempotent delete).
func ignoreNotFound(err error) error {
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}

// metaFromAnnotations extracts the containarium.dev/meta.* annotations.
func metaFromAnnotations(ann map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range ann {
		if strings.HasPrefix(k, metaAnnotationPrefix) {
			out[strings.TrimPrefix(k, metaAnnotationPrefix)] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
