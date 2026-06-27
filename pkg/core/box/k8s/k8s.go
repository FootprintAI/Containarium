//go:build k8s

package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/footprintai/containarium/pkg/core/box"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Config is the K8s backend's wiring, supplied at daemon start when the `k8s`
// build variant selects this backend. See docs/K8S-AGENT-BOX-RUNTIME-DESIGN.md.
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

	// TenantNamespacePrefix prefixes the per-tenant namespace
	// (e.g. "tenant-" → "tenant-<tenant>"). Defaults to "tenant-".
	TenantNamespacePrefix string

	// BoxImage is the agent-box image (sshd + agent-box) the box runs.
	BoxImage string

	// StorageClass is reserved for the box PVC (not wired in this slice).
	StorageClass string

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

// Backend implements box.BoxBackend on Kubernetes.
//
// Capability note: it deliberately does NOT implement box.ExecCapable — the
// K8s agent-box is ForceCommand-pinned and provisioning is image-baked, so
// there is no in-box exec seam. box.MetricsCapable / box.GPUCapable are
// deferred.
type Backend struct {
	cfg       Config
	clientset kubernetes.Interface
	dyn       dynamic.Interface // for the sshpiper Pipe CRD; nil disables gateway routing
}

var _ box.BoxBackend = (*Backend)(nil)

// New constructs a K8s backend: it builds a client-go clientset + dynamic
// client (in-cluster, an explicit kubeconfig, or the ambient rules) and applies
// config defaults.
func New(cfg Config) (*Backend, error) {
	restCfg, err := buildRestConfig(cfg.Kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("k8s: build rest config: %w", err)
	}
	cs, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("k8s: build clientset: %w", err)
	}
	dyn, err := dynamic.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("k8s: build dynamic client: %w", err)
	}
	return newBackend(cs, dyn, cfg), nil
}

// NewWithClientset builds a Backend over an injected clientset, with gateway
// (Pipe) routing disabled (no dynamic client). Used by lifecycle unit tests.
func NewWithClientset(cs kubernetes.Interface, cfg Config) *Backend {
	return newBackend(cs, nil, cfg)
}

// NewWithClients builds a Backend over injected clientset + dynamic client
// (fakes for unit tests, a kind cluster for e2e), exercising gateway routing.
func NewWithClients(cs kubernetes.Interface, dyn dynamic.Interface, cfg Config) *Backend {
	return newBackend(cs, dyn, cfg)
}

func newBackend(cs kubernetes.Interface, dyn dynamic.Interface, cfg Config) *Backend {
	if cfg.TenantNamespacePrefix == "" {
		cfg.TenantNamespacePrefix = "tenant-"
	}
	if cfg.GatewaySSHPort == 0 {
		cfg.GatewaySSHPort = 22
	}
	return &Backend{cfg: cfg, clientset: cs, dyn: dyn}
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

// Create reconciles the per-tenant namespace + Secret + headless Service +
// default-deny NetworkPolicy + StatefulSet, then returns the box's status.
// Each step is idempotent (AlreadyExists is success) so re-create reuses the
// box rather than erroring (#669).
func (b *Backend) Create(ctx context.Context, spec box.BoxSpec) (*box.BoxStatus, error) {
	ns := b.namespaceFor(spec.Ref.Tenant)
	tenant := spec.Ref.Tenant
	if spec.Image == "" {
		spec.Image = b.cfg.BoxImage // default to the configured agent-box image
	}

	if _, err := b.clientset.CoreV1().Namespaces().Create(ctx, namespaceObject(ns, tenant), metav1.CreateOptions{}); ignoreExists(err) != nil {
		return nil, fmt.Errorf("k8s: ensure namespace: %w", err)
	}
	// Provision the data PVC before the StatefulSet so the pod can mount it on
	// first start. Skipped when StorageClass is unset (backward compat: existing
	// deployments that don't need persistent storage keep the old behaviour).
	if b.cfg.StorageClass != "" {
		pvc := pvcObject(ns, tenant, b.cfg.StorageClass, spec.Resources.Disk)
		if _, err := b.clientset.CoreV1().PersistentVolumeClaims(ns).Create(ctx, pvc, metav1.CreateOptions{}); ignoreExists(err) != nil {
			return nil, fmt.Errorf("k8s: ensure pvc: %w", err)
		}
	}
	if _, err := b.clientset.CoreV1().Secrets(ns).Create(ctx, secretObject(ns, tenant, b.boxAuthorizedKeys(spec.SSHKeys)), metav1.CreateOptions{}); ignoreExists(err) != nil {
		return nil, fmt.Errorf("k8s: ensure secret: %w", err)
	}
	if _, err := b.clientset.CoreV1().Services(ns).Create(ctx, serviceObject(ns, tenant), metav1.CreateOptions{}); ignoreExists(err) != nil {
		return nil, fmt.Errorf("k8s: ensure service: %w", err)
	}
	if _, err := b.clientset.NetworkingV1().NetworkPolicies(ns).Create(ctx, networkPolicyObject(ns, tenant), metav1.CreateOptions{}); ignoreExists(err) != nil {
		return nil, fmt.Errorf("k8s: ensure networkpolicy: %w", err)
	}
	// Stable per-box host key Secret — created before the StatefulSet, which
	// mounts it (and dropbear uses it so the gateway can pin it).
	if _, err := b.ensureHostKey(ctx, tenant); err != nil {
		return nil, fmt.Errorf("k8s: ensure host key: %w", err)
	}
	if _, err := b.clientset.AppsV1().StatefulSets(ns).Create(ctx, statefulSetObject(ns, spec, b.cfg.StorageClass != ""), metav1.CreateOptions{}); ignoreExists(err) != nil {
		return nil, fmt.Errorf("k8s: ensure statefulset: %w", err)
	}
	// Program the SSH gateway so username=<tenant> routes to this box (no-op
	// when the gateway isn't configured).
	if err := b.upsertPipe(ctx, tenant, spec.SSHKeys); err != nil {
		return nil, fmt.Errorf("k8s: ensure gateway pipe: %w", err)
	}
	return b.Get(ctx, spec.Ref)
}

// Get reads the box's StatefulSet (and pod) into a BoxStatus, or (nil, nil)
// when the box does not exist.
func (b *Backend) Get(ctx context.Context, ref box.BoxRef) (*box.BoxStatus, error) {
	ns := b.namespaceFor(ref.Tenant)
	ss, err := b.clientset.AppsV1().StatefulSets(ns).Get(ctx, statefulSetName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	st := &box.BoxStatus{
		Ref:       box.BoxRef{Tenant: ref.Tenant, Name: statefulSetName},
		State:     stateOf(ss),
		Resources: resourcesOf(ss),
		Labels:    metaFromAnnotations(ss.Annotations),
		BackendID: "k8s",
	}
	// Pod IP, best-effort (the pod may not exist yet while replicas=0).
	if pod, perr := b.clientset.CoreV1().Pods(ns).Get(ctx, statefulSetName+"-0", metav1.GetOptions{}); perr == nil {
		st.IPAddress = pod.Status.PodIP
	}
	return st, nil
}

// List returns every box this backend manages (all namespaces, by label).
func (b *Backend) List(ctx context.Context) ([]box.BoxStatus, error) {
	ssl, err := b.clientset.AppsV1().StatefulSets("").List(ctx, metav1.ListOptions{
		LabelSelector: managedByLabel + "=" + managedByValue,
	})
	if err != nil {
		return nil, err
	}
	out := make([]box.BoxStatus, 0, len(ssl.Items))
	for i := range ssl.Items {
		ss := &ssl.Items[i]
		out = append(out, box.BoxStatus{
			Ref:       box.BoxRef{Tenant: ss.Labels[tenantLabel], Name: statefulSetName},
			State:     stateOf(ss),
			Resources: resourcesOf(ss),
			Labels:    metaFromAnnotations(ss.Annotations),
			BackendID: "k8s",
		})
	}
	return out, nil
}

// Delete removes the box's compute objects (StatefulSet, Service, Secrets,
// NetworkPolicy, gateway Pipe) but retains the PVC and namespace so the
// persistent data survives. Call Purge to permanently remove the PVC and
// namespace.
//
// When StorageClass is unset (no PVC), Delete falls back to removing the entire
// namespace (original behaviour, backward compat).
func (b *Backend) Delete(ctx context.Context, ref box.BoxRef, force bool) error {
	ns := b.namespaceFor(ref.Tenant)
	if err := b.deletePipe(ctx, ref.Tenant); err != nil {
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
	dels := []func() error{
		func() error {
			return ignoreNotFound(b.clientset.AppsV1().StatefulSets(ns).Delete(ctx, statefulSetName, metav1.DeleteOptions{}))
		},
		func() error {
			return ignoreNotFound(b.clientset.CoreV1().Services(ns).Delete(ctx, serviceName, metav1.DeleteOptions{}))
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

// Start scales the box StatefulSet to 1 replica.
func (b *Backend) Start(ctx context.Context, ref box.BoxRef) error { return b.scale(ctx, ref, 1) }

// Stop scales the box StatefulSet to 0 replicas.
func (b *Backend) Stop(ctx context.Context, ref box.BoxRef, force bool) error {
	return b.scale(ctx, ref, 0)
}

func (b *Backend) scale(ctx context.Context, ref box.BoxRef, replicas int32) error {
	patch := []byte(fmt.Sprintf(`{"spec":{"replicas":%d}}`, replicas))
	_, err := b.clientset.AppsV1().StatefulSets(b.namespaceFor(ref.Tenant)).
		Patch(ctx, statefulSetName, types.StrategicMergePatchType, patch, metav1.PatchOptions{})
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
	ns := b.namespaceFor(ref.Tenant)
	if !(b.gatewayEnabled() && b.cfg.GatewayUpstreamPublicKey != "") {
		sec := secretObject(ns, ref.Tenant, keys)
		_, err := b.clientset.CoreV1().Secrets(ns).Update(ctx, sec, metav1.UpdateOptions{})
		if apierrors.IsNotFound(err) {
			_, err = b.clientset.CoreV1().Secrets(ns).Create(ctx, sec, metav1.CreateOptions{})
		}
		if err != nil {
			return err
		}
	}
	// Re-program the gateway Pipe so the rotated client keys take effect at the
	// front (no-op when the gateway isn't configured).
	return b.upsertPipe(ctx, ref.Tenant, keys)
}

// boxAuthorizedKeys returns the keys the box itself should authorize: the
// gateway's upstream key when routing through sshpiper, else the agent's keys
// (direct access).
func (b *Backend) boxAuthorizedKeys(agentKeys []string) []string {
	if b.gatewayEnabled() && b.cfg.GatewayUpstreamPublicKey != "" {
		return []string{b.cfg.GatewayUpstreamPublicKey}
	}
	return agentKeys
}

// Resize patches the box container's resource limits. Unparseable (incus-native)
// quantities are skipped; a no-op resize returns nil.
func (b *Backend) Resize(ctx context.Context, ref box.BoxRef, r box.ResourceLimits) error {
	res := resourceRequirements(r, 0) // Resize does not change GPU count
	if res == nil {
		return nil
	}
	patch := map[string]any{
		"spec": map[string]any{
			"template": map[string]any{
				"spec": map[string]any{
					"containers": []map[string]any{{
						"name":      "agent-box",
						"resources": res,
					}},
				},
			},
		},
	}
	body, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	_, err = b.clientset.AppsV1().StatefulSets(b.namespaceFor(ref.Tenant)).
		Patch(ctx, statefulSetName, types.StrategicMergePatchType, body, metav1.PatchOptions{})
	return err
}

// SetMeta writes the runtime-neutral metadata as prefixed StatefulSet
// annotations.
func (b *Backend) SetMeta(ctx context.Context, ref box.BoxRef, meta map[string]string) error {
	ann := map[string]string{}
	for k, v := range meta {
		ann[metaAnnotationPrefix+k] = v
	}
	patch, err := json.Marshal(map[string]any{"metadata": map[string]any{"annotations": ann}})
	if err != nil {
		return err
	}
	_, err = b.clientset.AppsV1().StatefulSets(b.namespaceFor(ref.Tenant)).
		Patch(ctx, statefulSetName, types.MergePatchType, patch, metav1.PatchOptions{})
	return err
}

// GetMeta reads the prefixed annotations back into the metadata map.
func (b *Backend) GetMeta(ctx context.Context, ref box.BoxRef) (map[string]string, error) {
	ss, err := b.clientset.AppsV1().StatefulSets(b.namespaceFor(ref.Tenant)).Get(ctx, statefulSetName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return metaFromAnnotations(ss.Annotations), nil
}

// stateOf maps a StatefulSet's replica/ready counts to the proto state: 0
// desired replicas → STOPPED; ready → RUNNING; otherwise still coming up.
func stateOf(ss *appsv1.StatefulSet) pb.ContainerState {
	desired := int32(0)
	if ss.Spec.Replicas != nil {
		desired = *ss.Spec.Replicas
	}
	if desired == 0 {
		return pb.ContainerState_CONTAINER_STATE_STOPPED
	}
	if ss.Status.ReadyReplicas >= 1 {
		return pb.ContainerState_CONTAINER_STATE_RUNNING
	}
	return pb.ContainerState_CONTAINER_STATE_PROVISIONING
}

// resourcesOf reads the box container's limits back into the runtime-neutral
// shape (K8s quantity strings, e.g. "2"/"4Gi").
func resourcesOf(ss *appsv1.StatefulSet) box.ResourceLimits {
	var r box.ResourceLimits
	for _, c := range ss.Spec.Template.Spec.Containers {
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
