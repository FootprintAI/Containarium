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
}

var _ box.BoxBackend = (*Backend)(nil)

// New constructs a K8s backend: it builds a client-go clientset (in-cluster,
// an explicit kubeconfig, or the ambient rules) and applies config defaults.
func New(cfg Config) (*Backend, error) {
	restCfg, err := buildRestConfig(cfg.Kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("k8s: build rest config: %w", err)
	}
	cs, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("k8s: build clientset: %w", err)
	}
	return NewWithClientset(cs, cfg), nil
}

// NewWithClientset builds a Backend over an injected clientset (a kind cluster
// for e2e, or a fake for unit tests). Skips rest-config discovery.
func NewWithClientset(cs kubernetes.Interface, cfg Config) *Backend {
	if cfg.TenantNamespacePrefix == "" {
		cfg.TenantNamespacePrefix = "tenant-"
	}
	if cfg.GatewaySSHPort == 0 {
		cfg.GatewaySSHPort = 22
	}
	return &Backend{cfg: cfg, clientset: cs}
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

	if _, err := b.clientset.CoreV1().Namespaces().Create(ctx, namespaceObject(ns, tenant), metav1.CreateOptions{}); ignoreExists(err) != nil {
		return nil, fmt.Errorf("k8s: ensure namespace: %w", err)
	}
	if _, err := b.clientset.CoreV1().Secrets(ns).Create(ctx, secretObject(ns, tenant, spec.SSHKeys), metav1.CreateOptions{}); ignoreExists(err) != nil {
		return nil, fmt.Errorf("k8s: ensure secret: %w", err)
	}
	if _, err := b.clientset.CoreV1().Services(ns).Create(ctx, serviceObject(ns, tenant), metav1.CreateOptions{}); ignoreExists(err) != nil {
		return nil, fmt.Errorf("k8s: ensure service: %w", err)
	}
	if _, err := b.clientset.NetworkingV1().NetworkPolicies(ns).Create(ctx, networkPolicyObject(ns, tenant), metav1.CreateOptions{}); ignoreExists(err) != nil {
		return nil, fmt.Errorf("k8s: ensure networkpolicy: %w", err)
	}
	if _, err := b.clientset.AppsV1().StatefulSets(ns).Create(ctx, statefulSetObject(ns, spec), metav1.CreateOptions{}); ignoreExists(err) != nil {
		return nil, fmt.Errorf("k8s: ensure statefulset: %w", err)
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

// Delete removes the per-tenant namespace, cascading every box object.
func (b *Backend) Delete(ctx context.Context, ref box.BoxRef, force bool) error {
	err := b.clientset.CoreV1().Namespaces().Delete(ctx, b.namespaceFor(ref.Tenant), metav1.DeleteOptions{})
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

// SetAuthorizedKeys upserts the box's authorized_keys Secret.
func (b *Backend) SetAuthorizedKeys(ctx context.Context, ref box.BoxRef, keys []string) error {
	ns := b.namespaceFor(ref.Tenant)
	sec := secretObject(ns, ref.Tenant, keys)
	_, err := b.clientset.CoreV1().Secrets(ns).Update(ctx, sec, metav1.UpdateOptions{})
	if apierrors.IsNotFound(err) {
		_, err = b.clientset.CoreV1().Secrets(ns).Create(ctx, sec, metav1.CreateOptions{})
	}
	return err
}

// Resize patches the box container's resource limits. Unparseable (incus-native)
// quantities are skipped; a no-op resize returns nil.
func (b *Backend) Resize(ctx context.Context, ref box.BoxRef, r box.ResourceLimits) error {
	res := resourceRequirements(r)
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
