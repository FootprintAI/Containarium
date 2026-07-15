package k8s

import (
	"context"
	"encoding/base64"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// sshpiperRouter is the sshpiper-backed gatewayRouter: it programs one Pipe CR
// per tenant in the gateway namespace, which the sshpiper Kubernetes plugin
// watches to route incoming SSH by username to the tenant's box pod. It is the
// only gatewayRouter implementation today; the seam (gateway.go) exists so a
// different SSH front end could replace it without touching box lifecycle.
type sshpiperRouter struct{ b *Backend }

var _ gatewayRouter = (*sshpiperRouter)(nil)

// pipeGVR is the sshpiper Kubernetes plugin's CRD. The design note
// (docs/K8S-AGENT-BOX-RUNTIME-DESIGN.md) calls it "PiperUpstream"; the
// maintained plugin's actual resource is `pipes` in group sshpiper.com/v1beta1
// (kind Pipe). sshpiper watches a namespace for these and routes incoming SSH
// by username — so programming a Pipe is how the gateway learns to forward a
// tenant's connection to its box pod.
var pipeGVR = schema.GroupVersionResource{Group: "sshpiper.com", Version: "v1beta1", Resource: "pipes"}

func pipeName(tenant string) string { return "box-" + tenant }

// Enabled reports whether SSH-gateway routing should be programmed: a dynamic
// client plus a configured gateway namespace where Pipes live. When off (no
// GatewayNamespace), boxes are still reconciled but not routed — useful for
// clusters without sshpiper, and for the core lifecycle e2e.
func (r *sshpiperRouter) Enabled() bool {
	return r.b.dyn != nil && r.b.cfg.GatewayNamespace != ""
}

// upstreamHost is the in-cluster DNS the gateway forwards the tenant's SSH to:
// the Sandbox's controller-created headless Service (named after the Sandbox),
// whose A record resolves to the box pod. Matches the Sandbox's
// status.serviceFQDN; computed here rather than read from status so the Pipe
// can be programmed at Create time, before the controller first reconciles.
func (r *sshpiperRouter) upstreamHost(tenant string) string {
	return fmt.Sprintf("%s.%s.svc.cluster.local:%d", sandboxName, r.b.namespaceFor(tenant), sshPort)
}

// pipeObject builds the sshpiper Pipe that routes username=<tenant> to the
// tenant's box pod: the incoming connection authenticates against the box's
// authorized keys (inline, base64), and the upstream host key is trusted
// (ignore_hostkey — TOFU/known_hosts pinning is a follow-up).
//
// fromKeys is the union of the agent's client keys (direct node-gateway
// access) and any authorized sentinel keys (hop 2 of the sentinel chain) —
// both authenticate the incoming connection at the node gateway.
func (r *sshpiperRouter) pipeObject(tenant string, fromKeys []string, hostPubKeys []string) *unstructured.Unstructured {
	var buf []byte
	for _, k := range fromKeys {
		buf = append(buf, []byte(k)...)
		buf = append(buf, '\n')
	}
	to := map[string]any{
		"host":     r.upstreamHost(tenant),
		"username": boxSSHUser, // fixed box login user; tenant identity is enforced by from.username
	}
	// Host-key handling: pin the box's host keys (known_hosts_data) when we have
	// them, else fall back to ignore_hostkey (the escape hatch / pre-pinning
	// behavior). Both keys are pinned because sshpiper may negotiate either —
	// stops a man-in-the-middle between sshpiper and the box.
	if len(hostPubKeys) > 0 && !r.b.cfg.InsecureIgnoreHostKey {
		to["known_hosts_data"] = knownHostsData(r.upstreamHost(tenant), hostPubKeys...)
	} else {
		to["ignore_hostkey"] = true
	}
	// The upstream credential: sshpiper authenticates to the box with this key
	// (its public half is authorized on the box). Set only when configured.
	if r.b.cfg.GatewayUpstreamKeySecret != "" {
		to["private_key_secret"] = map[string]any{"name": r.b.cfg.GatewayUpstreamKeySecret}
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "sshpiper.com/v1beta1",
		"kind":       "Pipe",
		"metadata": map[string]any{
			"name":      pipeName(tenant),
			"namespace": r.b.cfg.GatewayNamespace,
			"labels":    toAnyMap(boxLabels(tenant)),
		},
		"spec": map[string]any{
			"from": []any{map[string]any{
				"username":             tenant,
				"authorized_keys_data": base64.StdEncoding.EncodeToString(buf),
			}},
			"to": to,
		},
	}}
}

// ProgramRoute creates or updates the tenant's Pipe in the gateway namespace.
// No-op when the gateway isn't configured. The Pipe's from-keys are the
// agent's client keys plus any authorized sentinel keys (so a sentinel in
// front of this node can complete hop 2).
func (r *sshpiperRouter) ProgramRoute(ctx context.Context, tenant string, keys []string) error {
	if !r.Enabled() {
		return nil
	}
	ns := r.b.cfg.GatewayNamespace
	hostPubs, err := r.b.ensureHostKey(ctx, tenant) // pin the box's stable host keys
	if err != nil {
		return fmt.Errorf("ensure host key: %w", err)
	}
	fromKeys := append(append([]string{}, keys...), r.b.sentinelKeys(ctx)...)
	obj := r.pipeObject(tenant, fromKeys, hostPubs)
	_, err = r.b.dyn.Resource(pipeGVR).Namespace(ns).Create(ctx, obj, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		existing, gerr := r.b.dyn.Resource(pipeGVR).Namespace(ns).Get(ctx, pipeName(tenant), metav1.GetOptions{})
		if gerr != nil {
			return gerr
		}
		existing.Object["spec"] = obj.Object["spec"]
		_, err = r.b.dyn.Resource(pipeGVR).Namespace(ns).Update(ctx, existing, metav1.UpdateOptions{})
	}
	return err
}

// RemoveRoute removes the tenant's Pipe. No-op when the gateway isn't configured
// or the Pipe is already gone. (The Pipe lives in the gateway namespace, so the
// per-tenant namespace delete does not cascade to it — it must be deleted
// explicitly.)
func (r *sshpiperRouter) RemoveRoute(ctx context.Context, tenant string) error {
	if !r.Enabled() {
		return nil
	}
	err := r.b.dyn.Resource(pipeGVR).Namespace(r.b.cfg.GatewayNamespace).Delete(ctx, pipeName(tenant), metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}

func toAnyMap(m map[string]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
