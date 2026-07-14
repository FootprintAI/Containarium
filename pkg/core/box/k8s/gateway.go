package k8s

import (
	"context"
	"encoding/base64"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// ensureHostKey returns the box's stable host public key (authorized-key form),
// generating + storing a per-box host keypair Secret on first call. The private
// half is mounted into the box (its entrypoint uses it as dropbear's host key);
// the public half pins the box in the gateway Pipe's known_hosts_data. Stable
// (not regenerated per pod restart) so the pin stays valid.
func (b *Backend) ensureHostKey(ctx context.Context, tenant string) (pubs []string, err error) {
	ns := b.namespaceFor(tenant)
	name := hostKeySecretName(tenant)
	if sec, gerr := b.clientset.CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{}); gerr == nil {
		return []string{string(sec.Data[hostKeyPubField]), string(sec.Data[hostKeyRSAPubField])}, nil
	} else if !apierrors.IsNotFound(gerr) {
		return nil, gerr
	}
	edPriv, edPub, err := generateEd25519HostKey()
	if err != nil {
		return nil, err
	}
	rsaPriv, rsaPub, err := generateRSAHostKey()
	if err != nil {
		return nil, err
	}
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: boxLabels(tenant)},
		Type:       corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			hostKeyField:       edPriv,
			hostKeyPubField:    []byte(edPub),
			hostKeyRSAField:    rsaPriv,
			hostKeyRSAPubField: []byte(rsaPub),
		},
	}
	if _, err := b.clientset.CoreV1().Secrets(ns).Create(ctx, sec, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return nil, err
	}
	return []string{edPub, rsaPub}, nil
}

// pipeGVR is the sshpiper Kubernetes plugin's CRD. The design note
// (docs/K8S-AGENT-BOX-RUNTIME-DESIGN.md) calls it "PiperUpstream"; the
// maintained plugin's actual resource is `pipes` in group sshpiper.com/v1beta1
// (kind Pipe). sshpiper watches a namespace for these and routes incoming SSH
// by username — so programming a Pipe is how the gateway learns to forward a
// tenant's connection to its box pod.
var pipeGVR = schema.GroupVersionResource{Group: "sshpiper.com", Version: "v1beta1", Resource: "pipes"}

func pipeName(tenant string) string { return "box-" + tenant }

// gatewayEnabled reports whether SSH-gateway routing should be programmed: a
// dynamic client plus a configured gateway namespace where Pipes live. When
// off (no GatewayNamespace), boxes are still reconciled but not routed — useful
// for clusters without sshpiper, and for the core lifecycle e2e.
func (b *Backend) gatewayEnabled() bool {
	return b.dyn != nil && b.cfg.GatewayNamespace != ""
}

// upstreamHost is the in-cluster DNS the gateway forwards the tenant's SSH to:
// the Sandbox's controller-created headless Service (named after the Sandbox),
// whose A record resolves to the box pod. Matches the Sandbox's
// status.serviceFQDN; computed here rather than read from status so the Pipe
// can be programmed at Create time, before the controller first reconciles.
func (b *Backend) upstreamHost(tenant string) string {
	return fmt.Sprintf("%s.%s.svc.cluster.local:%d", sandboxName, b.namespaceFor(tenant), sshPort)
}

// pipeObject builds the sshpiper Pipe that routes username=<tenant> to the
// tenant's box pod: the incoming connection authenticates against the box's
// authorized keys (inline, base64), and the upstream host key is trusted
// (ignore_hostkey — TOFU/known_hosts pinning is a follow-up).
func (b *Backend) pipeObject(tenant string, keys []string, hostPubKeys []string) *unstructured.Unstructured {
	var buf []byte
	for _, k := range keys {
		buf = append(buf, []byte(k)...)
		buf = append(buf, '\n')
	}
	to := map[string]any{
		"host":     b.upstreamHost(tenant),
		"username": boxSSHUser, // fixed box login user; tenant identity is enforced by from.username
	}
	// Host-key handling: pin the box's host keys (known_hosts_data) when we have
	// them, else fall back to ignore_hostkey (the escape hatch / pre-pinning
	// behavior). Both keys are pinned because sshpiper may negotiate either —
	// stops a man-in-the-middle between sshpiper and the box.
	if len(hostPubKeys) > 0 && !b.cfg.InsecureIgnoreHostKey {
		to["known_hosts_data"] = knownHostsData(b.upstreamHost(tenant), hostPubKeys...)
	} else {
		to["ignore_hostkey"] = true
	}
	// The upstream credential: sshpiper authenticates to the box with this key
	// (its public half is authorized on the box). Set only when configured.
	if b.cfg.GatewayUpstreamKeySecret != "" {
		to["private_key_secret"] = map[string]any{"name": b.cfg.GatewayUpstreamKeySecret}
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "sshpiper.com/v1beta1",
		"kind":       "Pipe",
		"metadata": map[string]any{
			"name":      pipeName(tenant),
			"namespace": b.cfg.GatewayNamespace,
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

// upsertPipe creates or updates the tenant's Pipe in the gateway namespace.
// No-op when the gateway isn't configured.
func (b *Backend) upsertPipe(ctx context.Context, tenant string, keys []string) error {
	if !b.gatewayEnabled() {
		return nil
	}
	ns := b.cfg.GatewayNamespace
	hostPubs, err := b.ensureHostKey(ctx, tenant) // pin the box's stable host keys
	if err != nil {
		return fmt.Errorf("ensure host key: %w", err)
	}
	obj := b.pipeObject(tenant, keys, hostPubs)
	_, err = b.dyn.Resource(pipeGVR).Namespace(ns).Create(ctx, obj, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		existing, gerr := b.dyn.Resource(pipeGVR).Namespace(ns).Get(ctx, pipeName(tenant), metav1.GetOptions{})
		if gerr != nil {
			return gerr
		}
		existing.Object["spec"] = obj.Object["spec"]
		_, err = b.dyn.Resource(pipeGVR).Namespace(ns).Update(ctx, existing, metav1.UpdateOptions{})
	}
	return err
}

// deletePipe removes the tenant's Pipe. No-op when the gateway isn't configured
// or the Pipe is already gone. (The Pipe lives in the gateway namespace, so the
// per-tenant namespace delete does not cascade to it — it must be deleted
// explicitly.)
func (b *Backend) deletePipe(ctx context.Context, tenant string) error {
	if !b.gatewayEnabled() {
		return nil
	}
	err := b.dyn.Resource(pipeGVR).Namespace(b.cfg.GatewayNamespace).Delete(ctx, pipeName(tenant), metav1.DeleteOptions{})
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
