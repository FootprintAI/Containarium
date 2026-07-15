package k8s

import (
	"context"
	"fmt"
	"log"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Client (agent) keys are recorded on the per-tenant Secret under this field,
// SEPARATE from authorized_keys (which is what the box's dropbear reads and,
// in gateway-upstream mode, holds the gateway key instead). The sentinel's
// keysync consumes these via ListClientKeys → /authorized-keys so the
// sentinel authenticates the AGENT at hop 1 — deriving them from the Pipe's
// from.authorized_keys_data would be wrong once the sentinel's own key is
// appended there.
const clientKeysKey = "client_keys"

// ClientKeyLister is the seam the daemon's /authorized-keys handler consumes
// on the k8s runtime (the LXC runtime walks /home instead).
type ClientKeyLister interface {
	ListClientKeys(ctx context.Context) (map[string]string, error)
}

var _ ClientKeyLister = (*Backend)(nil)

// ListClientKeys returns tenant → client authorized_keys content for every
// box this backend manages, read from the client_keys field of each
// per-tenant Secret. Boxes created before the field existed are skipped with
// a log line (their keys re-appear on the next SetAuthorizedKeys).
func (b *Backend) ListClientKeys(ctx context.Context) (map[string]string, error) {
	boxes, err := b.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("k8s: list boxes for client keys: %w", err)
	}
	out := make(map[string]string, len(boxes))
	for i := range boxes {
		tenant := boxes[i].Ref.Tenant
		sec, gerr := b.clientset.CoreV1().Secrets(b.namespaceFor(tenant)).Get(ctx, secretName(tenant), metav1.GetOptions{})
		if gerr != nil {
			log.Printf("[k8s] client keys for %s unavailable: %v (skipping)", tenant, gerr)
			continue
		}
		keys := string(sec.Data[clientKeysKey])
		if keys == "" {
			log.Printf("[k8s] box %s has no recorded client_keys (created pre-advertisement?); skipping until next key rotation", tenant)
			continue
		}
		out[tenant] = keys
	}
	return out, nil
}

// GatewayIngressPort resolves the SSH ingress port on this node that the
// sentinel should forward box traffic to. Precedence: the explicit
// Config.GatewayAdvertisePort override, else the gateway Service's NodePort.
// Returns 0 (advertise nothing → sentinel legacy convention) with a warning
// when neither is available — a sentinel-fronted K8s node without a
// resolvable ingress cannot be routed to.
func (b *Backend) GatewayIngressPort(ctx context.Context) int {
	if b.cfg.GatewayAdvertisePort > 0 {
		return b.cfg.GatewayAdvertisePort
	}
	svc, err := b.clientset.CoreV1().Services(b.cfg.GatewayNamespace).Get(ctx, b.cfg.GatewayService, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		log.Printf("[k8s] gateway service %s/%s not found; advertising no SSH ingress (set %s or deploy the gateway)",
			b.cfg.GatewayNamespace, b.cfg.GatewayService, "CONTAINARIUM_K8S_GATEWAY_ADVERTISE_PORT")
		return 0
	}
	if err != nil {
		log.Printf("[k8s] gateway service lookup failed: %v; advertising no SSH ingress", err)
		return 0
	}
	for _, p := range svc.Spec.Ports {
		if p.NodePort > 0 && (p.Name == "ssh" || len(svc.Spec.Ports) == 1) {
			return int(p.NodePort)
		}
	}
	log.Printf("[k8s] gateway service %s/%s has no NodePort; advertising no SSH ingress (expose it or set the advertise-port override)",
		b.cfg.GatewayNamespace, b.cfg.GatewayService)
	return 0
}

// ResolveGatewayDialTarget returns the host:port a tunnel-attached node
// should forward its advertised gateway port to (TunnelClient.Forward) — the
// in-cluster sshpiper Service's reachable address. NodePorts aren't reliably
// reachable on 127.0.0.1, so the tunnel needs an explicit target. Precedence:
// a LoadBalancer ingress address, else <node InternalIP>:<NodePort>. Empty
// when neither resolves (advertise nothing). Best-effort, logs on miss.
func (b *Backend) ResolveGatewayDialTarget(ctx context.Context) string {
	svc, err := b.clientset.CoreV1().Services(b.cfg.GatewayNamespace).Get(ctx, b.cfg.GatewayService, metav1.GetOptions{})
	if err != nil {
		log.Printf("[k8s] gateway dial target: service %s/%s lookup failed: %v", b.cfg.GatewayNamespace, b.cfg.GatewayService, err)
		return ""
	}
	// LoadBalancer ingress wins: routable from anywhere, dial the Service port.
	for _, ing := range svc.Status.LoadBalancer.Ingress {
		addr := ing.IP
		if addr == "" {
			addr = ing.Hostname
		}
		if addr != "" {
			for _, p := range svc.Spec.Ports {
				if p.Name == "ssh" || len(svc.Spec.Ports) == 1 {
					return fmt.Sprintf("%s:%d", addr, p.Port)
				}
			}
		}
	}
	// Else a node InternalIP + the NodePort.
	nodePort := b.GatewayIngressPort(ctx)
	if nodePort == 0 {
		return ""
	}
	nodes, err := b.clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil || len(nodes.Items) == 0 {
		log.Printf("[k8s] gateway dial target: no nodes to resolve an InternalIP: %v", err)
		return ""
	}
	for _, n := range nodes.Items {
		for _, a := range n.Status.Addresses {
			if a.Type == corev1.NodeInternalIP && a.Address != "" {
				return fmt.Sprintf("%s:%d", a.Address, nodePort)
			}
		}
	}
	return ""
}

// upsertTenantSecret writes the per-tenant Secret with both halves: the keys
// the box itself authorizes (boxKeys — the gateway upstream key in gateway
// mode, the client keys in direct mode) and the client_keys record the
// sentinel sync reads.
func (b *Backend) upsertTenantSecret(ctx context.Context, tenant string, boxKeys, clientKeys []string) error {
	sec := secretObject(b.namespaceFor(tenant), tenant, boxKeys, clientKeys)
	_, err := b.clientset.CoreV1().Secrets(b.namespaceFor(tenant)).Update(ctx, sec, metav1.UpdateOptions{})
	if apierrors.IsNotFound(err) {
		_, err = b.clientset.CoreV1().Secrets(b.namespaceFor(tenant)).Create(ctx, sec, metav1.CreateOptions{})
	}
	return err
}

// clientKeysOf reads a tenant's recorded client keys (empty when absent).
// Used by SetSentinelKey to rebuild each Pipe's from-keys.
func (b *Backend) clientKeysOf(ctx context.Context, tenant string) string {
	sec, err := b.clientset.CoreV1().Secrets(b.namespaceFor(tenant)).Get(ctx, secretName(tenant), metav1.GetOptions{})
	if err != nil {
		return ""
	}
	return string(sec.Data[clientKeysKey])
}
