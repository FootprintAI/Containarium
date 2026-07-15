package k8s

import (
	"context"
	"fmt"
	"log"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/footprintai/containarium/internal/gateway"
)

// The sentinel's upstream pubkey(s) are stored in this Secret in the gateway
// namespace (restart-safe) and appended to every box Pipe's from-keys so a
// sentinel fronting this node can complete hop 2 of the SSH chain
// (agent → sentinel → node gateway → box). Distinct from the box's own
// authorized_keys and the daemon's gateway-upstream key.
const (
	sentinelKeySecretName = "containarium-sentinel-keys"
	sentinelKeysField     = "authorized_keys"
)

var _ gateway.SentinelKeyAuthorizer = (*Backend)(nil)

// SetSentinelKey persists the sentinel's upstream pubkey and authorizes it at
// the node gateway: it's stored in a Secret in the gateway namespace and
// re-applied to every box's Pipe from-keys. Idempotent — re-posting the same
// key rewrites the Pipes but reports rotated=0.
//
// Requires gateway-upstream mode: a sentinel three-hop chain needs the node
// gateway to authenticate to boxes with its own key, so a sentinel in front
// of a direct-mode node is unsupported and errors clearly.
func (b *Backend) SetSentinelKey(ctx context.Context, pubKey string) (updated, rotated int, err error) {
	pubKey = strings.TrimSpace(pubKey)
	if pubKey == "" {
		return 0, 0, fmt.Errorf("k8s: empty sentinel key")
	}
	if !b.router.Enabled() || b.cfg.GatewayUpstreamKeySecret == "" {
		return 0, 0, fmt.Errorf("k8s: sentinel fronting requires gateway-upstream mode " +
			"(set CONTAINARIUM_K8S_GATEWAY_NAMESPACE + _UPSTREAM_KEY_SECRET); refusing to authorize a sentinel key in direct mode")
	}

	prev := b.sentinelKeys(ctx)
	if len(prev) == 1 && prev[0] == pubKey {
		rotated = 0
	} else if len(prev) > 0 {
		rotated = 1 // a different prior sentinel key is being replaced
	}

	// Store exactly one current sentinel key (rotation replaces, not appends —
	// mirrors the LXC marker-block semantics).
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      sentinelKeySecretName,
			Namespace: b.cfg.GatewayNamespace,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{sentinelKeysField: []byte(pubKey + "\n")},
	}
	if _, uerr := b.clientset.CoreV1().Secrets(b.cfg.GatewayNamespace).Update(ctx, sec, metav1.UpdateOptions{}); apierrors.IsNotFound(uerr) {
		_, uerr = b.clientset.CoreV1().Secrets(b.cfg.GatewayNamespace).Create(ctx, sec, metav1.CreateOptions{})
		if uerr != nil {
			return 0, 0, fmt.Errorf("k8s: store sentinel key: %w", uerr)
		}
	} else if uerr != nil {
		return 0, 0, fmt.Errorf("k8s: store sentinel key: %w", uerr)
	}

	// Re-program every box's Pipe so the sentinel key takes effect at hop 2.
	boxes, lerr := b.List(ctx)
	if lerr != nil {
		return 0, rotated, fmt.Errorf("k8s: list boxes for sentinel re-key: %w", lerr)
	}
	for i := range boxes {
		tenant := boxes[i].Ref.Tenant
		clientKeys := splitKeys(b.clientKeysOf(ctx, tenant))
		if perr := b.router.ProgramRoute(ctx, tenant, clientKeys); perr != nil {
			log.Printf("[k8s] sentinel re-key: box %s Pipe update failed: %v", tenant, perr)
			continue
		}
		updated++
	}
	return updated, rotated, nil
}

// sentinelKeys reads the currently-authorized sentinel pubkey(s) from the
// gateway-namespace Secret (empty when none / gateway off).
func (b *Backend) sentinelKeys(ctx context.Context) []string {
	if b.cfg.GatewayNamespace == "" {
		return nil
	}
	sec, err := b.clientset.CoreV1().Secrets(b.cfg.GatewayNamespace).Get(ctx, sentinelKeySecretName, metav1.GetOptions{})
	if err != nil {
		return nil
	}
	return splitKeys(string(sec.Data[sentinelKeysField]))
}

// splitKeys turns an authorized_keys blob into non-empty, non-comment lines.
func splitKeys(blob string) []string {
	var out []string
	for _, line := range strings.Split(blob, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}
