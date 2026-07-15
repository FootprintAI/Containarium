package k8s

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// gatewayRouter programs SSH-gateway routing for a tenant's box: it maps an
// incoming SSH connection (authenticated against the tenant's client keys) to
// the tenant's box pod. It is the seam between the box lifecycle (Create /
// Delete / SetAuthorizedKeys / sentinel re-key) and whatever SSH front end
// fronts the cluster, so the lifecycle code never depends on sshpiper's Pipe
// CRD directly. The sole implementation today is sshpiperRouter
// (gateway_sshpiper.go).
type gatewayRouter interface {
	// Enabled reports whether routing should be programmed. When false, boxes
	// are still reconciled but not fronted (a cluster without the gateway, or
	// the core lifecycle e2e); ProgramRoute and RemoveRoute are then no-ops.
	Enabled() bool
	// ProgramRoute creates or updates the tenant's route so username=<tenant>
	// reaches its box pod. clientKeys are the agent keys that may connect at the
	// front; the router unions in any authorized sentinel keys itself.
	ProgramRoute(ctx context.Context, tenant string, clientKeys []string) error
	// RemoveRoute deletes the tenant's route. No-op when already gone or the
	// gateway isn't configured.
	RemoveRoute(ctx context.Context, tenant string) error
}

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
