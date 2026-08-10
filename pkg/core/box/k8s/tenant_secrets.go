package k8s

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Delivering tenant secrets to a K8s box (#1190).
//
// On LXC a secret is delivered by `incus config set environment.<NAME>` (env
// mode) or by writing /run/secrets/<NAME> into the container's tmpfs (file
// mode). Neither has a K8s equivalent, so `containarium secret set` succeeded
// and the value never reached the box — the API call looks identical on both
// backends.
//
// The delivery here is a per-tenant Secret mounted into the box, and the
// choice of a mount over env vars is forced rather than stylistic:
//
//   - A container's environment is fixed when it starts. Updating a Secret
//     that was projected with envFrom does NOT change a running pod; the pod
//     has to be recreated. That fails the requirement that RefreshSecrets
//     update a running box.
//   - A Secret *volume* is refreshed in place by the kubelet, so a new
//     session sees the new value with no restart. That is also what the LXC
//     path actually promises — its own RefreshSecrets message says "new execs
//     will see updated values", not that running processes are re-parented.
//
// So the mount is what makes the two backends agree, and env projection is
// what would have made them differ while looking correct.
//
// The mount is tmpfs (Kubernetes backs Secret volumes with memory), which
// preserves the ephemeral-disposal property file-mode secrets have on LXC:
// when the pod goes, the plaintext goes with it. Nothing is written to the
// box's PVC or into the Sandbox CR — the CR carries the Secret's name, never
// its contents.

const (
	// tenantSecretsVolume is the pod volume carrying the tenant's secrets.
	tenantSecretsVolume = "tenant-secrets"
	// TenantSecretsMount is where the box sees them, one file per secret.
	// Same path as the LXC file-delivery mode, so anything reading secrets
	// from disk works unchanged on both backends.
	TenantSecretsMount = "/run/secrets"
)

// tenantSecretsName is the per-tenant Secret holding delivered secrets.
//
// Distinct from the authorized-keys and host-key Secrets: those are SSH
// plumbing the platform owns, this is tenant data. Mixing them would mean a
// tenant secret named `authorized_keys` could lock a box out.
func tenantSecretsName(tenant string) string { return tenant + "-secrets" }

// tenantSecretsObject builds the per-tenant secrets object.
func tenantSecretsObject(ns, tenant string, data map[string][]byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tenantSecretsName(tenant),
			Namespace: ns,
			Labels:    boxLabels(tenant),
		},
		Type: corev1.SecretTypeOpaque,
		Data: data,
	}
}

// ApplyTenantSecrets materializes a tenant's secrets into their box.
//
// An empty map deletes the Secret rather than leaving an empty one: a
// deleted secret must stop being readable in the box, and an empty-but-present
// Secret keeps the mount alive with stale files until the kubelet resyncs.
func (b *Backend) ApplyTenantSecrets(ctx context.Context, tenant string, data map[string][]byte) error {
	if tenant == "" {
		return fmt.Errorf("k8s: tenant is required")
	}

	ns := b.cfg.TenantNamespacePrefix + tenant
	secrets := b.clientset.CoreV1().Secrets(ns)
	name := tenantSecretsName(tenant)

	if len(data) == 0 {
		err := secrets.Delete(ctx, name, metav1.DeleteOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("k8s: delete tenant secrets for %q: %w", tenant, err)
		}
		return nil
	}

	desired := tenantSecretsObject(ns, tenant, data)
	existing, err := secrets.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			if _, err := secrets.Create(ctx, desired, metav1.CreateOptions{}); err != nil {
				return fmt.Errorf("k8s: create tenant secrets for %q: %w", tenant, err)
			}
			return nil
		}
		return fmt.Errorf("k8s: read tenant secrets for %q: %w", tenant, err)
	}

	// Update carries the whole Data map, so a secret deleted upstream
	// disappears here. Merging instead would leave a deleted secret readable
	// in the box for as long as the box lives.
	updated := existing.DeepCopy()
	updated.Data = data
	updated.Type = corev1.SecretTypeOpaque
	if updated.Labels == nil {
		updated.Labels = map[string]string{}
	}
	for k, v := range boxLabels(tenant) {
		updated.Labels[k] = v
	}
	if _, err := secrets.Update(ctx, updated, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("k8s: update tenant secrets for %q: %w", tenant, err)
	}
	return nil
}

// tenantSecretsVolumeFor builds the pod volume and its mount.
//
// Optional, because a box with no secrets must still start. A required volume
// whose Secret does not exist leaves the pod in ContainerCreating forever —
// so the common case (a tenant who has set no secrets) would be a box that
// never comes up. The kubelet populates the mount if the Secret appears
// later, which is exactly the first `secret set` on a running box.
func tenantSecretsVolumeFor(tenant string) (corev1.Volume, corev1.VolumeMount) {
	optional := true
	return corev1.Volume{
			Name: tenantSecretsVolume,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: tenantSecretsName(tenant),
					Optional:   &optional,
					// 0400: readable by the box's user, by nobody else, and
					// never executable.
					DefaultMode: int32p(0o400),
				},
			},
		}, corev1.VolumeMount{
			Name:      tenantSecretsVolume,
			MountPath: TenantSecretsMount,
			ReadOnly:  true,
		}
}
