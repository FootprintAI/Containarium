package k8s

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/footprintai/containarium/pkg/core/box"
)

// sandboxPodSpecForTest returns the pod spec the backend would create.
func sandboxPodSpecForTest(t *testing.T, spec box.BoxSpec) corev1.PodSpec {
	t.Helper()
	sb := sandboxObject("tenant-"+spec.Ref.Tenant, spec, false, memDefaults{}, podOptions{})
	podSpec := sb.Spec.PodTemplate.Spec
	if len(podSpec.Containers) != 1 {
		t.Fatalf("want 1 container, got %d", len(podSpec.Containers))
	}
	return podSpec
}

func secretsBackend() *Backend {
	return NewWithClientset(fake.NewSimpleClientset(), nil, Config{TenantNamespacePrefix: "tenant-"})
}

func getTenantSecret(t *testing.T, b *Backend, tenant string) (*corev1.Secret, error) {
	t.Helper()
	return b.clientset.CoreV1().Secrets("tenant-"+tenant).
		Get(context.Background(), tenantSecretsName(tenant), metav1.GetOptions{})
}

func TestApplyTenantSecrets_CreatesTheSecret(t *testing.T) {
	b := secretsBackend()
	err := b.ApplyTenantSecrets(context.Background(), "alice", map[string][]byte{
		"API_TOKEN": []byte("s3cret"),
	})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}

	got, err := getTenantSecret(t, b, "alice")
	if err != nil {
		t.Fatalf("secret was not created: %v", err)
	}
	if string(got.Data["API_TOKEN"]) != "s3cret" {
		t.Errorf("value = %q, want the secret — `secret set` succeeding while the value never "+
			"reaches the box is the whole of #1190", got.Data["API_TOKEN"])
	}
}

// A changed value must replace the old one. This is what RefreshSecrets
// depends on, and the kubelet propagates it into a running pod's mount.
func TestApplyTenantSecrets_UpdatesAnExistingValue(t *testing.T) {
	b := secretsBackend()
	ctx := context.Background()
	if err := b.ApplyTenantSecrets(ctx, "alice", map[string][]byte{"TOKEN": []byte("old")}); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	if err := b.ApplyTenantSecrets(ctx, "alice", map[string][]byte{"TOKEN": []byte("new")}); err != nil {
		t.Fatalf("second apply: %v", err)
	}

	got, _ := getTenantSecret(t, b, "alice")
	if string(got.Data["TOKEN"]) != "new" {
		t.Errorf("value = %q, want the updated one", got.Data["TOKEN"])
	}
}

// A secret deleted upstream must stop being readable in the box. Merging into
// the existing Data would leave it there for the life of the box.
func TestApplyTenantSecrets_RemovesADeletedSecret(t *testing.T) {
	b := secretsBackend()
	ctx := context.Background()
	if err := b.ApplyTenantSecrets(ctx, "alice", map[string][]byte{
		"KEEP": []byte("a"), "DROP": []byte("b"),
	}); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	if err := b.ApplyTenantSecrets(ctx, "alice", map[string][]byte{"KEEP": []byte("a")}); err != nil {
		t.Fatalf("second apply: %v", err)
	}

	got, _ := getTenantSecret(t, b, "alice")
	if _, still := got.Data["DROP"]; still {
		t.Error("a deleted secret is still readable in the box — deletion that leaves the value " +
			"in place is worse than deletion that fails, because it reports success")
	}
	if string(got.Data["KEEP"]) != "a" {
		t.Error("deleting one secret removed another")
	}
}

// Deleting the last secret removes the object rather than leaving an empty
// one, so nothing stale remains mounted.
func TestApplyTenantSecrets_DeletingTheLastSecretRemovesTheObject(t *testing.T) {
	b := secretsBackend()
	ctx := context.Background()
	if err := b.ApplyTenantSecrets(ctx, "alice", map[string][]byte{"TOKEN": []byte("v")}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := b.ApplyTenantSecrets(ctx, "alice", nil); err != nil {
		t.Fatalf("apply empty: %v", err)
	}

	if _, err := getTenantSecret(t, b, "alice"); !apierrors.IsNotFound(err) {
		t.Errorf("the secret object survived with no secrets in it (err=%v)", err)
	}
}

// Applying nothing to a tenant that never had secrets is a no-op, not an
// error — the reconciler runs this path on every pass for every tenant.
func TestApplyTenantSecrets_EmptyForAnUnknownTenantIsNotAnError(t *testing.T) {
	if err := secretsBackend().ApplyTenantSecrets(context.Background(), "nobody", nil); err != nil {
		t.Errorf("apply: %v — the reconciler would log an error per tenant per pass", err)
	}
}

func TestApplyTenantSecrets_RequiresATenant(t *testing.T) {
	if err := secretsBackend().ApplyTenantSecrets(context.Background(), "", map[string][]byte{
		"A": []byte("b"),
	}); err == nil {
		t.Error("an empty tenant was accepted — the secret would land in a namespace built from " +
			"an empty name")
	}
}

// The tenant's secrets must not share an object with the platform's SSH
// plumbing: a tenant secret named `authorized_keys` would otherwise be able
// to overwrite the box's keys.
func TestTenantSecretsAreSeparateFromTheSSHPlumbing(t *testing.T) {
	tenant := "alice"
	if tenantSecretsName(tenant) == secretName(tenant) {
		t.Error("tenant secrets share the authorized-keys object — a secret named " +
			"authorized_keys could lock the box out or let anyone in")
	}
	if tenantSecretsName(tenant) == hostKeySecretName(tenant) {
		t.Error("tenant secrets share the host-key object")
	}
}

// --- pod wiring -------------------------------------------------------

// The mount, not env projection, is what makes RefreshSecrets reach a running
// box: a Secret update never changes a running container's environment, but
// the kubelet does refresh its volumes.
func TestBoxPodMountsTenantSecretsAsAVolume(t *testing.T) {
	spec := box.BoxSpec{Ref: box.BoxRef{Tenant: "alice"}, Image: "img"}
	pod := sandboxPodSpecForTest(t, spec)

	var mount *corev1.VolumeMount
	for i := range pod.Containers[0].VolumeMounts {
		if pod.Containers[0].VolumeMounts[i].Name == tenantSecretsVolume {
			mount = &pod.Containers[0].VolumeMounts[i]
		}
	}
	if mount == nil {
		t.Fatal("the box mounts no tenant-secrets volume — secrets set through the API would " +
			"never reach it (#1190)")
	}
	if mount.MountPath != TenantSecretsMount {
		t.Errorf("mount path = %q, want %q to match the LXC file-delivery path", mount.MountPath, TenantSecretsMount)
	}
	if !mount.ReadOnly {
		t.Error("the secrets mount is writable — the box could rewrite its own secrets")
	}

	var vol *corev1.Volume
	for i := range pod.Volumes {
		if pod.Volumes[i].Name == tenantSecretsVolume {
			vol = &pod.Volumes[i]
		}
	}
	if vol == nil || vol.Secret == nil {
		t.Fatal("the tenant-secrets volume is not backed by a Secret")
	}
	if vol.Secret.SecretName != tenantSecretsName("alice") {
		t.Errorf("volume references %q, want the tenant's secrets object", vol.Secret.SecretName)
	}
	// A required volume whose Secret does not exist leaves the pod in
	// ContainerCreating forever — so every box belonging to a tenant who has
	// set no secrets would never start.
	if vol.Secret.Optional == nil || !*vol.Secret.Optional {
		t.Error("the secrets volume is required — a tenant with no secrets would get a box that " +
			"never leaves ContainerCreating")
	}
	if vol.Secret.DefaultMode == nil || *vol.Secret.DefaultMode != 0o400 {
		t.Errorf("secret file mode = %v, want 0400", vol.Secret.DefaultMode)
	}
}

// Secrets must not be projected into the container's environment from the
// pod spec: that is the path that cannot be refreshed without a restart, and
// it puts the values where `kubectl describe pod` shows them.
func TestBoxPodDoesNotProjectSecretsIntoTheEnvironment(t *testing.T) {
	spec := box.BoxSpec{Ref: box.BoxRef{Tenant: "alice"}, Image: "img"}
	pod := sandboxPodSpecForTest(t, spec)

	c := pod.Containers[0]
	if len(c.EnvFrom) > 0 {
		t.Errorf("the container uses envFrom (%d source(s)) — env projection cannot be refreshed "+
			"without recreating the pod, which is what #1190 AC2 rules out", len(c.EnvFrom))
	}
	for _, e := range c.Env {
		if e.ValueFrom != nil && e.ValueFrom.SecretKeyRef != nil {
			t.Errorf("env %q is projected from a Secret — it would be fixed at container start "+
				"and stale after any refresh", e.Name)
		}
	}
}
