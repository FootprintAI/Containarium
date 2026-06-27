//go:build k8s

package k8s

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/footprintai/containarium/pkg/core/box"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// These tests drive the real reconciler against a fake clientset, so they run
// in plain `go test -tags k8s` with no cluster. The kind e2e (e2e_test.go)
// covers behavior against a real apiserver.

func testBackend() (*Backend, *fake.Clientset) {
	cs := fake.NewSimpleClientset()
	return NewWithClientset(cs, Config{BoxImage: "registry.k8s.io/pause:3.9", GatewayHost: "gw.example.com"}), cs
}

func TestKindAndCapabilities(t *testing.T) {
	b, _ := testBackend()
	if b.Kind() != box.KindK8s {
		t.Fatalf("Kind() = %q, want %q", b.Kind(), box.KindK8s)
	}
	// K8s provisioning is image-baked → no in-box exec seam.
	if _, ok := interface{}(b).(box.ExecCapable); ok {
		t.Error("k8s Backend must not implement box.ExecCapable")
	}
}

func TestCreateReconcilesObjects(t *testing.T) {
	b, cs := testBackend()
	ctx := context.Background()
	st, err := b.Create(ctx, box.BoxSpec{
		Ref:       box.BoxRef{Tenant: "alice"},
		Image:     "registry.k8s.io/pause:3.9",
		SSHKeys:   []string{"ssh-ed25519 AAAA"},
		AutoStart: true,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if st == nil || st.Ref.Tenant != "alice" || st.Ref.Name != statefulSetName {
		t.Fatalf("status = %+v", st)
	}

	ns := "tenant-alice"
	if _, err := cs.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{}); err != nil {
		t.Errorf("namespace not created: %v", err)
	}
	ss, err := cs.AppsV1().StatefulSets(ns).Get(ctx, statefulSetName, metav1.GetOptions{})
	if err != nil {
		t.Errorf("statefulset not created: %v", err)
	} else {
		// restricted-PSA hardening the box image is built for.
		sc := ss.Spec.Template.Spec.Containers[0].SecurityContext
		if sc == nil || sc.RunAsNonRoot == nil || !*sc.RunAsNonRoot {
			t.Errorf("container not runAsNonRoot: %+v", sc)
		}
		if sc != nil && (sc.Capabilities == nil || len(sc.Capabilities.Drop) != 1 || string(sc.Capabilities.Drop[0]) != "ALL") {
			t.Errorf("container does not drop ALL caps: %+v", sc.Capabilities)
		}
		if pscPort := ss.Spec.Template.Spec.Containers[0].Ports[0].ContainerPort; pscPort != 2222 {
			t.Errorf("container port = %d, want 2222", pscPort)
		}
		// authorized_keys mounted where the image reads it (or the box rejects
		// every login — found in live test), and the stable host key mounted
		// (so the gateway can pin it).
		mounts := map[string]string{} // mountPath set
		for _, m := range ss.Spec.Template.Spec.Containers[0].VolumeMounts {
			mounts[m.MountPath] = m.Name
		}
		if mounts["/etc/agent-box"] == "" {
			t.Errorf("authorized_keys not mounted at /etc/agent-box: %+v", ss.Spec.Template.Spec.Containers[0].VolumeMounts)
		}
		if mounts["/etc/agent-box-hostkey"] == "" {
			t.Errorf("host key not mounted at /etc/agent-box-hostkey")
		}
		vols := map[string]string{} // volume name -> secret name
		for _, v := range ss.Spec.Template.Spec.Volumes {
			if v.Secret != nil {
				vols[v.Name] = v.Secret.SecretName
			}
		}
		if vols[authorizedKeysVolume] != secretName("alice") {
			t.Errorf("authorized-keys volume secret = %q", vols[authorizedKeysVolume])
		}
		if vols[hostKeyVolume] != hostKeySecretName("alice") {
			t.Errorf("host-key volume secret = %q", vols[hostKeyVolume])
		}
	}
	if _, err := cs.CoreV1().Services(ns).Get(ctx, serviceName, metav1.GetOptions{}); err != nil {
		t.Errorf("service not created: %v", err)
	}
	if _, err := cs.NetworkingV1().NetworkPolicies(ns).Get(ctx, "default-deny", metav1.GetOptions{}); err != nil {
		t.Errorf("networkpolicy not created: %v", err)
	}
	sec, err := cs.CoreV1().Secrets(ns).Get(ctx, secretName("alice"), metav1.GetOptions{})
	if err != nil {
		t.Errorf("secret not created: %v", err)
	} else if string(sec.Data[authorizedKeysKey]) != "ssh-ed25519 AAAA\n" {
		t.Errorf("authorized_keys = %q", sec.Data[authorizedKeysKey])
	}

	// AutoStart=true → desired 1 replica, not yet ready under the fake → PROVISIONING.
	if st.State != pb.ContainerState_CONTAINER_STATE_PROVISIONING {
		t.Errorf("state = %v, want PROVISIONING", st.State)
	}
}

func TestCreateIdempotent(t *testing.T) {
	b, _ := testBackend()
	ctx := context.Background()
	spec := box.BoxSpec{Ref: box.BoxRef{Tenant: "bob"}, Image: "x", AutoStart: true}
	if _, err := b.Create(ctx, spec); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	if _, err := b.Create(ctx, spec); err != nil {
		t.Fatalf("re-Create should be idempotent, got: %v", err)
	}
}

func TestGetMissing(t *testing.T) {
	b, _ := testBackend()
	st, err := b.Get(context.Background(), box.BoxRef{Tenant: "ghost"})
	if err != nil || st != nil {
		t.Fatalf("Get(missing) = (%+v, %v), want (nil, nil)", st, err)
	}
}

func TestStartStopScale(t *testing.T) {
	b, cs := testBackend()
	ctx := context.Background()
	ref := box.BoxRef{Tenant: "carol"}
	if _, err := b.Create(ctx, box.BoxSpec{Ref: ref, Image: "x"}); err != nil { // AutoStart false → 0
		t.Fatalf("Create: %v", err)
	}
	ss, _ := cs.AppsV1().StatefulSets("tenant-carol").Get(ctx, statefulSetName, metav1.GetOptions{})
	if *ss.Spec.Replicas != 0 {
		t.Fatalf("created replicas = %d, want 0", *ss.Spec.Replicas)
	}
	if err := b.Start(ctx, ref); err != nil {
		t.Fatalf("Start: %v", err)
	}
	ss, _ = cs.AppsV1().StatefulSets("tenant-carol").Get(ctx, statefulSetName, metav1.GetOptions{})
	if *ss.Spec.Replicas != 1 {
		t.Errorf("after Start replicas = %d, want 1", *ss.Spec.Replicas)
	}
	if err := b.Stop(ctx, ref, false); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	ss, _ = cs.AppsV1().StatefulSets("tenant-carol").Get(ctx, statefulSetName, metav1.GetOptions{})
	if *ss.Spec.Replicas != 0 {
		t.Errorf("after Stop replicas = %d, want 0", *ss.Spec.Replicas)
	}
}

func TestDeleteRemovesNamespace(t *testing.T) {
	b, cs := testBackend()
	ctx := context.Background()
	ref := box.BoxRef{Tenant: "dave"}
	if _, err := b.Create(ctx, box.BoxSpec{Ref: ref, Image: "x", AutoStart: true}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := b.Delete(ctx, ref, true); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := cs.CoreV1().Namespaces().Get(ctx, "tenant-dave", metav1.GetOptions{}); err == nil {
		t.Error("namespace still present after Delete")
	}
	// Delete of an absent box is a no-op.
	if err := b.Delete(ctx, box.BoxRef{Tenant: "nobody"}, true); err != nil {
		t.Errorf("Delete(missing) = %v, want nil", err)
	}
}

func TestSetGetMeta(t *testing.T) {
	b, _ := testBackend()
	ctx := context.Background()
	ref := box.BoxRef{Tenant: "erin"}
	if _, err := b.Create(ctx, box.BoxSpec{Ref: ref, Image: "x", AutoStart: true}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := b.SetMeta(ctx, ref, map[string]string{"ttl": "3600", "team": "infra"}); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}
	meta, err := b.GetMeta(ctx, ref)
	if err != nil {
		t.Fatalf("GetMeta: %v", err)
	}
	if meta["ttl"] != "3600" || meta["team"] != "infra" {
		t.Errorf("meta = %+v", meta)
	}
}

func TestResolveGatewayEndpoint(t *testing.T) {
	b, _ := testBackend()
	ep, err := b.Resolve(context.Background(), box.BoxRef{Tenant: "alice"})
	if err != nil || ep == nil {
		t.Fatalf("Resolve = (%+v, %v)", ep, err)
	}
	if ep.SSHHost != "gw.example.com" || ep.SSHUser != "alice" || ep.SSHPort != 22 {
		t.Errorf("endpoint = %+v", ep)
	}
}

// testBackendWithStorage returns a backend with a StorageClass set, exercising
// the CSI PVC lifecycle paths.
func testBackendWithStorage() (*Backend, *fake.Clientset) {
	cs := fake.NewSimpleClientset()
	return NewWithClientset(cs, Config{
		BoxImage:     "registry.k8s.io/pause:3.9",
		GatewayHost:  "gw.example.com",
		StorageClass: "standard",
	}), cs
}

// TestPVCObjectBuilder verifies that pvcObject produces a well-formed PVC with
// the correct namespace, labels, StorageClass, and storage request.
func TestPVCObjectBuilder(t *testing.T) {
	pvc := pvcObject("tenant-alice", "alice", "standard", "20Gi")

	if pvc.Name != pvcName {
		t.Errorf("PVC name = %q, want %q", pvc.Name, pvcName)
	}
	if pvc.Namespace != "tenant-alice" {
		t.Errorf("PVC namespace = %q, want tenant-alice", pvc.Namespace)
	}
	if pvc.Spec.StorageClassName == nil || *pvc.Spec.StorageClassName != "standard" {
		t.Errorf("StorageClassName = %v", pvc.Spec.StorageClassName)
	}
	q := pvc.Spec.Resources.Requests["storage"]
	if q.String() != "20Gi" {
		t.Errorf("storage request = %q, want 20Gi", q.String())
	}
}

// TestPVCObjectBuilderDefaults verifies the disk-size default when spec leaves
// Resources.Disk empty.
func TestPVCObjectBuilderDefaults(t *testing.T) {
	pvc := pvcObject("tenant-bob", "bob", "fast", "")
	q := pvc.Spec.Resources.Requests["storage"]
	if q.String() != defaultDisk {
		t.Errorf("default storage = %q, want %q", q.String(), defaultDisk)
	}
}

// TestCreateProvisionsPVC verifies that Create provisions a PVC when
// StorageClass is configured.
func TestCreateProvisionsPVC(t *testing.T) {
	b, cs := testBackendWithStorage()
	ctx := context.Background()
	ref := box.BoxRef{Tenant: "frank"}
	if _, err := b.Create(ctx, box.BoxSpec{
		Ref:       ref,
		Image:     "x",
		Resources: box.ResourceLimits{Disk: "30Gi"},
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	ns := "tenant-frank"
	pvc, err := cs.CoreV1().PersistentVolumeClaims(ns).Get(ctx, pvcName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("PVC not created: %v", err)
	}
	if pvc.Spec.StorageClassName == nil || *pvc.Spec.StorageClassName != "standard" {
		t.Errorf("StorageClassName = %v", pvc.Spec.StorageClassName)
	}
	q := pvc.Spec.Resources.Requests["storage"]
	if q.String() != "30Gi" {
		t.Errorf("storage request = %q, want 30Gi", q.String())
	}

	// StatefulSet must mount the data volume at /home/agent.
	ss, err := cs.AppsV1().StatefulSets(ns).Get(ctx, statefulSetName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("StatefulSet not found: %v", err)
	}
	mounts := map[string]string{}
	for _, m := range ss.Spec.Template.Spec.Containers[0].VolumeMounts {
		mounts[m.MountPath] = m.Name
	}
	if mounts[dataMount] == "" {
		t.Errorf("data volume not mounted at %s: mounts=%v", dataMount, mounts)
	}
}

// TestCreateNoPVCWhenStorageClassEmpty verifies backward compat: no PVC when
// StorageClass is unset, and the StatefulSet has no data volume mount.
func TestCreateNoPVCWhenStorageClassEmpty(t *testing.T) {
	b, cs := testBackend() // no StorageClass
	ctx := context.Background()
	if _, err := b.Create(ctx, box.BoxSpec{Ref: box.BoxRef{Tenant: "grace"}, Image: "x"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	ns := "tenant-grace"
	pvcs, err := cs.CoreV1().PersistentVolumeClaims(ns).List(ctx, metav1.ListOptions{})
	if err != nil || len(pvcs.Items) != 0 {
		t.Errorf("expected no PVCs when StorageClass is empty, got %d", len(pvcs.Items))
	}
	ss, _ := cs.AppsV1().StatefulSets(ns).Get(ctx, statefulSetName, metav1.GetOptions{})
	for _, m := range ss.Spec.Template.Spec.Containers[0].VolumeMounts {
		if m.MountPath == dataMount {
			t.Errorf("data volume mounted even without StorageClass")
		}
	}
}

// TestDeleteRetainsPVC verifies that Delete removes box compute objects but
// keeps the namespace and PVC when StorageClass is configured.
func TestDeleteRetainsPVC(t *testing.T) {
	b, cs := testBackendWithStorage()
	ctx := context.Background()
	ref := box.BoxRef{Tenant: "henry"}
	if _, err := b.Create(ctx, box.BoxSpec{Ref: ref, Image: "x"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := b.Delete(ctx, ref, false); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	ns := "tenant-henry"
	// Namespace must survive (PVC lives in it).
	if _, err := cs.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{}); err != nil {
		t.Errorf("namespace removed by Delete: %v", err)
	}
	// PVC must survive.
	if _, err := cs.CoreV1().PersistentVolumeClaims(ns).Get(ctx, pvcName, metav1.GetOptions{}); err != nil {
		t.Errorf("PVC removed by Delete: %v", err)
	}
	// StatefulSet must be gone.
	if _, err := cs.AppsV1().StatefulSets(ns).Get(ctx, statefulSetName, metav1.GetOptions{}); err == nil {
		t.Error("StatefulSet still present after Delete")
	}
}

// TestPurgeRemovesPVCAndNamespace verifies that Purge removes both the PVC and
// the namespace, and is a no-op on an absent box.
func TestPurgeRemovesPVCAndNamespace(t *testing.T) {
	b, cs := testBackendWithStorage()
	ctx := context.Background()
	ref := box.BoxRef{Tenant: "iris"}
	if _, err := b.Create(ctx, box.BoxSpec{Ref: ref, Image: "x"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := b.Delete(ctx, ref, false); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := b.Purge(ctx, ref); err != nil {
		t.Fatalf("Purge: %v", err)
	}

	ns := "tenant-iris"
	if _, err := cs.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{}); err == nil {
		t.Error("namespace still present after Purge")
	}
	// Purge of an absent box is a no-op.
	if err := b.Purge(ctx, box.BoxRef{Tenant: "nobody"}); err != nil {
		t.Errorf("Purge(missing) = %v, want nil", err)
	}
}
