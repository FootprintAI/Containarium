//go:build k8s

package k8s

import (
	"context"
	"os"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/footprintai/containarium/pkg/core/box"
)

// TestE2E_SharedVolumeRestartsRunningPod checks the live Pod, rather than just
// the Sandbox template, after attach, detach, and force-delete. A static
// hostPath PV supplies RWX metadata on the single-node kind cluster; this test
// exercises controller lifecycle behavior, not a distributed RWX provisioner.
func TestE2E_SharedVolumeRestartsRunningPod(t *testing.T) {
	if os.Getenv("CONTAINARIUM_K8S_E2E") == "" {
		t.Skip("set CONTAINARIUM_K8S_E2E=1 (and KUBECONFIG) to run the kind e2e")
	}
	const class = "containarium-e2e-volume-restart"
	const volumeName = "shared-data"
	const mountPath = "/mnt/shared"
	b, err := New(Config{
		Kubeconfig: os.Getenv("KUBECONFIG"), BoxImage: "registry.k8s.io/pause:3.9",
		GatewayHost: "gateway.example.com", SharedVolumeStorageClass: class,
	})
	if err != nil {
		t.Fatal(err)
	}
	ref := box.BoxRef{Tenant: "volume-restart-e2e"}
	ns := b.namespaceFor(ref.Tenant)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_ = b.Delete(ctx, ref, true)
		_ = b.clientset.CoreV1().PersistentVolumes().Delete(ctx, class, metav1.DeleteOptions{})
		_ = b.clientset.StorageV1().StorageClasses().Delete(ctx, class, metav1.DeleteOptions{})
	})
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	if _, err := b.clientset.StorageV1().StorageClasses().Create(ctx, &storagev1.StorageClass{
		ObjectMeta: metav1.ObjectMeta{Name: class}, Provisioner: "kubernetes.io/no-provisioner",
	}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	hostPathType := corev1.HostPathDirectoryOrCreate
	if _, err := b.clientset.CoreV1().PersistentVolumes().Create(ctx, &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: class},
		Spec: corev1.PersistentVolumeSpec{
			Capacity:                      corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("1Mi")},
			AccessModes:                   []corev1.PersistentVolumeAccessMode{corev1.ReadWriteMany},
			StorageClassName:              class,
			PersistentVolumeReclaimPolicy: corev1.PersistentVolumeReclaimRetain,
			ClaimRef: &corev1.ObjectReference{
				Namespace: ns, Name: sharedVolumePVCName(volumeName),
			},
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				HostPath: &corev1.HostPathVolumeSource{Path: "/tmp/containarium-e2e-volume-restart", Type: &hostPathType},
			},
		},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Create(ctx, box.BoxSpec{
		Ref: ref, Image: "registry.k8s.io/pause:3.9", AutoStart: true,
		SSHKeys: []string{"ssh-ed25519 AAAAExampleKeyForE2E test@e2e"},
	}); err != nil {
		t.Fatal(err)
	}
	pod := waitForRecreatedVolumePod(t, ctx, b, ns, "")
	if _, err := b.CreateVolume(ctx, ref.Tenant, volumeName, 1<<20, class); err != nil {
		t.Fatal(err)
	}
	attach := func() error {
		return b.AttachVolume(ctx, ref.Tenant, volumeName, class, ref.Tenant, mountPath, false)
	}
	for _, step := range []struct {
		name    string
		apply   func() error
		mounted bool
	}{
		{name: "attach", apply: attach, mounted: true},
		{name: "detach", apply: func() error { return b.DetachVolume(ctx, ref.Tenant, volumeName, ref.Tenant) }},
		{name: "reattach", apply: attach, mounted: true},
		{name: "force-delete", apply: func() error { return b.DeleteVolume(ctx, ref.Tenant, volumeName, class, true) }},
	} {
		t.Logf("applying %s to running Pod %s", step.name, pod.UID)
		if err := step.apply(); err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		pod = waitForRecreatedVolumePod(t, ctx, b, ns, pod.UID)
		mounted, claimed := false, false
		for _, mount := range pod.Spec.Containers[0].VolumeMounts {
			if mount.Name == sharedVolumePodName(volumeName) && mount.MountPath == mountPath {
				mounted = true
			}
		}
		for _, vol := range pod.Spec.Volumes {
			if vol.PersistentVolumeClaim != nil && vol.PersistentVolumeClaim.ClaimName == sharedVolumePVCName(volumeName) {
				claimed = true
			}
		}
		if mounted != step.mounted || claimed != step.mounted {
			t.Fatalf("%s: live Pod mounted=%t claimed=%t; want both %t", step.name, mounted, claimed, step.mounted)
		}
	}
	if err := wait.PollUntilContextTimeout(ctx, 250*time.Millisecond, time.Minute, true, func(ctx context.Context) (bool, error) {
		_, err := b.clientset.CoreV1().PersistentVolumeClaims(ns).Get(ctx, sharedVolumePVCName(volumeName), metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		return false, err
	}); err != nil {
		t.Fatalf("PVC still present after force-delete: %v", err)
	}
}

func waitForRecreatedVolumePod(t *testing.T, ctx context.Context, b *Backend, ns string, previous types.UID) *corev1.Pod {
	t.Helper()
	var pod *corev1.Pod
	err := wait.PollUntilContextTimeout(ctx, 250*time.Millisecond, 3*time.Minute, true, func(ctx context.Context) (bool, error) {
		current, err := b.clientset.CoreV1().Pods(ns).Get(ctx, sandboxName, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if current.UID == previous || current.DeletionTimestamp != nil {
			return false, nil
		}
		for _, condition := range current.Status.Conditions {
			if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
				pod = current
				return true, nil
			}
		}
		return false, nil
	})
	if err != nil {
		t.Fatalf("waiting for a Ready Pod replacing %q: %v", previous, err)
	}
	return pod
}
