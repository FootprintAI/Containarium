//go:build k8s

package k8s

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/pkg/core/backup"
	"github.com/footprintai/containarium/pkg/core/box"
	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

// This lane requires the snapshot controller and CSI hostpath driver. Ordinary
// lifecycle kind tests deliberately do not opt in without that infrastructure.
func TestE2E_CSISnapshot(t *testing.T) {
	if os.Getenv("CONTAINARIUM_K8S_SNAPSHOT_E2E") != "1" {
		t.Skip("run scripts/k8s-snapshot-e2e.sh")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	b, err := New(Config{Kubeconfig: os.Getenv("KUBECONFIG"), StorageClass: "snapshot-e2e", BoxImage: "busybox:1.37.0"})
	if err != nil {
		t.Fatal(err)
	}
	tenant := "snapshot-" + uuid.NewString()[:8]
	ns := b.namespaceFor(tenant)
	if _, err = b.clientset.CoreV1().Namespaces().Create(ctx, namespaceObject(ns, tenant), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := b.clientset.CoreV1().Namespaces().Delete(cleanup, ns, metav1.DeleteOptions{}); err != nil {
			t.Log(err)
		}
	})
	pvc := pvcObject(ns, tenant, "snapshot-e2e", "1Gi")
	if _, err = b.clientset.CoreV1().PersistentVolumeClaims(ns).Create(ctx, pvc, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	// Use a small deterministic workload rather than an SSH image. The real
	// Sandbox controller still owns suspension, pod replacement and readiness.
	sb := sandboxObject(ns, box.BoxSpec{Ref: box.BoxRef{Tenant: tenant}, Image: "busybox:1.37.0", AutoStart: true}, true, memDefaults{}, podOptions{})
	podSpec := &sb.Spec.PodTemplate.Spec
	podSpec.Containers[0].Command = []string{"sleep", "3600"}
	podSpec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: dataVolume, MountPath: dataMount}}
	podSpec.Volumes = []corev1.Volume{{Name: dataVolume, VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: pvcName}}}}
	podSpec.SecurityContext.FSGroup = int64p(1000)
	if _, err = b.sandboxes.AgentsV1beta1().Sandboxes(ns).Create(ctx, sb, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	var pod string
	if err = wait.PollUntilContextCancel(ctx, time.Second, true, func(ctx context.Context) (bool, error) {
		pods, err := b.clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return false, err
		}
		for _, p := range pods.Items {
			for _, c := range p.Status.Conditions {
				if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
					pod = p.Name
					return true, nil
				}
			}
		}
		return false, nil
	}); err != nil {
		t.Fatal(err)
	}
	run := func(script string) string {
		t.Helper()
		out, err := exec.CommandContext(ctx, "kubectl", "-n", ns, "exec", pod, "--", "sh", "-ec", script).CombinedOutput()
		if err != nil {
			t.Fatalf("box command failed: %v: %s", err, out)
		}
		return string(out)
	}
	run("printf 'snapshot-proof\\n' > /home/agent/workspace/marker; sync")
	mgr := backup.NewManager(nil, nil, t.TempDir(), backup.WithSnapshots(b))
	rec, err := mgr.CreateSnapshot(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	records, err := mgr.List(tenant)
	if err != nil || len(records) != 1 {
		t.Fatalf("list %+v %v", records, err)
	}
	run("rm /home/agent/workspace/marker; sync; test ! -e /home/agent/workspace/marker")
	if err = mgr.RestoreSnapshot(ctx, rec); err != nil {
		t.Fatal(err)
	}
	pods, err := b.clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
	if err != nil || len(pods.Items) != 1 {
		t.Fatalf("restored pods %+v %v", pods, err)
	}
	pod = pods.Items[0].Name
	if got := strings.TrimSpace(run("cat /home/agent/workspace/marker")); got != "snapshot-proof" {
		t.Fatalf("restored content %q", got)
	}
	claim, err := b.activeDataClaim(ctx, tenant)
	if err != nil || claim == pvcName {
		t.Fatalf("restored claim %q %v", claim, err)
	}
	if err = mgr.DeleteContext(ctx, rec.ID); err != nil {
		t.Fatal(err)
	}
	snapshots, err := b.dyn.Resource(snapshotGVR).Namespace(ns).List(ctx, metav1.ListOptions{})
	if err != nil || len(snapshots.Items) != 0 {
		t.Fatalf("snapshot leak %+v %v", snapshots, err)
	}
}
