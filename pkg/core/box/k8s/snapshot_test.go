package k8s

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/pkg/core/backup"
	"github.com/footprintai/containarium/pkg/core/box"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	sandboxv1beta1 "sigs.k8s.io/agent-sandbox/api/v1beta1"
	sandboxfake "sigs.k8s.io/agent-sandbox/clients/k8s/clientset/versioned/fake"
)

func snapshotFixture(t *testing.T) (*Backend, *dynamicfake.FakeDynamicClient, *fake.Clientset, *sandboxfake.Clientset) {
	t.Helper()
	ns := "tenant-example"
	cs := fake.NewSimpleClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}, &storagev1.StorageClass{ObjectMeta: metav1.ObjectMeta{Name: "csi"}, Provisioner: "example.csi"}, pvcObject(ns, "example", "csi", "1Gi"))
	cs.Resources = []*metav1.APIResourceList{{GroupVersion: "snapshot.storage.k8s.io/v1", APIResources: []metav1.APIResource{{Name: "volumesnapshots"}, {Name: "volumesnapshotclasses"}, {Name: "volumesnapshotcontents"}}}}
	source, err := cs.CoreV1().PersistentVolumeClaims(ns).Get(context.Background(), pvcName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	source.Status.Phase = corev1.ClaimBound
	if _, err = cs.CoreV1().PersistentVolumeClaims(ns).UpdateStatus(context.Background(), source, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	sb := sandboxObject(ns, box.BoxSpec{Ref: box.BoxRef{Tenant: "example"}, Image: "example.com/box:test", AutoStart: true}, true, memDefaults{}, podOptions{})
	sc := sandboxfake.NewSimpleClientset()
	if _, err := sc.AgentsV1beta1().Sandboxes(ns).Create(context.Background(), sb, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	class := &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": "snapshot.storage.k8s.io/v1", "kind": "VolumeSnapshotClass", "metadata": map[string]interface{}{"name": "csi"}, "driver": "example.csi", "deletionPolicy": "Delete"}}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{snapshotGVR: "VolumeSnapshotList", snapshotClassGVR: "VolumeSnapshotClassList"}, class)
	dyn.PrependReactor("create", "volumesnapshots", func(a ktesting.Action) (bool, runtime.Object, error) {
		obj := a.(ktesting.CreateAction).GetObject().(*unstructured.Unstructured)
		obj.SetUID(types.UID("uid-" + obj.GetName()))
		obj.Object["status"] = map[string]interface{}{"readyToUse": true, "restoreSize": "1Gi"}
		return false, nil, nil
	})
	b := NewWithClients(cs, sc, dyn, Config{StorageClass: "csi", BoxImage: "example.com/box:test"})
	return b, dyn, cs, sc
}

func TestSnapshotLifecycleAndRestoreUsesNewPVC(t *testing.T) {
	ctx := context.Background()
	b, dyn, cs, sc := snapshotFixture(t)
	m := backup.NewManager(nil, nil, t.TempDir(), backup.WithSnapshots(b))
	rec, err := m.CreateSnapshot(ctx, "example")
	if err != nil {
		t.Fatal(err)
	}
	listed, err := m.List("example")
	if err != nil || len(listed) != 1 {
		t.Fatalf("list %v %v", listed, err)
	}
	sc.PrependReactor("update", "sandboxes", func(a ktesting.Action) (bool, runtime.Object, error) {
		sb := a.(ktesting.UpdateAction).GetObject().(*sandboxv1beta1.Sandbox)
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "restored", Namespace: sb.Namespace, Labels: boxLabels("example")}, Spec: sb.Spec.PodTemplate.Spec, Status: corev1.PodStatus{Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}}
		_, err := cs.CoreV1().Pods(sb.Namespace).Create(ctx, pod, metav1.CreateOptions{})
		return false, nil, err
	})
	if err = m.RestoreSnapshot(ctx, rec); err != nil {
		t.Fatal(err)
	}
	claim, err := b.activeDataClaim(ctx, "example")
	if err != nil || claim == pvcName {
		t.Fatalf("claim %s %v", claim, err)
	}
	pvc, err := cs.CoreV1().PersistentVolumeClaims("tenant-example").Get(ctx, claim, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if pvc.Spec.DataSource == nil || pvc.Spec.DataSource.Name != rec.Snapshot.Name {
		t.Fatalf("restore datasource %+v", pvc.Spec.DataSource)
	}
	if _, err = cs.CoreV1().PersistentVolumeClaims("tenant-example").Get(ctx, pvcName, metav1.GetOptions{}); err != nil {
		t.Fatal("original PVC lost:", err)
	}
	pvc.Status.Phase = corev1.ClaimBound
	if _, err = cs.CoreV1().PersistentVolumeClaims("tenant-example").UpdateStatus(ctx, pvc, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	// A later backup must snapshot the restored disk, not the original data PVC.
	next, err := m.CreateSnapshot(ctx, "example")
	if err != nil {
		t.Fatal(err)
	}
	obj, err := dyn.Resource(snapshotGVR).Namespace("tenant-example").Get(ctx, next.Snapshot.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	source, _, _ := unstructured.NestedString(obj.Object, "spec", "source", "persistentVolumeClaimName")
	if source != claim {
		t.Fatalf("snapshotted %s, want %s", source, claim)
	}
	// Prove deletion is routed to CSI, never os.Remove(snapshot://...).
	if err = m.DeleteContext(ctx, rec.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = dyn.Resource(snapshotGVR).Namespace("tenant-example").Get(ctx, rec.Snapshot.Name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("snapshot still exists: %v", err)
	}
	if _, err = m.Get(rec.ID); err == nil {
		t.Fatal("metadata still exists")
	}
}

func TestSnapshotUnsupportedCreatesNothing(t *testing.T) {
	for _, scenario := range []string{"no-crds", "missing-contents-crd", "no-class", "wrong-driver", "retain", "ambiguous"} {
		t.Run(scenario, func(t *testing.T) {
			b, dyn, cs, _ := snapshotFixture(t)
			switch scenario {
			case "missing-contents-crd":
				cs.Resources[0].APIResources = cs.Resources[0].APIResources[:2]
			case "no-crds":
				dyn.PrependReactor("list", "volumesnapshots", func(ktesting.Action) (bool, runtime.Object, error) {
					return true, nil, apierrors.NewNotFound(snapshotGVR.GroupResource(), "")
				})
			case "no-class":
				if err := dyn.Resource(snapshotClassGVR).Delete(context.Background(), "csi", metav1.DeleteOptions{}); err != nil {
					t.Fatal(err)
				}
			default:
				class, err := dyn.Resource(snapshotClassGVR).Get(context.Background(), "csi", metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if scenario == "wrong-driver" {
					class.Object["driver"] = "other.csi"
				}
				if scenario == "retain" {
					class.Object["deletionPolicy"] = "Retain"
				}
				if scenario == "ambiguous" {
					class.SetName("second")
					_, err = dyn.Resource(snapshotClassGVR).Create(context.Background(), class, metav1.CreateOptions{})
				} else {
					_, err = dyn.Resource(snapshotClassGVR).Update(context.Background(), class, metav1.UpdateOptions{})
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			dyn.ClearActions()
			cs.ClearActions()
			if _, err := b.CreateVolumeSnapshot(context.Background(), "example", "backup"); err == nil {
				t.Fatal("expected unsupported error")
			}
			for _, a := range append(dyn.Actions(), cs.Actions()...) {
				if a.GetVerb() == "create" {
					t.Fatalf("created %s without support", a.GetResource())
				}
			}
		})
	}
}

func TestSnapshotFailedOrTimedOutIsCleanedUp(t *testing.T) {
	for _, scenario := range []string{"error", "timeout"} {
		t.Run(scenario, func(t *testing.T) {
			b, dyn, _, _ := snapshotFixture(t)
			dyn.PrependReactor("get", "volumesnapshots", func(a ktesting.Action) (bool, runtime.Object, error) {
				obj, err := dyn.Tracker().Get(snapshotGVR, a.GetNamespace(), a.(ktesting.GetAction).GetName())
				if err != nil {
					return true, nil, err
				}
				snap := obj.(*unstructured.Unstructured).DeepCopy()
				snap.Object["status"] = map[string]interface{}{"readyToUse": false}
				if scenario == "error" {
					snap.Object["status"].(map[string]interface{})["error"] = map[string]interface{}{"message": "storage failed"}
				}
				return true, snap, nil
			})
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			defer cancel()
			if _, err := b.CreateVolumeSnapshot(ctx, "example", "backup"); err == nil {
				t.Fatal("expected failure")
			}
			if _, err := dyn.Tracker().Get(snapshotGVR, "tenant-example", "backup"); !apierrors.IsNotFound(err) {
				t.Fatalf("failed snapshot leaked: %v", err)
			}
		})
	}
}

func TestSnapshotRejectsChangedIdentityAndNamespace(t *testing.T) {
	b, _, cs, _ := snapshotFixture(t)
	ref, err := b.CreateVolumeSnapshot(context.Background(), "example", "backup")
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"uid", "namespace"} {
		t.Run(scenario, func(t *testing.T) {
			altered := *ref
			switch scenario {
			case "uid":
				altered.UID = "replacement"
			case "namespace":
				altered.Namespace = "tenant-other"
			}
			cs.ClearActions()
			if err := b.RestoreVolumeSnapshot(context.Background(), "example", altered); err == nil {
				t.Fatal("expected refusal")
			}
			for _, a := range cs.Actions() {
				if a.GetVerb() == "create" {
					t.Fatal("created PVC before validating identity")
				}
			}
		})
	}
	if err = b.DeleteVolumeSnapshot(context.Background(), "other", *ref); err == nil || !strings.Contains(err.Error(), "ownership") {
		t.Fatal(err)
	}
}

func TestSnapshotRestoreWaitsForOldPodAndKeepsDisks(t *testing.T) {
	b, _, cs, sc := snapshotFixture(t)
	ref, err := b.CreateVolumeSnapshot(context.Background(), "example", "backup")
	if err != nil {
		t.Fatal(err)
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "old", Namespace: ref.Namespace, Labels: boxLabels("example")}, Status: corev1.PodStatus{Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}}
	if _, err = cs.CoreV1().Pods(ref.Namespace).Create(context.Background(), pod, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err = b.RestoreVolumeSnapshot(ctx, "example", *ref); err == nil {
		t.Fatal("accepted a still-running old pod")
	}
	sb, err := sc.AgentsV1beta1().Sandboxes(ref.Namespace).Get(context.Background(), sandboxName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range sb.Spec.PodTemplate.Spec.Volumes {
		if v.Name == dataVolume && v.PersistentVolumeClaim.ClaimName != pvcName {
			t.Fatal("switched volume before old pod stopped")
		}
	}
	claims, err := cs.CoreV1().PersistentVolumeClaims(ref.Namespace).List(context.Background(), metav1.ListOptions{})
	if err != nil || len(claims.Items) != 2 {
		t.Fatalf("expected retained original and restore PVC: %+v %v", claims, err)
	}
}
