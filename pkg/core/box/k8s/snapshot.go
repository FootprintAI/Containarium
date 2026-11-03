package k8s

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/footprintai/containarium/pkg/core/backup"
	"github.com/footprintai/containarium/pkg/core/box"

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	sandboxv1beta1 "sigs.k8s.io/agent-sandbox/api/v1beta1"
)

var snapshotGVR = schema.GroupVersionResource{Group: "snapshot.storage.k8s.io", Version: "v1", Resource: "volumesnapshots"}
var snapshotClassGVR = schema.GroupVersionResource{Group: "snapshot.storage.k8s.io", Version: "v1", Resource: "volumesnapshotclasses"}

const snapshotTimeout = 5 * time.Minute

var _ backup.SnapshotOps = (*Backend)(nil)

// activeDataClaim follows the Sandbox template, including a previous restore.
func (b *Backend) activeDataClaim(ctx context.Context, tenant string) (string, error) {
	sb, err := b.sandboxes.AgentsV1beta1().Sandboxes(b.namespaceFor(tenant)).Get(ctx, sandboxName, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	for _, v := range sb.Spec.PodTemplate.Spec.Volumes {
		if v.Name == dataVolume && v.PersistentVolumeClaim != nil {
			return v.PersistentVolumeClaim.ClaimName, nil
		}
	}
	return "", fmt.Errorf("box has no persistent data PVC; configure a CSI StorageClass")
}

// snapshotClass checks both snapshot APIs before creating any resource. Classes
// must match the actual PVC's StorageClass provisioner, not a daemon default.
func (b *Backend) snapshotClass(ctx context.Context, ns, storageClass string) (string, error) {
	if b.dyn == nil {
		return "", fmt.Errorf("CSI snapshot client is unavailable")
	}
	resources, err := b.clientset.Discovery().ServerResourcesForGroupVersion("snapshot.storage.k8s.io/v1")
	if err != nil {
		return "", fmt.Errorf("CSI snapshot APIs unavailable (install snapshot CRDs): %w", err)
	}
	available := make(map[string]bool, len(resources.APIResources))
	for _, r := range resources.APIResources {
		available[r.Name] = true
	}
	for _, name := range []string{"volumesnapshots", "volumesnapshotclasses", "volumesnapshotcontents"} {
		if !available[name] {
			return "", fmt.Errorf("CSI snapshot CRD %s is unavailable", name)
		}
	}
	if _, err := b.dyn.Resource(snapshotGVR).Namespace(ns).List(ctx, metav1.ListOptions{Limit: 1}); err != nil {
		return "", fmt.Errorf("CSI VolumeSnapshot API unavailable (install snapshot CRDs/controller and check RBAC): %w", err)
	}
	sc, err := b.clientset.StorageV1().StorageClasses().Get(ctx, storageClass, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("read source StorageClass: %w", err)
	}
	classes, err := b.dyn.Resource(snapshotClassGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return "", fmt.Errorf("CSI VolumeSnapshotClass API unavailable: %w", err)
	}
	var candidates, defaults []string
	for _, c := range classes.Items {
		driver, _, _ := unstructured.NestedString(c.Object, "driver")
		policy, _, _ := unstructured.NestedString(c.Object, "deletionPolicy")
		if driver != sc.Provisioner || policy != "Delete" {
			continue
		}
		candidates = append(candidates, c.GetName())
		if c.GetAnnotations()["snapshot.storage.kubernetes.io/is-default-class"] == "true" {
			defaults = append(defaults, c.GetName())
		}
	}
	if len(defaults) == 1 {
		return defaults[0], nil
	}
	if len(defaults) == 0 && len(candidates) == 1 {
		return candidates[0], nil
	}
	return "", fmt.Errorf("StorageClass %q needs one unambiguous matching VolumeSnapshotClass with deletionPolicy=Delete (found %d, defaults %d)", storageClass, len(candidates), len(defaults))
}

func (b *Backend) CreateVolumeSnapshot(ctx context.Context, tenant, name string) (_ *backup.SnapshotReference, resultErr error) {
	if !b.snapshotMu.TryLock() {
		return nil, fmt.Errorf("another snapshot operation is in progress; retry")
	}
	defer b.snapshotMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, snapshotTimeout)
	defer cancel()
	if err := b.validateTenantName(tenant); err != nil {
		return nil, err
	}
	ns := b.namespaceFor(tenant)
	claim, err := b.activeDataClaim(ctx, tenant)
	if err != nil {
		return nil, err
	}
	pvc, err := b.clientset.CoreV1().PersistentVolumeClaims(ns).Get(ctx, claim, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	if pvc.Status.Phase != corev1.ClaimBound {
		return nil, fmt.Errorf("source PVC is not Bound")
	}
	if pvc.Spec.StorageClassName == nil || *pvc.Spec.StorageClassName == "" {
		return nil, fmt.Errorf("source PVC has no CSI StorageClass")
	}
	class, err := b.snapshotClass(ctx, ns, *pvc.Spec.StorageClassName)
	if err != nil {
		return nil, err
	}
	obj := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "snapshot.storage.k8s.io/v1", "kind": "VolumeSnapshot",
		"metadata": map[string]interface{}{"name": name, "namespace": ns},
		"spec":     map[string]interface{}{"volumeSnapshotClassName": class, "source": map[string]interface{}{"persistentVolumeClaimName": claim}},
	}}
	obj.SetLabels(boxLabels(tenant))
	created, err := b.dyn.Resource(snapshotGVR).Namespace(ns).Create(ctx, obj, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}
	size := pvc.Spec.Resources.Requests[corev1.ResourceStorage]
	ref := &backup.SnapshotReference{Namespace: ns, Name: name, UID: string(created.GetUID()), StorageClass: *pvc.Spec.StorageClassName, Size: size.String()}
	defer func() {
		if resultErr != nil {
			cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			resultErr = errors.Join(resultErr, b.DeleteVolumeSnapshot(cleanup, tenant, *ref))
		}
	}()
	err = wait.PollUntilContextCancel(ctx, 500*time.Millisecond, true, func(ctx context.Context) (bool, error) {
		current, err := b.checkedSnapshot(ctx, tenant, *ref)
		if err != nil {
			return false, err
		}
		ready, _, _ := unstructured.NestedBool(current.Object, "status", "readyToUse")
		if ready {
			if value, ok, _ := unstructured.NestedString(current.Object, "status", "restoreSize"); ok {
				q, err := resource.ParseQuantity(value)
				if err != nil {
					return false, err
				}
				if q.Cmp(size) > 0 {
					ref.Size = q.String()
				}
			}
		}
		return ready, nil
	})
	if err != nil {
		return nil, fmt.Errorf("wait for CSI snapshot ready: %w", err)
	}
	return ref, nil
}

func (b *Backend) checkedSnapshot(ctx context.Context, tenant string, ref backup.SnapshotReference) (*unstructured.Unstructured, error) {
	if err := b.validateTenantName(tenant); err != nil {
		return nil, err
	}
	if ref.Namespace != b.namespaceFor(tenant) || ref.Name == "" || ref.UID == "" {
		return nil, fmt.Errorf("invalid snapshot ownership or identity")
	}
	if b.dyn == nil {
		return nil, fmt.Errorf("CSI snapshot client unavailable")
	}
	obj, err := b.dyn.Resource(snapshotGVR).Namespace(ref.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	if string(obj.GetUID()) != ref.UID {
		return nil, fmt.Errorf("snapshot UID changed; refusing replacement object")
	}
	if message, ok, _ := unstructured.NestedString(obj.Object, "status", "error", "message"); ok {
		return nil, fmt.Errorf("CSI snapshot failed: %s", message)
	}
	return obj, nil
}

func (b *Backend) DeleteVolumeSnapshot(ctx context.Context, tenant string, ref backup.SnapshotReference) error {
	// Do not use checkedSnapshot: a failed snapshot must still be deletable.
	if err := b.validateTenantName(tenant); err != nil {
		return err
	}
	if b.dyn == nil || ref.Namespace != b.namespaceFor(tenant) || ref.UID == "" {
		return fmt.Errorf("invalid snapshot backend or ownership")
	}
	uid := types.UID(ref.UID)
	err := b.dyn.Resource(snapshotGVR).Namespace(ref.Namespace).Delete(ctx, ref.Name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return wait.PollUntilContextTimeout(ctx, 500*time.Millisecond, time.Minute, true, func(ctx context.Context) (bool, error) {
		_, err := b.dyn.Resource(snapshotGVR).Namespace(ref.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		return false, err
	})
}

// RestoreVolumeSnapshot restores in the source namespace, retains the old PVC,
// and changes the template only after the controller has stopped the old pod.
// Keeping the old PVC avoids deleting live data during failed restores.
func (b *Backend) RestoreVolumeSnapshot(ctx context.Context, tenant string, ref backup.SnapshotReference) error {
	if !b.snapshotMu.TryLock() {
		return fmt.Errorf("another snapshot operation is in progress; retry")
	}
	defer b.snapshotMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, snapshotTimeout)
	defer cancel()
	snap, err := b.checkedSnapshot(ctx, tenant, ref)
	if err != nil {
		return err
	}
	ready, _, _ := unstructured.NestedBool(snap.Object, "status", "readyToUse")
	if !ready {
		return fmt.Errorf("snapshot is not readyToUse")
	}
	sbClient := b.sandboxes.AgentsV1beta1().Sandboxes(ref.Namespace)
	sb, err := sbClient.Get(ctx, sandboxName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	volumeIndex := -1
	for i, v := range sb.Spec.PodTemplate.Spec.Volumes {
		if v.Name == dataVolume && v.PersistentVolumeClaim != nil {
			volumeIndex = i
		}
	}
	if volumeIndex < 0 {
		return fmt.Errorf("target box has no data PVC")
	}
	originalUID := sb.UID
	originalClaim := sb.Spec.PodTemplate.Spec.Volumes[volumeIndex].PersistentVolumeClaim.ClaimName
	size, err := resource.ParseQuantity(ref.Size)
	if err != nil {
		return fmt.Errorf("invalid snapshot size: %w", err)
	}
	pvc := pvcObject(ref.Namespace, tenant, ref.StorageClass, ref.Size)
	pvc.Name = "data-restore-" + uuid.NewString()
	group := "snapshot.storage.k8s.io"
	pvc.Spec.DataSource = &corev1.TypedLocalObjectReference{APIGroup: &group, Kind: "VolumeSnapshot", Name: ref.Name}
	pvc.Spec.Resources.Requests[corev1.ResourceStorage] = size
	if _, err = b.clientset.CoreV1().PersistentVolumeClaims(ref.Namespace).Create(ctx, pvc, metav1.CreateOptions{}); err != nil {
		return err
	}
	// Once created, retain the new PVC too: a timed-out API update may have
	// committed, and deleting it could then destroy the box's active volume.
	if err = b.Stop(ctx, box.BoxRef{Tenant: tenant}, false); err != nil {
		return fmt.Errorf("suspend box (new PVC %s retained): %w", pvc.Name, err)
	}
	if err = wait.PollUntilContextCancel(ctx, 500*time.Millisecond, true, func(ctx context.Context) (bool, error) {
		pods, err := b.clientset.CoreV1().Pods(ref.Namespace).List(ctx, metav1.ListOptions{LabelSelector: metav1.FormatLabelSelector(&metav1.LabelSelector{MatchLabels: boxLabels(tenant)})})
		if err != nil {
			return false, err
		}
		return len(pods.Items) == 0, nil
	}); err != nil {
		return fmt.Errorf("wait for old box pod to stop: %w", err)
	}
	// Re-read after suspension; use resourceVersion to reject concurrent edits.
	sb, err = sbClient.Get(ctx, sandboxName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if sb.Spec.OperatingMode != sandboxv1beta1.SandboxOperatingModeSuspended {
		return fmt.Errorf("box was concurrently resumed; retry restore")
	}
	volumeIndex = -1
	for i, v := range sb.Spec.PodTemplate.Spec.Volumes {
		if v.Name == dataVolume && v.PersistentVolumeClaim != nil {
			volumeIndex = i
		}
	}
	if volumeIndex < 0 {
		return fmt.Errorf("box data volume changed during restore")
	}
	if sb.UID != originalUID || sb.Spec.PodTemplate.Spec.Volumes[volumeIndex].PersistentVolumeClaim.ClaimName != originalClaim {
		return fmt.Errorf("box identity or active PVC changed during restore; PVCs retained")
	}
	sb.Spec.PodTemplate.Spec.Volumes[volumeIndex].PersistentVolumeClaim.ClaimName = pvc.Name
	sb.Spec.OperatingMode = sandboxv1beta1.SandboxOperatingModeRunning
	if _, err = sbClient.Update(ctx, sb, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("switch restored PVC (box suspended, PVCs retained): %w", err)
	}
	// WFFC storage binds only after a consumer pod is scheduled. Wait after
	// resuming rather than deadlocking on PVC Bound before creating the pod.
	return wait.PollUntilContextCancel(ctx, 500*time.Millisecond, true, func(ctx context.Context) (bool, error) {
		pods, err := b.clientset.CoreV1().Pods(ref.Namespace).List(ctx, metav1.ListOptions{LabelSelector: metav1.FormatLabelSelector(&metav1.LabelSelector{MatchLabels: boxLabels(tenant)})})
		if err != nil {
			return false, err
		}
		for _, pod := range pods.Items {
			if pod.DeletionTimestamp != nil {
				continue
			}
			mounted := false
			for _, v := range pod.Spec.Volumes {
				if v.PersistentVolumeClaim != nil && v.PersistentVolumeClaim.ClaimName == pvc.Name {
					mounted = true
				}
			}
			if mounted {
				for _, condition := range pod.Status.Conditions {
					if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
						return true, nil
					}
				}
			}
		}
		return false, nil
	})
}
