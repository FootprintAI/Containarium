// Package controller holds the Box CRD reconciler — the operator half of the
// Kubernetes agent-box control plane (#995). It reconciles a containarium.dev
// Box into the per-tenant bundle by delegating to a box.BoxBackend, the same
// Create/Delete the imperative API uses, so both paths converge on one builder.
package controller

import (
	"context"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	containariumv1alpha1 "github.com/footprintai/containarium/apis/containarium/v1alpha1"
	box "github.com/footprintai/containarium/pkg/core/box"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// boxFinalizer makes the reconciler tear the box down via the backend before
// the Box CR is removed from the API server.
const boxFinalizer = "containarium.dev/box"

// requeueInterval refreshes status while a box is still coming up.
const requeueInterval = 30 * time.Second

// BoxReconciler reconciles a Box into the per-tenant agent-box bundle
// (Sandbox + Pipe + Secret + NetworkPolicy) by delegating to a box.BoxBackend.
// It owns only the Box CR's finalizer and status; the backend owns the
// downstream objects.
type BoxReconciler struct {
	client.Client
	Backend box.BoxBackend
}

// +kubebuilder:rbac:groups=containarium.dev,resources=boxes,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=containarium.dev,resources=boxes/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=containarium.dev,resources=boxes/finalizers,verbs=update

// Reconcile drives the cluster toward the Box's spec.
func (r *BoxReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var b containariumv1alpha1.Box
	if err := r.Get(ctx, req.NamespacedName, &b); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	ref := box.BoxRef{Tenant: tenantOf(&b)}

	// Deletion: tear down via the backend, then drop the finalizer.
	if !b.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(&b, boxFinalizer) {
			if err := r.Backend.Delete(ctx, ref, false); err != nil {
				return ctrl.Result{}, fmt.Errorf("delete box %q: %w", ref.Tenant, err)
			}
			controllerutil.RemoveFinalizer(&b, boxFinalizer)
			if err := r.Update(ctx, &b); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	// Ensure the finalizer before creating anything the backend must clean up.
	if controllerutil.AddFinalizer(&b, boxFinalizer) {
		if err := r.Update(ctx, &b); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Create/ensure the box (idempotent) — the single convergent builder.
	st, err := r.Backend.Create(ctx, specFromBox(&b))
	if err != nil {
		b.Status.Phase = containariumv1alpha1.BoxFailed
		meta.SetStatusCondition(&b.Status.Conditions, metav1.Condition{
			Type:               "Ready",
			Status:             metav1.ConditionFalse,
			Reason:             "CreateFailed",
			Message:            err.Error(),
			ObservedGeneration: b.Generation,
		})
		_ = r.Status().Update(ctx, &b)
		return ctrl.Result{}, fmt.Errorf("ensure box %q: %w", ref.Tenant, err)
	}

	r.applyStatus(ctx, &b, st)
	if err := r.Status().Update(ctx, &b); err != nil {
		return ctrl.Result{}, err
	}
	// Re-check while the pod may still be starting.
	if b.Status.Phase != containariumv1alpha1.BoxRunning {
		return ctrl.Result{RequeueAfter: requeueInterval}, nil
	}
	return ctrl.Result{}, nil
}

// applyStatus maps the backend's BoxStatus onto the Box CR's status subresource.
func (r *BoxReconciler) applyStatus(ctx context.Context, b *containariumv1alpha1.Box, st *box.BoxStatus) {
	b.Status.ObservedGeneration = b.Generation
	b.Status.PodName = st.Ref.Name
	b.Status.Phase = phaseFromState(st.State)
	if ep, err := r.Backend.Resolve(ctx, box.BoxRef{Tenant: tenantOf(b)}); err == nil && ep != nil {
		b.Status.Endpoint = endpointString(ep)
	}
	ready, reason := metav1.ConditionFalse, "Provisioning"
	if b.Status.Phase == containariumv1alpha1.BoxRunning {
		ready, reason = metav1.ConditionTrue, "Running"
	}
	meta.SetStatusCondition(&b.Status.Conditions, metav1.Condition{
		Type:               "Ready",
		Status:             ready,
		Reason:             reason,
		Message:            fmt.Sprintf("box is %s", b.Status.Phase),
		ObservedGeneration: b.Generation,
	})
}

// SetupWithManager registers the reconciler with a controller-runtime manager.
func (r *BoxReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&containariumv1alpha1.Box{}).
		Named("box").
		Complete(r)
}

// tenantOf resolves the routing key: spec.tenant, defaulting to the CR name.
func tenantOf(b *containariumv1alpha1.Box) string {
	if b.Spec.Tenant != "" {
		return b.Spec.Tenant
	}
	return b.Name
}

// specFromBox translates a Box CR into the runtime-neutral box.BoxSpec.
func specFromBox(b *containariumv1alpha1.Box) box.BoxSpec {
	autoStart := true
	if b.Spec.AutoStart != nil {
		autoStart = *b.Spec.AutoStart
	}
	return box.BoxSpec{
		Ref:   box.BoxRef{Tenant: tenantOf(b)},
		Image: b.Spec.Image,
		Mode:  b.Spec.Mode,
		Resources: box.ResourceLimits{
			CPU:          b.Spec.Resources.CPU,
			Memory:       b.Spec.Resources.Memory,
			Disk:         b.Spec.Resources.Disk,
			StorageClass: b.Spec.Resources.StorageClass,
		},
		SSHKeys:       b.Spec.SSHKeys,
		Labels:        b.Spec.Labels,
		Stack:         b.Spec.Stack,
		StackParams:   b.Spec.StackParams,
		GitSource:     b.Spec.GitSource,
		GitRef:        b.Spec.GitRef,
		WorkspacePath: b.Spec.WorkspacePath,
		AutoStart:     autoStart,
	}
}

// phaseFromState maps the backend's container state onto a Box phase.
func phaseFromState(s pb.ContainerState) containariumv1alpha1.BoxPhase {
	switch s {
	case pb.ContainerState_CONTAINER_STATE_RUNNING:
		return containariumv1alpha1.BoxRunning
	case pb.ContainerState_CONTAINER_STATE_STOPPED, pb.ContainerState_CONTAINER_STATE_FROZEN:
		return containariumv1alpha1.BoxSuspended
	case pb.ContainerState_CONTAINER_STATE_ERROR:
		return containariumv1alpha1.BoxFailed
	default:
		return containariumv1alpha1.BoxPending
	}
}

// endpointString renders a BoxEndpoint as the human-facing connect target.
func endpointString(ep *box.BoxEndpoint) string {
	if ep.SSHHost == "" {
		return ep.DirectIP
	}
	if ep.SSHUser != "" {
		return fmt.Sprintf("%s@%s", ep.SSHUser, ep.SSHHost)
	}
	return ep.SSHHost
}
