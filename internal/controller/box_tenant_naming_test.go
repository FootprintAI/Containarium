package controller

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	containariumv1alpha1 "github.com/footprintai/containarium/apis/containarium/v1alpha1"
	box "github.com/footprintai/containarium/pkg/core/box"
)

// A hand-applied Box CR whose spec.tenant carries the reserved -container-
// infix or -container suffix is refused before any finalizer is added or the
// backend Create runs (#3630).
func TestReconcileRejectsCollidingTenantOnNewBox(t *testing.T) {
	for _, tenant := range []string{"owner-a-container-b", "owner-a-container"} {
		t.Run(tenant, func(t *testing.T) {
			s := testScheme(t)
			b := &containariumv1alpha1.Box{
				ObjectMeta: metav1.ObjectMeta{Name: "crbox", Namespace: "default"},
				Spec:       containariumv1alpha1.BoxSpec{Tenant: tenant},
			}
			cl := fake.NewClientBuilder().WithScheme(s).WithObjects(b).WithStatusSubresource(b).Build()
			be := &fakeBackend{}
			r := &BoxReconciler{Client: cl, Backend: be}
			req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "crbox", Namespace: "default"}}
			ctx := context.Background()

			if _, err := r.Reconcile(ctx, req); err != nil {
				t.Fatalf("reconcile: %v", err)
			}
			if len(be.created) != 0 {
				t.Fatalf("backend Create ran for rejected tenant: %v", be.created)
			}
			var got containariumv1alpha1.Box
			if err := cl.Get(ctx, req.NamespacedName, &got); err != nil {
				t.Fatal(err)
			}
			if controllerutil.ContainsFinalizer(&got, boxFinalizer) {
				t.Error("finalizer added to a rejected Box")
			}
			if got.Status.Phase != containariumv1alpha1.BoxFailed {
				t.Errorf("phase = %q, want Failed", got.Status.Phase)
			}
		})
	}
}

// The daemon's CR writer refuses to create a Box with a colliding tenant, but
// still updates one that already exists (existing names are audited, not
// renamed).
func TestUpsertBoxRejectsCollidingTenantOnCreate(t *testing.T) {
	for _, tenant := range []string{"owner-a-container-b", "owner-a-container"} {
		t.Run(tenant, func(t *testing.T) {
			cl := fake.NewClientBuilder().WithScheme(testScheme(t)).Build()
			err := upsertBox(context.Background(), cl, "default", box.BoxSpec{Ref: box.BoxRef{Tenant: tenant}})
			if err == nil {
				t.Fatal("upsertBox accepted a colliding tenant")
			}
			var list containariumv1alpha1.BoxList
			if lerr := cl.List(context.Background(), &list); lerr != nil || len(list.Items) != 0 {
				t.Fatalf("Box CR was created: %v %v", lerr, list.Items)
			}
		})
	}

	t.Run("existing box still updates", func(t *testing.T) {
		existing := &containariumv1alpha1.Box{
			ObjectMeta: metav1.ObjectMeta{Name: "legacy-container-x", Namespace: "default"},
			Spec:       containariumv1alpha1.BoxSpec{Tenant: "legacy-container-x"},
		}
		cl := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(existing).Build()
		spec := box.BoxSpec{Ref: box.BoxRef{Tenant: "legacy-container-x"}, Image: "img2"}
		if err := upsertBox(context.Background(), cl, "default", spec); err != nil {
			t.Fatalf("update of existing box rejected: %v", err)
		}
	})
}
