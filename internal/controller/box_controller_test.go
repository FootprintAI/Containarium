package controller

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	containariumv1alpha1 "github.com/footprintai/containarium/apis/containarium/v1alpha1"
	box "github.com/footprintai/containarium/pkg/core/box"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// fakeBackend is a minimal box.BoxBackend that records Create/Delete and
// reports a running box, so reconcile logic can be tested without a cluster.
type fakeBackend struct {
	created   []box.BoxSpec
	deleted   []string
	createErr error
}

func (f *fakeBackend) Kind() box.BackendKind { return "" }
func (f *fakeBackend) Create(_ context.Context, spec box.BoxSpec) (*box.BoxStatus, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	f.created = append(f.created, spec)
	return &box.BoxStatus{
		Ref:   box.BoxRef{Tenant: spec.Ref.Tenant, Name: "box-" + spec.Ref.Tenant},
		State: pb.ContainerState_CONTAINER_STATE_RUNNING,
	}, nil
}
func (f *fakeBackend) Start(context.Context, box.BoxRef) error      { return nil }
func (f *fakeBackend) Stop(context.Context, box.BoxRef, bool) error { return nil }
func (f *fakeBackend) Delete(_ context.Context, ref box.BoxRef, _ bool) error {
	f.deleted = append(f.deleted, ref.Tenant)
	return nil
}
func (f *fakeBackend) Get(context.Context, box.BoxRef) (*box.BoxStatus, error) { return nil, nil }
func (f *fakeBackend) List(context.Context) ([]box.BoxStatus, error)           { return nil, nil }
func (f *fakeBackend) Resolve(_ context.Context, ref box.BoxRef) (*box.BoxEndpoint, error) {
	return &box.BoxEndpoint{SSHHost: "gw.example.com", SSHPort: 22, SSHUser: ref.Tenant}, nil
}
func (f *fakeBackend) SetAuthorizedKeys(context.Context, box.BoxRef, []string) error { return nil }
func (f *fakeBackend) Resize(context.Context, box.BoxRef, box.ResourceLimits) error  { return nil }
func (f *fakeBackend) SetMeta(context.Context, box.BoxRef, map[string]string) error  { return nil }
func (f *fakeBackend) GetMeta(context.Context, box.BoxRef) (map[string]string, error) {
	return nil, nil
}

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := containariumv1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	return s
}

// TestReconcileCreate: first reconcile adds the finalizer (no Create yet);
// second reconcile creates the box and writes status.
func TestReconcileCreate(t *testing.T) {
	s := testScheme(t)
	b := &containariumv1alpha1.Box{
		ObjectMeta: metav1.ObjectMeta{Name: "alice", Namespace: "default"},
		Spec:       containariumv1alpha1.BoxSpec{Mode: "shell", SSHKeys: []string{"ssh-ed25519 AAA"}},
	}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(b).WithStatusSubresource(b).Build()
	be := &fakeBackend{}
	r := &BoxReconciler{Client: cl, Backend: be}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "alice", Namespace: "default"}}
	ctx := context.Background()

	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("reconcile 1: %v", err)
	}
	var got containariumv1alpha1.Box
	if err := cl.Get(ctx, req.NamespacedName, &got); err != nil {
		t.Fatal(err)
	}
	if !controllerutil.ContainsFinalizer(&got, boxFinalizer) {
		t.Fatal("finalizer not added on first reconcile")
	}
	if len(be.created) != 0 {
		t.Fatalf("Create called before finalizer was set: %v", be.created)
	}

	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("reconcile 2: %v", err)
	}
	if len(be.created) != 1 || be.created[0].Ref.Tenant != "alice" {
		t.Fatalf("Create not called for alice: %v", be.created)
	}
	if be.created[0].Mode != "shell" {
		t.Errorf("spec.Mode = %q, want shell", be.created[0].Mode)
	}
	if err := cl.Get(ctx, req.NamespacedName, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.Phase != containariumv1alpha1.BoxRunning {
		t.Errorf("phase = %q, want Running", got.Status.Phase)
	}
	if got.Status.PodName != "box-alice" {
		t.Errorf("podName = %q, want box-alice", got.Status.PodName)
	}
	if got.Status.Endpoint != "alice@gw.example.com" {
		t.Errorf("endpoint = %q, want alice@gw.example.com", got.Status.Endpoint)
	}
	if meta := got.Status.Conditions; len(meta) != 1 || meta[0].Type != "Ready" || meta[0].Status != metav1.ConditionTrue {
		t.Errorf("Ready condition not set true: %+v", got.Status.Conditions)
	}
}

// TestReconcileDelete: a Box under deletion is torn down via the backend, then
// the finalizer is removed and the object is gone.
func TestReconcileDelete(t *testing.T) {
	s := testScheme(t)
	b := &containariumv1alpha1.Box{
		ObjectMeta: metav1.ObjectMeta{Name: "bob", Namespace: "default", Finalizers: []string{boxFinalizer}},
	}
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(b).WithStatusSubresource(b).Build()
	be := &fakeBackend{}
	r := &BoxReconciler{Client: cl, Backend: be}
	ctx := context.Background()

	// Deleting an object that still has a finalizer marks it terminating.
	if err := cl.Delete(ctx, b); err != nil {
		t.Fatal(err)
	}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "bob", Namespace: "default"}}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("reconcile delete: %v", err)
	}
	if len(be.deleted) != 1 || be.deleted[0] != "bob" {
		t.Fatalf("Delete not called for bob: %v", be.deleted)
	}
	var got containariumv1alpha1.Box
	if err := cl.Get(ctx, req.NamespacedName, &got); err == nil {
		t.Error("Box should be gone after the finalizer is removed")
	}
}
