package controller

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	containariumv1alpha1 "github.com/footprintai/containarium/apis/containarium/v1alpha1"
	box "github.com/footprintai/containarium/pkg/core/box"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// The Box spec carries isolation and TTL both ways (#3688). A K8s box cannot be
// a VM, and a TTL expires the box instead of being ignored.

func TestBoxSpecRoundTripsIsolationAndTTL(t *testing.T) {
	in := box.BoxSpec{
		Isolation: pb.IsolationType_ISOLATION_TYPE_VM,
		TTL:       2 * time.Hour,
	}
	crSpec := boxFromSpec(in, "default").Spec
	if crSpec.Isolation != "vm" {
		t.Errorf("CR isolation = %q, want vm", crSpec.Isolation)
	}
	if crSpec.TTLSeconds == nil || *crSpec.TTLSeconds != 7200 {
		t.Errorf("CR ttlSeconds = %v, want 7200", crSpec.TTLSeconds)
	}
	back := specFromBox(&containariumv1alpha1.Box{
		ObjectMeta: metav1.ObjectMeta{Name: "alice", Namespace: "default"},
		Spec:       crSpec,
	})
	if back.Isolation != pb.IsolationType_ISOLATION_TYPE_VM {
		t.Errorf("round-trip isolation = %v, want VM", back.Isolation)
	}
	if back.TTL != 2*time.Hour {
		t.Errorf("round-trip TTL = %v, want 2h", back.TTL)
	}
}

func TestBoxSpecDefaultsAreContainerAndNoTTL(t *testing.T) {
	crSpec := boxFromSpec(box.BoxSpec{}, "default").Spec
	if crSpec.Isolation != "container" {
		t.Errorf("default isolation = %q, want container", crSpec.Isolation)
	}
	if crSpec.TTLSeconds != nil {
		t.Errorf("default ttlSeconds = %v, want none", *crSpec.TTLSeconds)
	}
	back := specFromBox(&containariumv1alpha1.Box{Spec: containariumv1alpha1.BoxSpec{}})
	if back.Isolation != pb.IsolationType_ISOLATION_TYPE_CONTAINER || back.TTL != 0 {
		t.Errorf("empty CR reads as isolation=%v ttl=%v, want container and none", back.Isolation, back.TTL)
	}
}

// boxWithFinalizer is a Box already past the first reconcile, so the isolation
// and TTL checks run on the first call.
func boxWithFinalizer(name string, created time.Time, spec containariumv1alpha1.BoxSpec) *containariumv1alpha1.Box {
	return &containariumv1alpha1.Box{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: "default",
			CreationTimestamp: metav1.NewTime(created),
			Finalizers:        []string{boxFinalizer},
		},
		Spec: spec,
	}
}

func TestReconcileRefusesVMIsolation(t *testing.T) {
	s := testScheme(t)
	b := boxWithFinalizer("alice", time.Now(), containariumv1alpha1.BoxSpec{Isolation: "vm"})
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(b).WithStatusSubresource(b).Build()
	be := &fakeBackend{}
	r := &BoxReconciler{Client: cl, Backend: be}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "alice", Namespace: "default"}}

	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if len(be.created) != 0 {
		t.Fatalf("a VM-isolated K8s box reached the backend: %v", be.created)
	}
	var got containariumv1alpha1.Box
	if err := cl.Get(context.Background(), req.NamespacedName, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.Phase != containariumv1alpha1.BoxFailed {
		t.Errorf("phase = %q, want Failed", got.Status.Phase)
	}
	var reason string
	for _, c := range got.Status.Conditions {
		if c.Type == "Ready" {
			reason = c.Reason
		}
	}
	if reason != "IsolationUnsupported" {
		t.Errorf("Ready reason = %q, want IsolationUnsupported", reason)
	}
}

func TestReconcileExpiresABoxPastItsTTL(t *testing.T) {
	s := testScheme(t)
	created := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	ttl := int64(60)
	b := boxWithFinalizer("alice", created, containariumv1alpha1.BoxSpec{TTLSeconds: &ttl})
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(b).WithStatusSubresource(b).Build()
	be := &fakeBackend{}
	r := &BoxReconciler{Client: cl, Backend: be, Now: func() time.Time { return created.Add(2 * time.Minute) }}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "alice", Namespace: "default"}}

	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if len(be.created) != 0 {
		t.Fatalf("an expired box was created: %v", be.created)
	}
	var got containariumv1alpha1.Box
	if err := cl.Get(context.Background(), req.NamespacedName, &got); err != nil {
		t.Fatal(err)
	}
	if got.DeletionTimestamp == nil {
		t.Error("expired box was not deleted (no deletionTimestamp)")
	}
}

func TestReconcileRequeuesAtTheTTLExpiry(t *testing.T) {
	s := testScheme(t)
	created := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	ttl := int64(300)
	b := boxWithFinalizer("alice", created, containariumv1alpha1.BoxSpec{TTLSeconds: &ttl})
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(b).WithStatusSubresource(b).Build()
	be := &fakeBackend{}
	r := &BoxReconciler{Client: cl, Backend: be, Now: func() time.Time { return created.Add(100 * time.Second) }}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "alice", Namespace: "default"}}

	res, err := r.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if len(be.created) != 1 {
		t.Fatalf("a live box was not created: %v", be.created)
	}
	if res.RequeueAfter != 200*time.Second {
		t.Errorf("RequeueAfter = %v, want 200s (the time left before expiry)", res.RequeueAfter)
	}
}
