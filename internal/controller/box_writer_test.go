package controller

import (
	"context"
	"testing"

	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	containariumv1alpha1 "github.com/footprintai/containarium/apis/containarium/v1alpha1"
	box "github.com/footprintai/containarium/pkg/core/box"
)

// TestUpsertBox: the convergent create path writes a Box CR from a BoxSpec, and
// a second upsert updates the existing CR in place (idempotent, like a
// re-create).
func TestUpsertBox(t *testing.T) {
	s := testScheme(t)
	cl := fake.NewClientBuilder().WithScheme(s).Build()
	ctx := context.Background()
	key := ctrlclient.ObjectKey{Namespace: "default", Name: "alice"}

	spec := box.BoxSpec{
		Ref:       box.BoxRef{Tenant: "alice"},
		Image:     "img",
		Mode:      "shell",
		SSHKeys:   []string{"ssh-ed25519 AAA"},
		Resources: box.ResourceLimits{CPU: "2", Memory: "4GB"},
		AutoStart: true,
	}
	if err := upsertBox(ctx, cl, "default", spec); err != nil {
		t.Fatalf("upsert create: %v", err)
	}
	var b containariumv1alpha1.Box
	if err := cl.Get(ctx, key, &b); err != nil {
		t.Fatalf("get after create: %v", err)
	}
	if b.Spec.Tenant != "alice" || b.Spec.Image != "img" || b.Spec.Mode != "shell" {
		t.Errorf("mapped spec wrong: %+v", b.Spec)
	}
	if b.Spec.Resources.CPU != "2" || b.Spec.Resources.Memory != "4GB" {
		t.Errorf("resources not mapped: %+v", b.Spec.Resources)
	}
	if b.Spec.AutoStart == nil || !*b.Spec.AutoStart {
		t.Error("autoStart not mapped to true")
	}

	// Second upsert with a changed field updates in place.
	spec.Image = "img2"
	if err := upsertBox(ctx, cl, "default", spec); err != nil {
		t.Fatalf("upsert update: %v", err)
	}
	if err := cl.Get(ctx, key, &b); err != nil {
		t.Fatal(err)
	}
	if b.Spec.Image != "img2" {
		t.Errorf("update not applied: image = %q, want img2", b.Spec.Image)
	}
}
