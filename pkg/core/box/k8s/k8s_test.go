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
	if _, err := cs.AppsV1().StatefulSets(ns).Get(ctx, statefulSetName, metav1.GetOptions{}); err != nil {
		t.Errorf("statefulset not created: %v", err)
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
