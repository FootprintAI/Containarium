package k8s

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	fake "k8s.io/client-go/kubernetes/fake"

	sandboxv1beta1 "sigs.k8s.io/agent-sandbox/api/v1beta1"
	sandboxfake "sigs.k8s.io/agent-sandbox/clients/k8s/clientset/versioned/fake"

	"github.com/footprintai/containarium/pkg/core/box"
)

// resizeBackend wires a Backend over a fake Sandbox already carrying the given
// resource requirements on its agent-box container, so a Resize can be observed
// against a known starting state.
func resizeBackend(t *testing.T, tenant string, start corev1.ResourceRequirements) (*Backend, *sandboxfake.Clientset) {
	t.Helper()
	sc := sandboxfake.NewSimpleClientset()
	if _, err := sc.AgentsV1beta1().Sandboxes("containarium-"+tenant).Create(context.Background(), &sandboxv1beta1.Sandbox{
		ObjectMeta: metav1.ObjectMeta{Name: sandboxName, Namespace: "containarium-" + tenant},
		Spec: sandboxv1beta1.SandboxSpec{
			SandboxBlueprint: sandboxv1beta1.SandboxBlueprint{
				PodTemplate: sandboxv1beta1.PodTemplate{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{Name: "agent-box", Resources: start}},
					},
				},
			},
		},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}
	b := NewWithClients(fake.NewSimpleClientset(), sc, nil, Config{TenantNamespacePrefix: "containarium-"})
	return b, sc
}

func resizedResources(t *testing.T, sc *sandboxfake.Clientset, tenant string) corev1.ResourceRequirements {
	t.Helper()
	sb, err := sc.AgentsV1beta1().Sandboxes("containarium-"+tenant).
		Get(context.Background(), sandboxName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get sandbox: %v", err)
	}
	for _, c := range sb.Spec.PodTemplate.Spec.Containers {
		if c.Name == "agent-box" {
			return c.Resources
		}
	}
	t.Fatal("agent-box container not found")
	return corev1.ResourceRequirements{}
}

func qty(t *testing.T, s string) resource.Quantity {
	t.Helper()
	q, err := resource.ParseQuantity(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return q
}

// A resize that names only CPU must leave the box's memory alone. Resize's own
// contract is "empty = unchanged" — the doc comment says so explicitly about
// the memory default — so an unmentioned axis must survive.
func TestResizeCPUOnlyPreservesMemory(t *testing.T) {
	start := corev1.ResourceRequirements{
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    qty(t, "2"),
			corev1.ResourceMemory: qty(t, "4Gi"),
		},
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    qty(t, "2"),
			corev1.ResourceMemory: qty(t, "4Gi"),
		},
	}
	b, sc := resizeBackend(t, "alice", start)

	if err := b.Resize(context.Background(), box.BoxRef{Tenant: "alice"}, box.ResourceLimits{CPU: "4"}); err != nil {
		t.Fatalf("Resize: %v", err)
	}

	got := resizedResources(t, sc, "alice")

	if c := got.Limits[corev1.ResourceCPU]; c.String() != "4" {
		t.Errorf("cpu limit = %q, want 4", c.String())
	}
	memLimit, ok := got.Limits[corev1.ResourceMemory]
	if !ok {
		t.Fatal("memory limit was DROPPED by a CPU-only resize — an unmentioned axis must survive")
	}
	if memLimit.String() != "4Gi" {
		t.Errorf("memory limit = %q, want 4Gi", memLimit.String())
	}
	memReq, ok := got.Requests[corev1.ResourceMemory]
	if !ok {
		t.Fatal("memory request was DROPPED by a CPU-only resize")
	}
	if memReq.String() != "4Gi" {
		t.Errorf("memory request = %q, want 4Gi", memReq.String())
	}
}

// The mirror case: a memory-only resize must not wipe the CPU ceiling.
func TestResizeMemoryOnlyPreservesCPU(t *testing.T) {
	start := corev1.ResourceRequirements{
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    qty(t, "2"),
			corev1.ResourceMemory: qty(t, "4Gi"),
		},
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    qty(t, "2"),
			corev1.ResourceMemory: qty(t, "4Gi"),
		},
	}
	b, sc := resizeBackend(t, "bob", start)

	if err := b.Resize(context.Background(), box.BoxRef{Tenant: "bob"}, box.ResourceLimits{Memory: "8Gi"}); err != nil {
		t.Fatalf("Resize: %v", err)
	}

	got := resizedResources(t, sc, "bob")

	if m := got.Limits[corev1.ResourceMemory]; m.String() != "8Gi" {
		t.Errorf("memory limit = %q, want 8Gi", m.String())
	}
	cpuLimit, ok := got.Limits[corev1.ResourceCPU]
	if !ok {
		t.Fatal("cpu limit was DROPPED by a memory-only resize — an unmentioned axis must survive")
	}
	if cpuLimit.String() != "2" {
		t.Errorf("cpu limit = %q, want 2", cpuLimit.String())
	}
}

// A resize that changes only the CPU *limit* must not silently move the box's
// scheduler reservation. A Burstable box (request < limit) must stay Burstable
// rather than being re-pinned to Guaranteed. This is #1572.
func TestResizeCPUPreservesBurstableRequest(t *testing.T) {
	start := corev1.ResourceRequirements{
		Limits:   corev1.ResourceList{corev1.ResourceCPU: qty(t, "2")},
		Requests: corev1.ResourceList{corev1.ResourceCPU: qty(t, "500m")},
	}
	b, sc := resizeBackend(t, "carol", start)

	if err := b.Resize(context.Background(), box.BoxRef{Tenant: "carol"}, box.ResourceLimits{CPU: "4"}); err != nil {
		t.Fatalf("Resize: %v", err)
	}

	got := resizedResources(t, sc, "carol")

	if c := got.Limits[corev1.ResourceCPU]; c.String() != "4" {
		t.Errorf("cpu limit = %q, want 4", c.String())
	}
	if r := got.Requests[corev1.ResourceCPU]; r.String() != "500m" {
		t.Errorf("cpu request = %q, want 500m — a limit-only resize must not move the reservation", r.String())
	}
}

// A resize may set the request explicitly, which is what makes a box's
// reservation adjustable after create at all (#1572 — create had
// --cpu-request/--memory-request; resize had no counterpart).
func TestResizeSetsExplicitRequest(t *testing.T) {
	start := corev1.ResourceRequirements{
		Limits:   corev1.ResourceList{corev1.ResourceCPU: qty(t, "2")},
		Requests: corev1.ResourceList{corev1.ResourceCPU: qty(t, "2")},
	}
	b, sc := resizeBackend(t, "dave", start)

	if err := b.Resize(context.Background(), box.BoxRef{Tenant: "dave"},
		box.ResourceLimits{CPU: "4", CPURequest: "500m"}); err != nil {
		t.Fatalf("Resize: %v", err)
	}

	got := resizedResources(t, sc, "dave")
	if c := got.Limits[corev1.ResourceCPU]; c.String() != "4" {
		t.Errorf("cpu limit = %q, want 4", c.String())
	}
	if r := got.Requests[corev1.ResourceCPU]; r.String() != "500m" {
		t.Errorf("cpu request = %q, want 500m", r.String())
	}
}

// A request carried over from a larger previous limit must be clamped down:
// K8s rejects a pod whose request exceeds its limit, so shrinking a box would
// otherwise write a spec the API server refuses.
func TestResizeClampsPreservedRequestToNewLimit(t *testing.T) {
	start := corev1.ResourceRequirements{
		Limits:   corev1.ResourceList{corev1.ResourceMemory: qty(t, "8Gi")},
		Requests: corev1.ResourceList{corev1.ResourceMemory: qty(t, "6Gi")},
	}
	b, sc := resizeBackend(t, "erin", start)

	// Shrink the limit below the preserved request.
	if err := b.Resize(context.Background(), box.BoxRef{Tenant: "erin"},
		box.ResourceLimits{Memory: "2Gi"}); err != nil {
		t.Fatalf("Resize: %v", err)
	}

	got := resizedResources(t, sc, "erin")
	if m := got.Limits[corev1.ResourceMemory]; m.String() != "2Gi" {
		t.Errorf("memory limit = %q, want 2Gi", m.String())
	}
	if r := got.Requests[corev1.ResourceMemory]; r.String() != "2Gi" {
		t.Errorf("memory request = %q, want 2Gi (clamped to the new limit)", r.String())
	}
}

// A box that carried no request at all gets request == limit, matching what
// create would have produced for it.
func TestResizeDefaultsMissingRequestToLimit(t *testing.T) {
	start := corev1.ResourceRequirements{
		Limits: corev1.ResourceList{corev1.ResourceCPU: qty(t, "1")},
	}
	b, sc := resizeBackend(t, "frank", start)

	if err := b.Resize(context.Background(), box.BoxRef{Tenant: "frank"},
		box.ResourceLimits{CPU: "3"}); err != nil {
		t.Fatalf("Resize: %v", err)
	}

	got := resizedResources(t, sc, "frank")
	if r := got.Requests[corev1.ResourceCPU]; r.String() != "3" {
		t.Errorf("cpu request = %q, want 3", r.String())
	}
}

// An incus-native quantity reaching the K8s path is skipped rather than
// written, so a bad string cannot fail pod admission — and, with the merge
// semantics, must not damage the existing value either.
func TestResizeSkipsUnparseableQuantity(t *testing.T) {
	start := corev1.ResourceRequirements{
		Limits:   corev1.ResourceList{corev1.ResourceMemory: qty(t, "4Gi")},
		Requests: corev1.ResourceList{corev1.ResourceMemory: qty(t, "4Gi")},
	}
	b, sc := resizeBackend(t, "grace", start)

	if err := b.Resize(context.Background(), box.BoxRef{Tenant: "grace"},
		box.ResourceLimits{Memory: "8GB"}); err != nil { // incus-native, not a K8s quantity
		t.Fatalf("Resize: %v", err)
	}

	got := resizedResources(t, sc, "grace")
	if m := got.Limits[corev1.ResourceMemory]; m.String() != "4Gi" {
		t.Errorf("memory limit = %q, want the original 4Gi to survive an unparseable input", m.String())
	}
}

// A resize naming nothing changes nothing.
func TestResizeNoOpLeavesResourcesUntouched(t *testing.T) {
	start := corev1.ResourceRequirements{
		Limits:   corev1.ResourceList{corev1.ResourceCPU: qty(t, "2"), corev1.ResourceMemory: qty(t, "4Gi")},
		Requests: corev1.ResourceList{corev1.ResourceCPU: qty(t, "1"), corev1.ResourceMemory: qty(t, "2Gi")},
	}
	b, sc := resizeBackend(t, "heidi", start)

	if err := b.Resize(context.Background(), box.BoxRef{Tenant: "heidi"}, box.ResourceLimits{}); err != nil {
		t.Fatalf("Resize: %v", err)
	}

	got := resizedResources(t, sc, "heidi")
	for name, want := range map[corev1.ResourceName]string{corev1.ResourceCPU: "2", corev1.ResourceMemory: "4Gi"} {
		if q := got.Limits[name]; q.String() != want {
			t.Errorf("%s limit = %q, want %q", name, q.String(), want)
		}
	}
	for name, want := range map[corev1.ResourceName]string{corev1.ResourceCPU: "1", corev1.ResourceMemory: "2Gi"} {
		if q := got.Requests[name]; q.String() != want {
			t.Errorf("%s request = %q, want %q", name, q.String(), want)
		}
	}
}
