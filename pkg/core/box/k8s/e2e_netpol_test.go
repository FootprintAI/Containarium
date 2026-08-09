//go:build k8s

package k8s

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/footprintai/containarium/pkg/core/box"
)

// TestE2E_NetworkPolicyIsolation proves the per-tenant default-deny
// NetworkPolicy is actually ENFORCED, not merely created.
//
// Why this file exists (#1234): kind's default CNI (kindnet) does not enforce
// NetworkPolicy. #1195 tightened the policy — ingress restricted to the
// sshpiper pod, egress to cluster DNS — and merged on a green `kind e2e` that
// could not have failed, because nothing in the cluster was enforcing the
// object under test. A test that cannot fail is worse than no test: it reports
// confidence it hasn't earned.
//
// scripts/k8s-e2e.sh now installs Calico by default. When it doesn't
// (E2E_CNI=kindnet), this test SKIPS rather than passing — a vacuous pass is
// exactly the failure mode being fixed.
func TestE2E_NetworkPolicyIsolation(t *testing.T) {
	if os.Getenv("CONTAINARIUM_K8S_E2E") == "" {
		t.Skip("set CONTAINARIUM_K8S_E2E=1 (and KUBECONFIG) to run the kind e2e")
	}
	if cni := os.Getenv("E2E_CNI"); cni == "kindnet" {
		t.Skip("E2E_CNI=kindnet does not enforce NetworkPolicy; skipping rather than passing vacuously (#1234)")
	}

	b, err := New(Config{
		Kubeconfig:       os.Getenv("KUBECONFIG"),
		BoxImage:         "registry.k8s.io/pause:3.9",
		GatewayHost:      "gateway.example.com",
		GatewayNamespace: "agent-gateway",
	})
	if err != nil {
		t.Fatalf("New (is the cluster reachable?): %v", err)
	}

	ctx := context.Background()
	ref := box.BoxRef{Tenant: "netpol"}
	t.Cleanup(func() { _ = b.Delete(context.Background(), ref, true) })

	if _, err := b.Create(ctx, box.BoxSpec{Ref: ref}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	boxNS := b.cfg.TenantNamespacePrefix + ref.Tenant

	// Confirm the policy object carries real peer selectors. If a future change
	// regresses to port-only rules, the connectivity assertion below would still
	// "pass" on a permissive CNI — so check the object too.
	np, err := b.clientset.NetworkingV1().NetworkPolicies(boxNS).Get(ctx, "default-deny", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get NetworkPolicy: %v", err)
	}
	if len(np.Spec.Ingress) == 0 || len(np.Spec.Ingress[0].From) == 0 {
		t.Fatal("ingress rule has no From peers — port-only rules match ALL sources (#1193)")
	}
	if len(np.Spec.Egress) == 0 || len(np.Spec.Egress[0].To) == 0 {
		t.Fatal("egress rule has no To peers — port-53 to any destination is an exfil channel (#1193)")
	}

	// The real assertion: a pod in a DIFFERENT namespace must not reach the
	// box's SSH port. Against the pre-#1195 port-only rule this connects and
	// the test fails — which is the point.
	probeNS := "netpol-probe"
	if _, err := b.clientset.CoreV1().Namespaces().Create(ctx,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: probeNS}}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create probe namespace: %v", err)
	}
	t.Cleanup(func() {
		_ = b.clientset.CoreV1().Namespaces().Delete(context.Background(), probeNS, metav1.DeleteOptions{})
	})

	target := fmt.Sprintf("box.%s.svc.cluster.local", boxNS)
	phase := runProbe(ctx, t, b, probeNS, "deny-probe",
		// Exit 0 only if the connection SUCCEEDS, so a blocked connection is a
		// pod failure. -w bounds the wait so a silently-dropped SYN doesn't hang
		// until the poll timeout and get misread as "still starting".
		fmt.Sprintf("nc -z -w 5 %s %d", target, sshPort))

	if phase == corev1.PodSucceeded {
		t.Errorf("a pod in namespace %q reached %s:%d — cross-namespace ingress is NOT blocked (#1193)", probeNS, target, sshPort)
	}
	if phase != corev1.PodFailed {
		t.Logf("probe ended in phase %v (wanted Failed = connection refused/blocked)", phase)
	}
}

// runProbe runs a one-shot pod and returns its terminal phase. A Succeeded
// phase means the command exited 0.
func runProbe(ctx context.Context, t *testing.T, b *Backend, ns, name, script string) corev1.PodPhase {
	t.Helper()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			Containers: []corev1.Container{{
				Name:    "probe",
				Image:   "busybox:1.36",
				Command: []string{"sh", "-c", script},
			}},
		},
	}
	if _, err := b.clientset.CoreV1().Pods(ns).Create(ctx, pod, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create probe pod: %v", err)
	}

	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		got, err := b.clientset.CoreV1().Pods(ns).Get(ctx, name, metav1.GetOptions{})
		if err == nil {
			switch got.Status.Phase {
			case corev1.PodSucceeded, corev1.PodFailed:
				return got.Status.Phase
			}
		}
		time.Sleep(3 * time.Second)
	}
	t.Fatalf("probe pod %s/%s did not terminate within the deadline", ns, name)
	return corev1.PodUnknown
}
