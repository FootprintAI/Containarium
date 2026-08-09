//go:build k8s

package k8s

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/clientcmd"

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
//
// The same trap has a second mouth, and avoiding it is most of this test:
// the real box pod runs registry.k8s.io/pause, which listens on NOTHING, so
// probing it would fail identically whether or not the policy blocks the
// connection. So the test stands up its own listener carrying the box labels
// the policy selects on, and runs a POSITIVE CONTROL from the gateway
// namespace first. If the allowed connection doesn't succeed, the denied one
// proves nothing and the test says so instead of reporting a pass.
func TestE2E_NetworkPolicyIsolation(t *testing.T) {
	if os.Getenv("CONTAINARIUM_K8S_E2E") == "" {
		t.Skip("set CONTAINARIUM_K8S_E2E=1 (and KUBECONFIG) to run the kind e2e")
	}
	if cni := os.Getenv("E2E_CNI"); cni == "kindnet" {
		t.Skip("E2E_CNI=kindnet does not enforce NetworkPolicy; skipping rather than passing vacuously (#1234)")
	}

	const gatewayNS = "agent-gateway"
	kubeconfig := os.Getenv("KUBECONFIG")

	restCfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		t.Fatalf("rest config: %v", err)
	}
	dyn, err := dynamic.NewForConfig(restCfg)
	if err != nil {
		t.Fatalf("dynamic client: %v", err)
	}
	// Create() programs an sshpiper Pipe when a gateway namespace is set, and
	// a gateway namespace is exactly what gives the policy its peer selectors
	// — so the CRD has to be here for this test to exercise the real path.
	installPipeCRD(t, dyn)

	b, err := New(Config{
		Kubeconfig:       kubeconfig,
		BoxImage:         "registry.k8s.io/pause:3.9",
		GatewayHost:      "gateway.example.com",
		GatewayNamespace: gatewayNS,
	})
	if err != nil {
		t.Fatalf("New (is the cluster reachable?): %v", err)
	}

	ctx := context.Background()
	ensureNamespace(ctx, t, b, gatewayNS)

	ref := box.BoxRef{Tenant: "netpol"}
	t.Cleanup(func() { _ = b.Delete(context.Background(), ref, true) })

	if _, err := b.Create(ctx, box.BoxSpec{Ref: ref}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	boxNS := b.cfg.TenantNamespacePrefix + ref.Tenant

	// Confirm the policy object carries real peer selectors. If a future change
	// regresses to port-only rules, the connectivity assertions below would
	// still behave correctly — but checking the object names the regression
	// precisely instead of leaving a bare connectivity failure to diagnose.
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

	// A listener the policy actually selects. httpd rather than `nc -l` because
	// it serves connections continuously: a one-shot listener would race the
	// second probe and fail for a reason unrelated to policy.
	targetIP := startPolicySelectedListener(ctx, t, b, boxNS, ref.Tenant)

	// POSITIVE CONTROL, and it runs first on purpose. It proves the listener is
	// up, the port is right, and the CNI is not simply dropping everything —
	// all the ways the denial assertion below could pass for a wrong reason.
	allowed := runProbe(ctx, t, b, probeSpec{
		ns:     gatewayNS,
		name:   "allow-probe",
		labels: map[string]string{sshpiperNameLabel: "sshpiper"},
		script: fmt.Sprintf("nc -z -w 5 %s %d", targetIP, sshPort),
	})
	if allowed != corev1.PodSucceeded {
		t.Fatalf("positive control FAILED: a pod in %q with the sshpiper label could not reach %s:%d "+
			"(phase %v). The policy is supposed to ALLOW this, so the denial check below would prove "+
			"nothing — failing loudly instead of reporting a pass.", gatewayNS, targetIP, sshPort, allowed)
	}

	// The actual isolation claim: same port, same listener, different namespace.
	// Against the pre-#1195 port-only rule this connection SUCCEEDS and the
	// test fails — which is the property the old e2e lacked entirely.
	const probeNS = "netpol-probe"
	ensureNamespace(ctx, t, b, probeNS)
	denied := runProbe(ctx, t, b, probeSpec{
		ns:   probeNS,
		name: "deny-probe",
		// Exit 0 only if the connection SUCCEEDS, so a blocked connection is a
		// pod failure. -w bounds the wait so a silently-dropped SYN doesn't hang
		// until the poll timeout and get misread as "still starting".
		script: fmt.Sprintf("nc -z -w 5 %s %d", targetIP, sshPort),
	})
	if denied == corev1.PodSucceeded {
		t.Errorf("a pod in namespace %q reached %s:%d — cross-namespace ingress is NOT blocked (#1193). "+
			"The positive control passed, so this is a policy failure, not a broken probe.",
			probeNS, targetIP, sshPort)
	}
}

// ensureNamespace makes a namespace exist and usable, and removes it again
// only if this call is what created it.
//
// Both halves matter once more than one test wants the same namespace, which
// is now the case for agent-gateway:
//
//   - Namespace deletion is ASYNCHRONOUS. A namespace left Terminating by an
//     earlier test's cleanup still exists, so a plain Create returns
//     AlreadyExists and the caller proceeds — then every write into it fails
//     with "unable to create new content in namespace X because it is being
//     terminated". So wait the termination out rather than racing it.
//   - Deleting a namespace this call did NOT create takes it away from
//     whoever did, which is how the race got started.
func ensureNamespace(ctx context.Context, t *testing.T, b *Backend, name string) {
	t.Helper()

	namespaces := b.clientset.CoreV1().Namespaces()
	deadline := time.Now().Add(2 * time.Minute)

	for {
		_, err := namespaces.Create(ctx,
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}, metav1.CreateOptions{})
		if err == nil {
			// We created it, so we own its removal.
			t.Cleanup(func() {
				_ = namespaces.Delete(context.Background(), name, metav1.DeleteOptions{})
			})
			return
		}
		if !apierrors.IsAlreadyExists(err) {
			t.Fatalf("create namespace %s: %v", name, err)
		}

		// It exists. Usable only if it is not on its way out.
		existing, getErr := namespaces.Get(ctx, name, metav1.GetOptions{})
		if getErr == nil && existing.Status.Phase != corev1.NamespaceTerminating {
			// Someone else created it; leave the removal to them.
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("namespace %s is still terminating after 2m; a previous test's cleanup has not "+
				"finished and every write into it would fail", name)
		}
		time.Sleep(2 * time.Second)
	}
}

// startPolicySelectedListener runs a pod in the tenant namespace carrying the
// labels the default-deny policy selects on, listening on sshPort, and returns
// its pod IP.
//
// It deliberately does NOT use the box pod: that runs pause, which listens on
// nothing, so every probe against it would fail for a reason that has nothing
// to do with NetworkPolicy.
func startPolicySelectedListener(ctx context.Context, t *testing.T, b *Backend, ns, tenant string) string {
	t.Helper()
	const name = "netpol-listener"
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: boxLabels(tenant)},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:    "listener",
				Image:   "busybox:1.36",
				Command: []string{"sh", "-c", fmt.Sprintf("httpd -f -p %d -h /tmp", sshPort)},
			}},
		},
	}
	if _, err := b.clientset.CoreV1().Pods(ns).Create(ctx, pod, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create listener pod: %v", err)
	}
	t.Cleanup(func() {
		_ = b.clientset.CoreV1().Pods(ns).Delete(context.Background(), name, metav1.DeleteOptions{})
	})

	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		got, err := b.clientset.CoreV1().Pods(ns).Get(ctx, name, metav1.GetOptions{})
		if err == nil && got.Status.Phase == corev1.PodRunning && got.Status.PodIP != "" {
			return got.Status.PodIP
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatal("listener pod never reached Running with an IP")
	return ""
}

type probeSpec struct {
	ns     string
	name   string
	labels map[string]string
	script string
}

// runProbe runs a one-shot pod and returns its terminal phase. A Succeeded
// phase means the command exited 0.
func runProbe(ctx context.Context, t *testing.T, b *Backend, p probeSpec) corev1.PodPhase {
	t.Helper()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: p.name, Namespace: p.ns, Labels: p.labels},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			Containers: []corev1.Container{{
				Name:    "probe",
				Image:   "busybox:1.36",
				Command: []string{"sh", "-c", p.script},
			}},
		},
	}
	if _, err := b.clientset.CoreV1().Pods(p.ns).Create(ctx, pod, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create probe pod: %v", err)
	}

	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		got, err := b.clientset.CoreV1().Pods(p.ns).Get(ctx, p.name, metav1.GetOptions{})
		if err == nil {
			switch got.Status.Phase {
			case corev1.PodSucceeded, corev1.PodFailed:
				return got.Status.Phase
			}
		}
		time.Sleep(3 * time.Second)
	}
	t.Fatalf("probe pod %s/%s did not terminate within the deadline", p.ns, p.name)
	return corev1.PodUnknown
}
