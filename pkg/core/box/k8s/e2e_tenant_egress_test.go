//go:build k8s

package k8s

import (
	"context"
	"fmt"
	"os"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/footprintai/containarium/pkg/core/box"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #1188 AC5: a tenant egress allowlist is ENFORCED on the K8s backend — a
// destination outside it is genuinely unreachable, not merely absent from a
// YAML object.
//
// This is the assertion the whole issue turns on. A tenant who sets an egress
// allowlist gets it enforced on LXC and, until now, silently ignored here.
// Checking that the NetworkPolicy object has the right shape would not
// distinguish "enforced" from "written and ignored" — which is exactly how
// #1195 shipped unvalidated and became #1234.
//
// The test therefore asserts both directions, and the ALLOWED probe runs
// first. Without it, "the denied destination was unreachable" is equally
// consistent with the CNI dropping everything, the listener never starting,
// or the wrong port — and the test would pass while proving nothing.
func TestE2E_TenantEgressAllowlistIsEnforced(t *testing.T) {
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
	// Create() programs an sshpiper Pipe when a gateway namespace is set.
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

	ref := box.BoxRef{Tenant: "egresspol"}
	t.Cleanup(func() { _ = b.Delete(context.Background(), ref, true) })
	if _, err := b.Create(ctx, box.BoxSpec{Ref: ref}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	boxNS := b.cfg.TenantNamespacePrefix + ref.Tenant

	// Two identical listeners in a neutral namespace. The only thing that
	// will differ between them is whether the tenant's allowlist names them.
	const targetNS = "egress-targets"
	ensureNamespace(ctx, t, b, targetNS)
	allowedIP := startTargetListener(ctx, t, b, targetNS, "allowed-target")
	deniedIP := startTargetListener(ctx, t, b, targetNS, "denied-target")

	// The tenant's policy permits exactly one of them.
	policy := &pb.NetworkPolicy{
		Tenant:      ref.Tenant,
		Mode:        pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE,
		EgressCidrs: []string{allowedIP + "/32"},
	}
	if err := b.ApplyTenantPolicy(ctx, ref.Tenant, policy); err != nil {
		t.Fatalf("ApplyTenantPolicy: %v", err)
	}

	// POSITIVE CONTROL, first. It proves the listeners are up, the port is
	// right, and the CNI is not simply dropping everything — every way the
	// denial assertion below could pass for a wrong reason.
	allowed := runProbe(ctx, t, b, probeSpec{
		ns:     boxNS,
		name:   "egress-allowed-probe",
		labels: boxLabels(ref.Tenant), // selected by the tenant's policy
		script: fmt.Sprintf("nc -z -w 5 %s %d", allowedIP, targetPort),
	})
	if allowed != corev1.PodSucceeded {
		t.Fatalf("positive control FAILED: the tenant could not reach %s:%d, which its own "+
			"allowlist permits (phase %v). The denial check below would prove nothing, so this "+
			"fails loudly instead of reporting a pass.", allowedIP, targetPort, allowed)
	}

	// THE assertion: same port, same image, same namespace — the only
	// difference is that this destination is outside the allowlist.
	denied := runProbe(ctx, t, b, probeSpec{
		ns:     boxNS,
		name:   "egress-denied-probe",
		labels: boxLabels(ref.Tenant),
		script: fmt.Sprintf("nc -z -w 5 %s %d", deniedIP, targetPort),
	})
	if denied == corev1.PodSucceeded {
		t.Errorf("the tenant reached %s:%d, which is OUTSIDE its egress allowlist — the policy is "+
			"not enforced on this backend (#1188). The positive control passed, so this is a "+
			"policy failure, not a broken probe.", deniedIP, targetPort)
	}
}

// targetPort is the port the egress targets listen on.
const targetPort = 8080

// startTargetListener runs a pod that accepts TCP connections and returns its
// pod IP. httpd rather than `nc -l` because it serves continuously — a
// one-shot listener would race the second probe and fail for a reason
// unrelated to policy.
func startTargetListener(ctx context.Context, t *testing.T, b *Backend, ns, name string) string {
	t.Helper()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:    "listener",
				Image:   "busybox:1.36",
				Command: []string{"sh", "-c", fmt.Sprintf("httpd -f -p %d -h /tmp", targetPort)},
			}},
		},
	}
	if _, err := b.clientset.CoreV1().Pods(ns).Create(ctx, pod, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create target %s: %v", name, err)
	}
	t.Cleanup(func() {
		_ = b.clientset.CoreV1().Pods(ns).Delete(context.Background(), name, metav1.DeleteOptions{})
	})

	return waitForPodIP(ctx, t, b, ns, name)
}
