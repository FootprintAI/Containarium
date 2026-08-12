//go:build k8s

package k8s

import (
	"context"
	"os"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/footprintai/containarium/pkg/core/box"
)

// TestE2E_BoxEgressPosture observes what a box can actually reach outbound.
//
// This closes the last open acceptance criterion on #1234: "document the
// current no-outbound-egress posture once observed, or fix it under #1188 if
// it turns out to be unintended." Until Calico landed, nobody had observed it
// — the policy was created and ignored, so the posture was inferred from
// reading the object rather than from behavior.
//
// What the object says: exactly ONE egress rule, DNS (UDP/TCP 53) to the
// kube-system namespace. Everything else denied. If that is what the cluster
// actually enforces, a K8s box can resolve names and connect to nothing —
// no package installs, no outbound HTTP, no control-plane API. That is a
// significant property for an agent runtime whose pitch is shell_exec, and
// it should be a measured fact rather than an assumption.
//
// Structure follows the lesson from #1235: the DENIAL assertion is worthless
// without a POSITIVE CONTROL, because a pod with no network at all would fail
// both. DNS is the control — the one thing the policy is supposed to allow.
func TestE2E_BoxEgressPosture(t *testing.T) {
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

	ref := box.BoxRef{Tenant: "egress"}
	t.Cleanup(func() { _ = b.Delete(context.Background(), ref, true) })
	if _, err := b.Create(ctx, box.BoxSpec{Ref: ref}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	boxNS := b.cfg.TenantNamespacePrefix + ref.Tenant

	// Probes run in the tenant namespace carrying the box labels, so the
	// per-tenant egress policy selects them exactly as it selects a real box.
	// (The real box pod runs pause and cannot run a probe — the #1235 trap.)
	labels := boxLabels(ref.Tenant)

	// POSITIVE CONTROL, first: DNS is the one egress the policy allows. If this
	// fails, the pod has no working network at all and every denial below would
	// pass for the wrong reason.
	dns := runProbe(ctx, t, b, probeSpec{
		ns:     boxNS,
		name:   "egress-dns-probe",
		labels: labels,
		script: "nslookup kubernetes.default.svc.cluster.local",
	})
	if dns != corev1.PodSucceeded {
		t.Fatalf("positive control FAILED: a box-labelled pod could not resolve DNS (phase %v). "+
			"The policy is supposed to ALLOW cluster DNS, so the denial checks below would prove "+
			"nothing — failing loudly instead of reporting a pass.", dns)
	}

	// The observation. The design note used to claim the egress allowlist
	// included "the control-plane API endpoint"; no such rule exists in the
	// object (corrected in #1194). This measures whether that matches reality.
	api := runProbe(ctx, t, b, probeSpec{
		ns:     boxNS,
		name:   "egress-api-probe",
		labels: labels,
		script: "nc -z -w 5 kubernetes.default.svc.cluster.local 443",
	})
	switch api {
	case corev1.PodSucceeded:
		// Not a failure of the policy as written — but it contradicts the
		// object, which means something else is granting egress. Worth
		// failing on, because the isolation story depends on knowing which.
		t.Errorf("a box-labelled pod reached the control-plane API on :443, but the NetworkPolicy " +
			"has no egress rule permitting it. Something outside the policy is granting egress — " +
			"investigate before trusting the deny-by-default posture (#1188).")
	default:
		t.Logf("OBSERVED: box egress to the control-plane API is blocked (phase %v). "+
			"Combined with the DNS control passing, the deny-by-default posture is real: "+
			"a K8s box can resolve names and reach nothing else. See #1188 for making the "+
			"egress allowlist policy-driven.", api)
	}
}
