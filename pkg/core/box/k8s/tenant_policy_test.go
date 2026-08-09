package k8s

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	sandboxfake "sigs.k8s.io/agent-sandbox/clients/k8s/clientset/versioned/fake"
)

// #1188: a tenant's egress policy is enforced on LXC and silently ignored on
// K8s, with the same SetNetworkPolicy call succeeding either way.
//
// The compiler's job is to carry what it can and REFUSE what it cannot.
// Every one of the stored model's inexpressible features fails in the SAME
// direction — more permissive than the tenant asked for — so dropping any of
// them quietly is strictly worse than not supporting the backend at all.

func enforcing(p *pb.NetworkPolicy) *pb.NetworkPolicy {
	p.Mode = pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE
	return p
}

func policyBackend() *Backend {
	return NewWithClientset(fake.NewSimpleClientset(), sandboxfake.NewSimpleClientset(),
		Config{TenantNamespacePrefix: "tenant-", GatewayNamespace: "agent-gateway"})
}

// THE most dangerous mis-compilation. LOG_ONLY means "observe denied flows,
// drop nothing" — a dry run. NetworkPolicy has no observe-only mode, so
// applying one ENFORCES it. Compiling a LOG_ONLY policy would start dropping
// a tenant's traffic during what they intended as a trial, and it would be
// discovered as an outage.
func TestCompileTenantPolicy_RefusesLogOnlyMode(t *testing.T) {
	for _, mode := range []pb.NetworkPolicyMode{
		pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY,
		pb.NetworkPolicyMode_NETWORK_POLICY_MODE_UNSPECIFIED, // treated as LOG_ONLY
	} {
		_, unsupported := compileTenantPolicy(&pb.NetworkPolicy{
			Tenant: "alice", Mode: mode, EgressCidrs: []string{"10.0.0.0/8"},
		})
		if len(unsupported) == 0 {
			t.Errorf("mode %v compiled to an enforcing NetworkPolicy — the tenant asked to "+
				"observe, and this would start dropping their traffic", mode)
		}
	}
}

// The metadata carve-out is deny-beats-allow and guards cloud credentials.
// An allowlist entry covering 169.254.169.254 cannot be narrowed by an
// allow-only policy, so it must be refused rather than admitted.
func TestCompileTenantPolicy_RefusesAllowlistCoveringMetadataIP(t *testing.T) {
	_, unsupported := compileTenantPolicy(enforcing(&pb.NetworkPolicy{
		Tenant:      "alice",
		EgressCidrs: []string{"169.254.0.0/16"}, // covers the metadata service
		// AllowMetadata false — the default, and the whole point
	}))
	if len(unsupported) == 0 {
		t.Fatal("an allowlist covering 169.254.169.254 was accepted while allow_metadata is " +
			"false — the tenant would reach the cloud metadata service, and its credentials, " +
			"which the stored policy explicitly withholds")
	}
	if !strings.Contains(unsupported[0].Reason, "metadata") {
		t.Errorf("reason should name the metadata carve-out: %v", unsupported[0])
	}
}

// A tenant who has explicitly opted in is a different matter.
func TestCompileTenantPolicy_AllowsMetadataWhenOptedIn(t *testing.T) {
	compiled, unsupported := compileTenantPolicy(enforcing(&pb.NetworkPolicy{
		Tenant: "alice", EgressCidrs: []string{"169.254.0.0/16"}, AllowMetadata: true,
	}))
	if len(unsupported) != 0 {
		t.Fatalf("opted-in metadata access was refused: %v", unsupported)
	}
	if len(compiled) != 1 {
		t.Errorf("compiled %d rules, want 1", len(compiled))
	}
}

// Domains are resolved on a refresh loop on the eBPF path. NetworkPolicy
// matches IPs, and freezing one moment's answer into a static object would go
// stale silently — the allowlist would drift from the names it was written in.
func TestCompileTenantPolicy_RefusesEgressDomains(t *testing.T) {
	_, unsupported := compileTenantPolicy(enforcing(&pb.NetworkPolicy{
		Tenant: "alice", EgressDomains: []string{"api.github.com"},
	}))
	if len(unsupported) == 0 {
		t.Fatal("egress_domains was accepted; NetworkPolicy cannot match names")
	}
}

// Virtual-patch deny rules are deny-beats-allow, same as the metadata IP.
func TestCompileTenantPolicy_RefusesDenyRules(t *testing.T) {
	_, unsupported := compileTenantPolicy(enforcing(&pb.NetworkPolicy{
		Tenant:      "alice",
		EgressCidrs: []string{"10.0.0.0/8"},
		DenyRules:   []*pb.NetworkPolicyDenyRule{{}},
	}))
	if len(unsupported) == 0 {
		t.Fatal("deny_rules were accepted; an allow-only policy cannot express them")
	}
}

func TestCompileTenantPolicy_CompilesCIDRs(t *testing.T) {
	compiled, unsupported := compileTenantPolicy(enforcing(&pb.NetworkPolicy{
		Tenant: "alice", EgressCidrs: []string{"203.0.113.0/24", "198.51.100.7"},
	}))
	if len(unsupported) != 0 {
		t.Fatalf("unexpected unsupported: %v", unsupported)
	}
	if len(compiled) != 2 {
		t.Fatalf("compiled %d rules, want 2", len(compiled))
	}
	// A bare address becomes a host route rather than being widened.
	var sawHostRoute bool
	for _, r := range compiled {
		if r.To[0].IPBlock.CIDR == "198.51.100.7/32" {
			sawHostRoute = true
		}
	}
	if !sawHostRoute {
		t.Errorf("a bare address did not become a /32: %+v", compiled)
	}
}

// Order must not depend on input order, or every reconcile rewrites the object.
func TestCompileTenantPolicy_DeterministicOrder(t *testing.T) {
	a := enforcing(&pb.NetworkPolicy{Tenant: "x", EgressCidrs: []string{"10.0.0.0/8", "192.168.0.0/16"}})
	b := enforcing(&pb.NetworkPolicy{Tenant: "x", EgressCidrs: []string{"192.168.0.0/16", "10.0.0.0/8"}})
	first, _ := compileTenantPolicy(a)
	second, _ := compileTenantPolicy(b)
	if peerCIDR(first[0]) != peerCIDR(second[0]) {
		t.Errorf("order depends on input: %q vs %q", peerCIDR(first[0]), peerCIDR(second[0]))
	}
}

func TestApplyTenantPolicy_AddsRulesAlongsideDNS(t *testing.T) {
	b := policyBackend()
	ctx := context.Background()

	if err := b.ApplyTenantPolicy(ctx, "alice", enforcing(&pb.NetworkPolicy{
		Tenant: "alice", EgressCidrs: []string{"203.0.113.0/24"},
	})); err != nil {
		t.Fatalf("ApplyTenantPolicy: %v", err)
	}

	np, err := b.clientset.NetworkingV1().NetworkPolicies("tenant-alice").Get(ctx, "default-deny", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(np.Spec.Egress) != 2 {
		t.Fatalf("egress has %d rules, want the DNS floor plus the tenant rule", len(np.Spec.Egress))
	}
	if len(np.Spec.Egress[0].Ports) != 2 {
		t.Errorf("the DNS allowance was disturbed: %+v", np.Spec.Egress[0])
	}
}

// Removal must revert to the FLOOR, never allow-all. A delete that widened
// access would be a silent privilege escalation.
func TestApplyTenantPolicy_RemovalRevertsToTheFloor(t *testing.T) {
	b := policyBackend()
	ctx := context.Background()

	if err := b.ApplyTenantPolicy(ctx, "alice", enforcing(&pb.NetworkPolicy{
		Tenant: "alice", EgressCidrs: []string{"203.0.113.0/24"},
	})); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := b.ApplyTenantPolicy(ctx, "alice", nil); err != nil {
		t.Fatalf("apply(nil): %v", err)
	}

	np, err := b.clientset.NetworkingV1().NetworkPolicies("tenant-alice").Get(ctx, "default-deny", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(np.Spec.Egress) != 1 {
		t.Fatalf("after removal egress has %d rules, want only the DNS floor: %+v",
			len(np.Spec.Egress), np.Spec.Egress)
	}
	only := np.Spec.Egress[0]
	if len(only.To) == 0 && len(only.Ports) == 0 {
		t.Fatal("removal left an unrestricted egress rule — a delete widened access")
	}
}

func TestApplyTenantPolicy_RefusesPartialApplication(t *testing.T) {
	b := policyBackend()
	ctx := context.Background()

	err := b.ApplyTenantPolicy(ctx, "alice", enforcing(&pb.NetworkPolicy{
		Tenant:        "alice",
		EgressCidrs:   []string{"203.0.113.0/24"},
		EgressDomains: []string{"api.github.com"}, // cannot be expressed
	}))
	if err == nil {
		t.Fatal("a policy with an inexpressible feature was applied; the tenant would get a " +
			"narrower allowlist than they configured, silently")
	}
	if _, err := b.clientset.NetworkingV1().NetworkPolicies("tenant-alice").Get(
		ctx, "default-deny", metav1.GetOptions{}); err == nil {
		t.Error("a refused policy still wrote an object")
	}
}

func TestApplyTenantPolicy_UpdatesInPlace(t *testing.T) {
	b := policyBackend()
	ctx := context.Background()
	for _, cidr := range []string{"203.0.113.0/24", "198.51.100.0/24"} {
		if err := b.ApplyTenantPolicy(ctx, "alice", enforcing(&pb.NetworkPolicy{
			Tenant: "alice", EgressCidrs: []string{cidr},
		})); err != nil {
			t.Fatalf("apply %s: %v", cidr, err)
		}
	}
	list, err := b.clientset.NetworkingV1().NetworkPolicies("tenant-alice").List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("repeated apply created %d policies, want 1 updated in place", len(list.Items))
	}
}
