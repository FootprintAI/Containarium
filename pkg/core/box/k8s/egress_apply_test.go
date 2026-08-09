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

// #1188 ACs 2-4, at the object level: a tenant egress allowlist appears
// alongside the DNS allowance; removal reverts to the default-deny floor and
// never to allow-all; a box with no policy is unchanged.

func egressTestBackend() *Backend {
	return NewWithClientset(fake.NewSimpleClientset(), sandboxfake.NewSimpleClientset(),
		Config{TenantNamespacePrefix: "tenant-", GatewayNamespace: "agent-gateway"})
}

func TestApplyTenantEgress_AddsRulesAlongsideDNS(t *testing.T) {
	b := egressTestBackend()
	ctx := context.Background()

	err := b.ApplyTenantEgress(ctx, "alice", []*pb.ACLRule{
		allowRule("203.0.113.0/24", "443", "tcp"),
	})
	if err != nil {
		t.Fatalf("ApplyTenantEgress: %v", err)
	}

	ns := "tenant-alice"
	np, err := b.clientset.NetworkingV1().NetworkPolicies(ns).Get(ctx, "default-deny", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get networkpolicy: %v", err)
	}

	if len(np.Spec.Egress) != 2 {
		t.Fatalf("egress has %d rules, want the DNS floor plus the tenant rule", len(np.Spec.Egress))
	}
	// DNS stays first and intact — a box that cannot resolve names looks like
	// a policy bug and is not one.
	if len(np.Spec.Egress[0].Ports) != 2 {
		t.Errorf("the DNS allowance was disturbed: %+v", np.Spec.Egress[0])
	}
	if np.Spec.Egress[1].To[0].IPBlock == nil || np.Spec.Egress[1].To[0].IPBlock.CIDR != "203.0.113.0/24" {
		t.Errorf("tenant rule = %+v, want an IPBlock for 203.0.113.0/24", np.Spec.Egress[1])
	}
}

// THE property that matters more than the feature: removing a policy must
// revert to the floor, never widen. A removal that opened access would be a
// silent privilege escalation triggered by a delete.
func TestApplyTenantEgress_RemovalRevertsToTheFloorNotAllowAll(t *testing.T) {
	b := egressTestBackend()
	ctx := context.Background()

	if err := b.ApplyTenantEgress(ctx, "alice", []*pb.ACLRule{
		allowRule("203.0.113.0/24", "443", "tcp"),
	}); err != nil {
		t.Fatalf("apply: %v", err)
	}

	// Policy removed.
	if err := b.ApplyTenantEgress(ctx, "alice", nil); err != nil {
		t.Fatalf("apply(empty): %v", err)
	}

	np, err := b.clientset.NetworkingV1().NetworkPolicies("tenant-alice").Get(ctx, "default-deny", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(np.Spec.Egress) != 1 {
		t.Fatalf("after removal egress has %d rules, want only the DNS floor: %+v",
			len(np.Spec.Egress), np.Spec.Egress)
	}
	// An egress rule with no `to` and no `ports` is allow-all. Reverting into
	// that would be the worst possible outcome of a delete.
	only := np.Spec.Egress[0]
	if len(only.To) == 0 && len(only.Ports) == 0 {
		t.Fatal("removal left an unrestricted egress rule — a delete widened access")
	}
	if len(only.Ports) != 2 {
		t.Errorf("the remaining rule is not the DNS floor: %+v", only)
	}
}

// A policy containing a rule that cannot be expressed must not be partially
// applied — the applied part would permit traffic the policy denies while
// reporting success.
func TestApplyTenantEgress_RefusesPartialApplication(t *testing.T) {
	b := egressTestBackend()
	ctx := context.Background()

	err := b.ApplyTenantEgress(ctx, "alice", []*pb.ACLRule{
		allowRule("10.0.0.0/8", "443", "tcp"),
		{Action: pb.ACLAction_ACL_ACTION_DROP, Destination: "10.1.2.0/24", Protocol: "tcp"},
	})
	if err == nil {
		t.Fatal("a policy with an inexpressible deny was applied; the allow would permit " +
			"10.1.2.0/24, which the tenant blocked")
	}
	if !strings.Contains(err.Error(), "10.1.2.0/24") {
		t.Errorf("the error should name the rule it could not carry: %v", err)
	}

	// And nothing was written.
	if _, err := b.clientset.NetworkingV1().NetworkPolicies("tenant-alice").Get(
		ctx, "default-deny", metav1.GetOptions{}); err == nil {
		t.Error("a refused policy still wrote an object")
	}
}

func TestApplyTenantEgress_UpdatesInPlaceOnRepeatedApply(t *testing.T) {
	b := egressTestBackend()
	ctx := context.Background()

	for _, cidr := range []string{"203.0.113.0/24", "198.51.100.0/24"} {
		if err := b.ApplyTenantEgress(ctx, "alice", []*pb.ACLRule{allowRule(cidr, "443", "tcp")}); err != nil {
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
	if got := list.Items[0].Spec.Egress[1].To[0].IPBlock.CIDR; got != "198.51.100.0/24" {
		t.Errorf("policy was not updated: egress targets %q", got)
	}
}

func TestApplyTenantEgress_RequiresTenant(t *testing.T) {
	if err := egressTestBackend().ApplyTenantEgress(context.Background(), "", nil); err == nil {
		t.Error("accepted an empty tenant")
	}
}
