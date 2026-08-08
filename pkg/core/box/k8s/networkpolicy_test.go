package k8s

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

// The gap these tests close (#1193): the shipped NetworkPolicy carried rules
// with `ports` and no `from`/`to`. Per the NetworkPolicy spec that matches
// every source and destination, so tenant boxes were reachable on :22 from any
// pod in the cluster while the design note said the opposite. Nothing asserted
// the object's shape, so code and doc drifted silently.
//
// The load-bearing assertion in each test below is that the peer list is
// NON-EMPTY. A port-only rule must fail these.

func TestNetworkPolicyIngressRestrictedToGateway(t *testing.T) {
	np := networkPolicyObject("tenant-a", "alice", "agent-gateway")

	if len(np.Spec.Ingress) != 1 {
		t.Fatalf("want exactly 1 ingress rule, got %d", len(np.Spec.Ingress))
	}
	rule := np.Spec.Ingress[0]

	if len(rule.From) == 0 {
		t.Fatal("ingress rule has no From peers: a port-only rule matches ALL sources, " +
			"leaving :22 open cluster-wide (#1193)")
	}
	if len(rule.From) != 1 {
		t.Fatalf("want a single From peer (AND semantics); got %d peers, which is OR "+
			"and would admit any pod in the gateway ns OR any sshpiper-labelled pod anywhere",
			len(rule.From))
	}

	peer := rule.From[0]
	if peer.NamespaceSelector == nil {
		t.Error("From peer has no NamespaceSelector; sshpiper-labelled pods in any namespace would be admitted")
	} else if got := peer.NamespaceSelector.MatchLabels[nsNameLabel]; got != "agent-gateway" {
		t.Errorf("NamespaceSelector %s = %q, want %q", nsNameLabel, got, "agent-gateway")
	}
	if peer.PodSelector == nil {
		t.Error("From peer has no PodSelector; every pod in the gateway namespace would be admitted")
	} else if got := peer.PodSelector.MatchLabels[sshpiperNameLabel]; got != "sshpiper" {
		t.Errorf("PodSelector %s = %q, want %q", sshpiperNameLabel, got, "sshpiper")
	}

	// The port must still be SSH — narrowing the source must not widen the port.
	if len(rule.Ports) != 1 {
		t.Fatalf("want 1 ingress port, got %d", len(rule.Ports))
	}
	if got := rule.Ports[0].Port.IntValue(); got != sshPort {
		t.Errorf("ingress port = %d, want %d", got, sshPort)
	}
	if rule.Ports[0].Protocol == nil || *rule.Ports[0].Protocol != corev1.ProtocolTCP {
		t.Errorf("ingress protocol = %v, want TCP", rule.Ports[0].Protocol)
	}
}

func TestNetworkPolicyEgressDNSRestrictedToClusterDNS(t *testing.T) {
	np := networkPolicyObject("tenant-a", "alice", "agent-gateway")

	if len(np.Spec.Egress) != 1 {
		t.Fatalf("want exactly 1 egress rule, got %d", len(np.Spec.Egress))
	}
	rule := np.Spec.Egress[0]

	if len(rule.To) == 0 {
		t.Fatal("egress rule has no To peers: port-53 to any destination is a DNS-exfiltration " +
			"channel out of a sandbox running untrusted code (#1193)")
	}
	if rule.To[0].NamespaceSelector == nil {
		t.Fatal("egress To peer has no NamespaceSelector")
	}
	if got := rule.To[0].NamespaceSelector.MatchLabels[nsNameLabel]; got != dnsNamespace {
		t.Errorf("egress NamespaceSelector %s = %q, want %q", nsNameLabel, got, dnsNamespace)
	}

	// Both UDP and TCP DNS must survive — TCP/53 carries large responses.
	var sawUDP, sawTCP bool
	for _, p := range rule.Ports {
		if p.Protocol == nil || p.Port.IntValue() != 53 {
			continue
		}
		switch *p.Protocol {
		case corev1.ProtocolUDP:
			sawUDP = true
		case corev1.ProtocolTCP:
			sawTCP = true
		}
	}
	if !sawUDP || !sawTCP {
		t.Errorf("want DNS on both UDP/53 and TCP/53; udp=%v tcp=%v", sawUDP, sawTCP)
	}
}

// An empty GatewayNamespace means routing is disabled (gateway_sshpiper.go).
// Emitting a selector that matches nothing would make the box unreachable
// rather than merely unrouted, so the ingress rule falls back to port-only.
func TestNetworkPolicyIngressFallsBackWhenGatewayNamespaceUnset(t *testing.T) {
	np := networkPolicyObject("tenant-a", "alice", "")

	if len(np.Spec.Ingress) != 1 {
		t.Fatalf("want exactly 1 ingress rule, got %d", len(np.Spec.Ingress))
	}
	if got := len(np.Spec.Ingress[0].From); got != 0 {
		t.Errorf("want port-only ingress when gatewayNS is empty, got %d From peers", got)
	}

	// Egress is not gateway-dependent, so it must still be restricted.
	if len(np.Spec.Egress[0].To) == 0 {
		t.Error("egress must stay restricted to cluster DNS regardless of gateway config")
	}
}

// The policy must still select the tenant's box pods and cover both directions
// — narrowing the rules must not change what the policy applies to.
func TestNetworkPolicySelectorAndPolicyTypesUnchanged(t *testing.T) {
	np := networkPolicyObject("tenant-a", "alice", "agent-gateway")

	if got := np.Spec.PodSelector.MatchLabels[tenantLabel]; got != "alice" {
		t.Errorf("PodSelector %s = %q, want %q", tenantLabel, got, "alice")
	}
	if len(np.Spec.PolicyTypes) != 2 {
		t.Fatalf("want both Ingress and Egress policy types, got %v", np.Spec.PolicyTypes)
	}
	if np.Name != "default-deny" {
		t.Errorf("policy name = %q, want %q", np.Name, "default-deny")
	}
	if np.Namespace != "tenant-a" {
		t.Errorf("policy namespace = %q, want %q", np.Namespace, "tenant-a")
	}
}
