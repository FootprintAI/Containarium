package k8s

import (
	"testing"

	corev1 "k8s.io/api/core/v1"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// #1188: a tenant's egress ACL is enforced on LXC and was silently ignored on
// K8s, with the same SetNetworkPolicy call succeeding either way.
//
// The compiler's job is to carry what it can and REFUSE what it cannot,
// because quietly dropping a rule is the bug being fixed, not a smaller
// version of it.

func allowRule(dst, port, proto string) *pb.ACLRule {
	return &pb.ACLRule{
		Action:          pb.ACLAction_ACL_ACTION_ALLOW,
		Destination:     dst,
		DestinationPort: port,
		Protocol:        proto,
	}
}

// THE property. Kubernetes NetworkPolicy is allow-only, so an explicit deny
// has no expression. Skipping it would honour the tenant's intent on LXC and
// ignore it on K8s — exactly the asymmetry #1188 is about.
//
// The tempting shortcut is "a deny is redundant under default-deny". That is
// true only when nothing else allows the destination, and false for the
// pattern tenants actually write: allow a wide range, carve out an exception.
func TestCompileEgressRules_RefusesDenyRatherThanDroppingThem(t *testing.T) {
	rules := []*pb.ACLRule{
		allowRule("10.0.0.0/8", "443", "tcp"),
		{
			Action:      pb.ACLAction_ACL_ACTION_DROP,
			Destination: "10.1.2.0/24", // an exception carved out of the allow above
			Protocol:    "tcp",
		},
	}

	compiled, unsupported := compileEgressRules(rules)

	if len(unsupported) != 1 {
		t.Fatalf("unsupported = %v, want exactly the deny rule — dropping it would permit "+
			"10.1.2.0/24, which the tenant explicitly blocked", unsupported)
	}
	if got := unsupported[0].Rule.GetDestination(); got != "10.1.2.0/24" {
		t.Errorf("unsupported rule = %q, want the deny", got)
	}
	// The allow still compiles; the caller decides what to do with a policy
	// that cannot be fully expressed.
	if len(compiled) != 1 {
		t.Errorf("compiled %d rules, want the allow to still compile", len(compiled))
	}
}

func TestCompileEgressRules_RejectAlsoUnsupported(t *testing.T) {
	_, unsupported := compileEgressRules([]*pb.ACLRule{
		{Action: pb.ACLAction_ACL_ACTION_REJECT, Destination: "10.0.0.0/8"},
	})
	if len(unsupported) != 1 {
		t.Fatalf("REJECT must be reported as unsupported, got %v", unsupported)
	}
}

func TestCompileEgressRules_CIDRAndPorts(t *testing.T) {
	compiled, unsupported := compileEgressRules([]*pb.ACLRule{
		allowRule("203.0.113.0/24", "443", "tcp"),
	})
	if len(unsupported) != 0 {
		t.Fatalf("unexpected unsupported: %v", unsupported)
	}
	if len(compiled) != 1 {
		t.Fatalf("compiled %d rules, want 1", len(compiled))
	}
	rule := compiled[0]
	if len(rule.To) != 1 || rule.To[0].IPBlock == nil || rule.To[0].IPBlock.CIDR != "203.0.113.0/24" {
		t.Errorf("peer = %+v, want an IPBlock for 203.0.113.0/24", rule.To)
	}
	if len(rule.Ports) != 1 || rule.Ports[0].Port.IntValue() != 443 {
		t.Errorf("ports = %+v, want 443", rule.Ports)
	}
	if rule.Ports[0].Protocol == nil || *rule.Ports[0].Protocol != corev1.ProtocolTCP {
		t.Errorf("protocol = %v, want TCP", rule.Ports[0].Protocol)
	}
}

func TestCompileEgressRules_PortListAndRange(t *testing.T) {
	compiled, unsupported := compileEgressRules([]*pb.ACLRule{
		allowRule("10.0.0.0/8", "80,443", "tcp"),
		allowRule("10.0.0.0/8", "8000-8100", "tcp"),
	})
	if len(unsupported) != 0 {
		t.Fatalf("unexpected unsupported: %v", unsupported)
	}
	if len(compiled[0].Ports) != 2 {
		t.Errorf("a comma list must become two port entries, got %+v", compiled[0].Ports)
	}
	rangeRule := compiled[1].Ports[0]
	if rangeRule.Port.IntValue() != 8000 || rangeRule.EndPort == nil || *rangeRule.EndPort != 8100 {
		t.Errorf("range compiled to %+v, want 8000-8100", rangeRule)
	}
}

// A bare IP is a valid ACL destination; it must become a host route rather
// than being refused or, worse, widened.
func TestCompileEgressRules_BareAddressBecomesHostRoute(t *testing.T) {
	compiled, unsupported := compileEgressRules([]*pb.ACLRule{allowRule("203.0.113.7", "53", "udp")})
	if len(unsupported) != 0 {
		t.Fatalf("unexpected unsupported: %v", unsupported)
	}
	if got := compiled[0].To[0].IPBlock.CIDR; got != "203.0.113.7/32" {
		t.Errorf("CIDR = %q, want a /32 host route", got)
	}
}

// "*" means the tenant asked for unrestricted egress. NetworkPolicy spells
// that as an empty peer list. It is deliberate, and distinct from the default,
// which stays deny — an allow-all only exists here because someone wrote one.
func TestCompileEgressRules_WildcardIsUnrestricted(t *testing.T) {
	compiled, unsupported := compileEgressRules([]*pb.ACLRule{allowRule("*", "*", "*")})
	if len(unsupported) != 0 {
		t.Fatalf("unexpected unsupported: %v", unsupported)
	}
	if len(compiled) != 1 || len(compiled[0].To) != 0 || len(compiled[0].Ports) != 0 {
		t.Errorf("wildcard compiled to %+v, want an unrestricted rule", compiled[0])
	}
}

// Things with no cluster meaning must be refused rather than guessed at. Pod
// CIDR, node CIDR and service CIDR are all plausible readings of "@internal",
// and picking one silently means something the tenant did not configure.
func TestCompileEgressRules_RefusesHostRelativeDestinations(t *testing.T) {
	for _, dst := range []string{"@internal", "@external"} {
		_, unsupported := compileEgressRules([]*pb.ACLRule{allowRule(dst, "*", "tcp")})
		if len(unsupported) != 1 {
			t.Errorf("destination %q was accepted; it has no cluster equivalent", dst)
		}
	}
}

// ICMP has no NetworkPolicy expression. Silently producing an unrestricted
// rule would fail in the permissive direction.
func TestCompileEgressRules_RefusesICMP(t *testing.T) {
	_, unsupported := compileEgressRules([]*pb.ACLRule{allowRule("10.0.0.0/8", "*", "icmp")})
	if len(unsupported) != 1 {
		t.Fatalf("icmp must be reported as unsupported, got %v", unsupported)
	}
}

func TestCompileEgressRules_RejectsMalformedInput(t *testing.T) {
	for _, tc := range []struct{ name, dst, port, proto string }{
		{"bad cidr", "not-an-address", "443", "tcp"},
		{"bad port", "10.0.0.0/8", "99999", "tcp"},
		{"inverted range", "10.0.0.0/8", "500-100", "tcp"},
		{"unknown protocol", "10.0.0.0/8", "443", "sctp-ish"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, unsupported := compileEgressRules([]*pb.ACLRule{allowRule(tc.dst, tc.port, tc.proto)})
			if len(unsupported) != 1 {
				t.Errorf("malformed rule was accepted: %+v", tc)
			}
		})
	}
}

// Output order must not depend on input order, or every reconcile rewrites the
// object and the diff is unreadable.
func TestCompileEgressRules_DeterministicOrder(t *testing.T) {
	a := allowRule("10.0.0.0/8", "443", "tcp")
	a.Priority = 2
	b := allowRule("192.168.0.0/16", "443", "tcp")
	b.Priority = 1

	first, _ := compileEgressRules([]*pb.ACLRule{a, b})
	second, _ := compileEgressRules([]*pb.ACLRule{b, a})

	if len(first) != 2 || len(second) != 2 {
		t.Fatalf("expected 2 rules each, got %d and %d", len(first), len(second))
	}
	if first[0].To[0].IPBlock.CIDR != second[0].To[0].IPBlock.CIDR {
		t.Errorf("order depends on input: %q vs %q",
			first[0].To[0].IPBlock.CIDR, second[0].To[0].IPBlock.CIDR)
	}
	// Lower priority number sorts first, matching the ACL's own semantics.
	if first[0].To[0].IPBlock.CIDR != "192.168.0.0/16" {
		t.Errorf("priority 1 should sort before priority 2, got %q", first[0].To[0].IPBlock.CIDR)
	}
}

// An empty policy compiles to nothing — the caller keeps the default-deny
// floor rather than receiving an allow-all.
func TestCompileEgressRules_EmptyIsEmpty(t *testing.T) {
	compiled, unsupported := compileEgressRules(nil)
	if len(compiled) != 0 || len(unsupported) != 0 {
		t.Errorf("empty policy compiled to %+v / %v, want nothing at all", compiled, unsupported)
	}
}
