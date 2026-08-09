package k8s

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Compiling a tenant's egress ACL down to Kubernetes NetworkPolicy (#1188).
//
// On the LXC path a tenant's policy becomes eBPF: an egress allowlist, deny
// CIDRs, virtual-patch rules. On K8s none of it was expressed — a tenant who
// set an egress allowlist got it enforced on LXC and silently ignored on K8s,
// with the same SetNetworkPolicy call succeeding either way.
//
// # What cannot be carried across, and why that must be loud
//
// Kubernetes NetworkPolicy is ALLOW-ONLY. There is no deny rule: a policy is
// a set of permitted flows, and everything unlisted is denied by the presence
// of the policy itself. So an explicit DROP/REJECT rule has no equivalent.
//
// Dropping such a rule on the floor would reproduce exactly the bug this
// exists to fix — a tenant's stated intent honoured on one backend and
// quietly ignored on the other. So the compiler REFUSES to compile a policy
// it cannot express faithfully, and names the rules it could not carry. A
// caller can then reject the policy, or record the asymmetry, but it cannot
// fail to notice it.
//
// The narrower reading — "a deny rule is redundant under default-deny, so it
// is safe to skip" — is true only when the denied destination is not also
// matched by an allow rule. It is precisely wrong for the case tenants
// actually write: allow a wide range, then carve an exception out of it.

// UnsupportedEgressRule is a rule that has no faithful NetworkPolicy
// expression.
type UnsupportedEgressRule struct {
	Rule   *pb.ACLRule
	Reason string
}

func (u UnsupportedEgressRule) String() string {
	dst := u.Rule.GetDestination()
	if dst == "" {
		dst = "*"
	}
	return fmt.Sprintf("%s %s (%s)", u.Rule.GetAction(), dst, u.Reason)
}

// compileEgressRules turns a tenant's egress ACL into NetworkPolicy egress
// rules, returning any rule that could not be expressed.
//
// A non-empty unsupported list means the policy MUST NOT be applied as-is:
// the result would permit traffic the tenant asked to block.
func compileEgressRules(rules []*pb.ACLRule) ([]networkingv1.NetworkPolicyEgressRule, []UnsupportedEgressRule) {
	var (
		out         []networkingv1.NetworkPolicyEgressRule
		unsupported []UnsupportedEgressRule
	)

	// Deterministic order: NetworkPolicy semantics do not depend on rule
	// order (it is a union of permitted flows), but a config that reshuffles
	// on every reconcile churns the API server and makes diffs unreadable.
	sorted := make([]*pb.ACLRule, len(rules))
	copy(sorted, rules)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].GetPriority() != sorted[j].GetPriority() {
			return sorted[i].GetPriority() < sorted[j].GetPriority()
		}
		return sorted[i].GetDestination() < sorted[j].GetDestination()
	})

	for _, r := range sorted {
		switch r.GetAction() {
		case pb.ACLAction_ACL_ACTION_ALLOW:
			// carry on below
		case pb.ACLAction_ACL_ACTION_DROP, pb.ACLAction_ACL_ACTION_REJECT:
			unsupported = append(unsupported, UnsupportedEgressRule{
				Rule:   r,
				Reason: "Kubernetes NetworkPolicy is allow-only and cannot express a deny",
			})
			continue
		default:
			unsupported = append(unsupported, UnsupportedEgressRule{
				Rule:   r,
				Reason: "unspecified action",
			})
			continue
		}

		peers, err := egressPeersFor(r.GetDestination())
		if err != nil {
			unsupported = append(unsupported, UnsupportedEgressRule{Rule: r, Reason: err.Error()})
			continue
		}
		ports, err := egressPortsFor(r.GetDestinationPort(), r.GetProtocol())
		if err != nil {
			unsupported = append(unsupported, UnsupportedEgressRule{Rule: r, Reason: err.Error()})
			continue
		}

		out = append(out, networkingv1.NetworkPolicyEgressRule{To: peers, Ports: ports})
	}

	return out, unsupported
}

// egressPeersFor turns an ACL destination into NetworkPolicy peers.
//
// Returns nil peers for "*" — in NetworkPolicy an empty `to` means every
// destination, which is what the tenant asked for. That is deliberate and
// distinct from the DEFAULT, which stays deny: an allow-all rule only exists
// here because someone wrote one.
func egressPeersFor(destination string) ([]networkingv1.NetworkPolicyPeer, error) {
	dst := strings.TrimSpace(destination)
	switch dst {
	case "", "*":
		return nil, nil
	case "@internal", "@external":
		// These are resolved against the host's own networks on the LXC
		// path. There is no equivalent notion inside a cluster, and guessing
		// one (pod CIDR? node CIDR? service CIDR?) would silently mean
		// something different from what the tenant configured.
		return nil, fmt.Errorf("destination %q has no cluster equivalent; use an explicit CIDR", dst)
	}

	prefix, err := netip.ParsePrefix(dst)
	if err != nil {
		// A bare address is a valid ACL destination; widen it to a host route.
		addr, addrErr := netip.ParseAddr(dst)
		if addrErr != nil {
			return nil, fmt.Errorf("destination %q is neither a CIDR nor an IP address", dst)
		}
		prefix = netip.PrefixFrom(addr, addr.BitLen())
	}
	return []networkingv1.NetworkPolicyPeer{
		{IPBlock: &networkingv1.IPBlock{CIDR: prefix.String()}},
	}, nil
}

// egressPortsFor turns an ACL port/protocol pair into NetworkPolicy ports.
//
// "*" on either side means "unrestricted", which NetworkPolicy expresses as
// no port entries at all.
func egressPortsFor(portSpec, protocol string) ([]networkingv1.NetworkPolicyPort, error) {
	proto, err := egressProtocolFor(protocol)
	if err != nil {
		return nil, err
	}

	spec := strings.TrimSpace(portSpec)
	if spec == "" || spec == "*" {
		if proto == nil {
			return nil, nil
		}
		// A protocol with no port still narrows the rule.
		return []networkingv1.NetworkPolicyPort{{Protocol: proto}}, nil
	}

	var ports []networkingv1.NetworkPolicyPort
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			start, err := parsePort(lo)
			if err != nil {
				return nil, err
			}
			end, err := parsePort(hi)
			if err != nil {
				return nil, err
			}
			if end < start {
				return nil, fmt.Errorf("port range %q ends before it starts", part)
			}
			p := intstr.FromInt(int(start))
			endPort := end
			ports = append(ports, networkingv1.NetworkPolicyPort{
				Protocol: proto, Port: &p, EndPort: &endPort,
			})
			continue
		}
		n, err := parsePort(part)
		if err != nil {
			return nil, err
		}
		p := intstr.FromInt(int(n))
		ports = append(ports, networkingv1.NetworkPolicyPort{Protocol: proto, Port: &p})
	}
	return ports, nil
}

// egressProtocolFor maps the ACL protocol onto the K8s one. Nil means "any",
// which NetworkPolicy spells as an unset Protocol.
func egressProtocolFor(protocol string) (*corev1.Protocol, error) {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "", "*", "any":
		return nil, nil
	case "tcp":
		p := corev1.ProtocolTCP
		return &p, nil
	case "udp":
		p := corev1.ProtocolUDP
		return &p, nil
	case "icmp":
		// NetworkPolicy has no ICMP: its ports are TCP/UDP/SCTP only. An ICMP
		// allow silently becoming "no restriction" would be the wrong
		// direction to fail in.
		return nil, fmt.Errorf("protocol icmp cannot be expressed by NetworkPolicy")
	default:
		return nil, fmt.Errorf("unknown protocol %q", protocol)
	}
}

func parsePort(s string) (int32, error) {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 32)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	return int32(n), nil
}
