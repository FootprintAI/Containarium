// Package netpolicy validates and compiles per-tenant NetworkPolicy values
// (the Phase A control-plane half of the eBPF network-isolation design) into
// the normalized form the per-veth TC_INGRESS BPF loader consumes.
//
// It is deliberately pure (no BPF, no DB, no network): given a *pb.NetworkPolicy
// it returns either a validation error or a CompiledPolicy with parsed/deduped
// CIDRs, normalized domains, and a resolved mode. The BPF map-update plumbing
// (a later Phase A increment) turns a CompiledPolicy into map entries. See
// docs/security/NETWORK-ISOLATION-DESIGN.md (#315).
package netpolicy

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// CompiledPolicy is the normalized, validated form of a NetworkPolicy, ready for
// the BPF loader. Egress is allowed to any EgressCIDRs plus the CIDRs the
// daemon resolves from EgressDomains; intra-tenant peer traffic is gated by
// AllowIntraTenant.
type CompiledPolicy struct {
	Tenant           string
	AllowIntraTenant bool
	EgressCIDRs      []netip.Prefix // parsed, masked-to-network, deduped, sorted
	EgressDomains    []string       // lowercased, trimmed, deduped, sorted
	AllowMetadata    bool           // may reach the cloud metadata service (default deny)
	Mode             pb.NetworkPolicyMode
	// LogOnly is true unless Mode is ENFORCE — i.e. UNSPECIFIED and LOG_ONLY
	// both observe-only (Phase A default), only ENFORCE drops packets.
	LogOnly bool
	// DenyRules are virtual-patch block rules (#660): parsed/masked/deduped/sorted
	// destination prefixes (optionally port/proto-scoped) that are denied BEFORE
	// the egress allow-list is consulted — deny beats allow. Expiry is preserved
	// here (not filtered) so the package stays time-pure; the daemon drops expired
	// rules with DenyRule.Expired(now) before pushing them to the kernel.
	DenyRules []DenyRule
}

// DenyRule is one normalized virtual-patch block rule (#660). The destination
// CIDR is matched first; Port/Proto (0 = any) further scope the block to a
// single service. A host IP is carried as a /32.
type DenyRule struct {
	CIDR      netip.Prefix
	Port      uint16    // 0 = any port
	Proto     uint8     // IP protocol number (0 = any; 6 = tcp, 17 = udp)
	Note      string    // operator note, typically a CVE id
	ExpiresAt time.Time // zero = no expiry
}

// Expired reports whether the rule's expiry has passed relative to now. A
// zero ExpiresAt never expires.
func (d DenyRule) Expired(now time.Time) bool {
	return !d.ExpiresAt.IsZero() && now.After(d.ExpiresAt)
}

// Validate reports whether a NetworkPolicy is well-formed without compiling it.
// Compile performs the same checks, so callers that only need the compiled
// result can skip Validate.
func Validate(p *pb.NetworkPolicy) error {
	_, err := Compile(p)
	return err
}

// Compile validates and normalizes a NetworkPolicy.
func Compile(p *pb.NetworkPolicy) (CompiledPolicy, error) {
	if p == nil {
		return CompiledPolicy{}, fmt.Errorf("network policy is nil")
	}
	tenant := strings.TrimSpace(p.GetTenant())
	if tenant == "" {
		return CompiledPolicy{}, fmt.Errorf("network policy: tenant is required")
	}

	cidrs, err := compileCIDRs(p.GetEgressCidrs())
	if err != nil {
		return CompiledPolicy{}, err
	}
	domains, err := compileDomains(p.GetEgressDomains())
	if err != nil {
		return CompiledPolicy{}, err
	}
	deny, err := compileDenyRules(p.GetDenyRules())
	if err != nil {
		return CompiledPolicy{}, err
	}

	// Unspecified defaults to log-only in Phase A; reject unknown enum values.
	mode := p.GetMode()
	switch mode {
	case pb.NetworkPolicyMode_NETWORK_POLICY_MODE_UNSPECIFIED:
		mode = pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY
	case pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY,
		pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE:
		// ok
	default:
		return CompiledPolicy{}, fmt.Errorf("network policy: unknown mode %d", int32(mode))
	}

	return CompiledPolicy{
		Tenant:           tenant,
		AllowIntraTenant: p.GetAllowIntraTenant(),
		EgressCIDRs:      cidrs,
		EgressDomains:    domains,
		AllowMetadata:    p.GetAllowMetadata(),
		Mode:             mode,
		LogOnly:          mode != pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE,
		DenyRules:        deny,
	}, nil
}

// ToProto renders a CompiledPolicy back into a NetworkPolicy message — the
// normalized form to persist and echo to callers (masked/deduped/sorted CIDRs,
// normalized domains, resolved mode).
func (c CompiledPolicy) ToProto() *pb.NetworkPolicy {
	cidrs := make([]string, len(c.EgressCIDRs))
	for i, p := range c.EgressCIDRs {
		cidrs[i] = p.String()
	}
	var deny []*pb.NetworkPolicyDenyRule
	if len(c.DenyRules) > 0 {
		deny = make([]*pb.NetworkPolicyDenyRule, len(c.DenyRules))
		for i, d := range c.DenyRules {
			var exp string
			if !d.ExpiresAt.IsZero() {
				exp = d.ExpiresAt.UTC().Format(time.RFC3339)
			}
			deny[i] = &pb.NetworkPolicyDenyRule{
				Cidr:      d.CIDR.String(),
				Port:      uint32(d.Port),
				Proto:     protoName(d.Proto),
				Note:      d.Note,
				ExpiresAt: exp,
			}
		}
	}
	return &pb.NetworkPolicy{
		Tenant:           c.Tenant,
		AllowIntraTenant: c.AllowIntraTenant,
		EgressCidrs:      cidrs,
		EgressDomains:    append([]string(nil), c.EgressDomains...),
		AllowMetadata:    c.AllowMetadata,
		Mode:             c.Mode,
		DenyRules:        deny,
	}
}

// compileCIDRs parses each egress CIDR, masks it to its network address (so
// "1.2.3.4/24" canonicalizes to "1.2.3.0/24"), dedupes, and sorts.
func compileCIDRs(raw []string) ([]netip.Prefix, error) {
	seen := make(map[string]netip.Prefix, len(raw))
	for _, c := range raw {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("network policy: invalid egress CIDR %q: %w", c, err)
		}
		p = p.Masked()
		seen[p.String()] = p
	}
	out := make([]netip.Prefix, 0, len(seen))
	for _, p := range seen {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out, nil
}

// compileDenyRules parses each virtual-patch deny rule (#660): the CIDR is
// required (a bare host IP is taken as /32 and masked); port must fit a u16;
// proto is "tcp"|"udp"|""(any); expires_at, if set, must be RFC3339.
//
// Rules are deduped by CIDR — at most one rule per destination prefix, the LAST
// one in the list winning. This matches the kernel's deny_cidr LPM map, whose
// key is CIDR-only (port/proto live in the value), so a single CIDR maps to a
// single slot. Allowing two rules for the same CIDR with different ports here
// would compile to the same kernel slot and one would silently clobber the
// other; collapsing to one-per-CIDR makes the policy say exactly what the kernel
// can enforce. To block more than one port on a host, deny the host (port 0).
//
// Sorted by CIDR so reconcile diffs are stable. Expiry is NOT applied here (the
// package is time-pure); it is carried on the DenyRule for the daemon to drop.
func compileDenyRules(raw []*pb.NetworkPolicyDenyRule) ([]DenyRule, error) {
	seen := make(map[string]DenyRule, len(raw))
	for _, r := range raw {
		if r == nil {
			continue
		}
		c := strings.TrimSpace(r.GetCidr())
		if c == "" {
			return nil, fmt.Errorf("network policy: deny rule cidr is required")
		}
		var prefix netip.Prefix
		if strings.Contains(c, "/") {
			p, err := netip.ParsePrefix(c)
			if err != nil {
				return nil, fmt.Errorf("network policy: invalid deny cidr %q: %w", c, err)
			}
			prefix = p.Masked()
		} else {
			a, err := netip.ParseAddr(c)
			if err != nil {
				return nil, fmt.Errorf("network policy: invalid deny address %q: %w", c, err)
			}
			prefix = netip.PrefixFrom(a, a.BitLen())
		}
		if r.GetPort() > 65535 {
			return nil, fmt.Errorf("network policy: deny rule port %d out of range (0-65535)", r.GetPort())
		}
		proto, err := parseProto(r.GetProto())
		if err != nil {
			return nil, err
		}
		var exp time.Time
		if s := strings.TrimSpace(r.GetExpiresAt()); s != "" {
			t, err := time.Parse(time.RFC3339, s)
			if err != nil {
				return nil, fmt.Errorf("network policy: invalid deny expires_at %q (want RFC3339): %w", s, err)
			}
			exp = t
		}
		seen[prefix.String()] = DenyRule{
			CIDR:      prefix,
			Port:      uint16(r.GetPort()),
			Proto:     proto,
			Note:      strings.TrimSpace(r.GetNote()),
			ExpiresAt: exp,
		}
	}
	out := make([]DenyRule, 0, len(seen))
	for _, d := range seen {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CIDR.String() < out[j].CIDR.String() })
	return out, nil
}

// parseProto maps a friendly protocol name to its IP protocol number. ""/"any"
// is 0 (match any protocol).
func parseProto(s string) (uint8, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "any":
		return 0, nil
	case "tcp":
		return 6, nil
	case "udp":
		return 17, nil
	default:
		return 0, fmt.Errorf("network policy: unknown deny proto %q (want tcp, udp, or empty)", s)
	}
}

// protoName is the inverse of parseProto for echoing a normalized policy back.
func protoName(p uint8) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return ""
	}
}

// compileDomains normalizes egress domains (lowercase, trim, strip a trailing
// dot), rejects anything that carries a scheme/port/path, dedupes, and sorts.
func compileDomains(raw []string) ([]string, error) {
	seen := make(map[string]struct{}, len(raw))
	for _, d := range raw {
		d = strings.ToLower(strings.TrimSpace(d))
		d = strings.TrimSuffix(d, ".")
		if d == "" {
			continue
		}
		if strings.ContainsAny(d, "/:") || strings.Contains(d, " ") {
			return nil, fmt.Errorf("network policy: egress domain %q must be a bare hostname (no scheme/port/path)", d)
		}
		seen[d] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for d := range seen {
		out = append(out, d)
	}
	sort.Strings(out)
	return out, nil
}
