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
	Mode             pb.NetworkPolicyMode
	// LogOnly is true unless Mode is ENFORCE — i.e. UNSPECIFIED and LOG_ONLY
	// both observe-only (Phase A default), only ENFORCE drops packets.
	LogOnly bool
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
		Mode:             mode,
		LogOnly:          mode != pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE,
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
	return &pb.NetworkPolicy{
		Tenant:           c.Tenant,
		AllowIntraTenant: c.AllowIntraTenant,
		EgressCidrs:      cidrs,
		EgressDomains:    append([]string(nil), c.EgressDomains...),
		Mode:             c.Mode,
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
