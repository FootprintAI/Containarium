// Package codeegress holds the pure half of the coding tool's egress
// allowlist (#2370, docs/architecture/coding-cli-egress-allowlist.md):
// validating a CodingToolEgressPolicy and resolving the effective policy a
// run takes. No store, no kernel, no network.
package codeegress

import (
	"errors"
	"fmt"
	"strings"

	"github.com/footprintai/containarium/internal/netpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// validationTenant stands in for the cluster default's empty tenant when the
// lists are checked with netpolicy.Compile, which requires a tenant. Only the
// CIDR, domain and mode rules are taken from it.
const validationTenant = "coding-tool-egress-default"

// Implicit is what the daemon knows about the always-allowed destinations.
// GatewayEndpoint is the host:port a box reaches the model gateway on; empty
// when the daemon cannot name it.
type Implicit struct {
	GatewayEndpoint string
}

// Normalize validates a policy with the same rules as NetworkPolicy and
// returns its stored form: masked, deduped, sorted CIDRs; normalized domains.
// Unlike NetworkPolicy, the mode has no default: UNSPECIFIED (or an unknown
// value) is an error, so a caller who forgets it cannot store a policy that
// drops nothing. Server-assigned fields (revision, updated_at, updated_by)
// are dropped; the store sets them.
func Normalize(p *pb.CodingToolEgressPolicy) (*pb.CodingToolEgressPolicy, error) {
	if p == nil {
		return nil, errors.New("coding-tool egress policy is required")
	}
	switch p.GetMode() {
	case pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY, pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE:
	default:
		return nil, fmt.Errorf("mode must be LOG_ONLY or ENFORCE, got %v: a coding-tool egress policy has no default mode", p.GetMode())
	}
	tenant := strings.TrimSpace(p.GetTenant())
	check := tenant
	if check == "" {
		check = validationTenant
	}
	compiled, err := netpolicy.Compile(&pb.NetworkPolicy{
		Tenant:        check,
		EgressCidrs:   p.GetEgressCidrs(),
		EgressDomains: p.GetEgressDomains(),
		Mode:          p.GetMode(),
	})
	if err != nil {
		return nil, err
	}
	norm := compiled.ToProto()
	return &pb.CodingToolEgressPolicy{
		Tenant:        tenant,
		Mode:          norm.GetMode(),
		EgressCidrs:   nilIfEmpty(norm.GetEgressCidrs()),
		EgressDomains: nilIfEmpty(norm.GetEgressDomains()),
	}, nil
}

// Effective resolves the policy a run for tenant takes. A tenant policy
// replaces the cluster default (no merge); with neither, runs are
// unrestricted (decision Q7). While a policy is in effect the DNS resolver
// and the model gateway are always allowed and listed as implicit entries.
// A policy with empty lists under ENFORCE is deny-all for listed
// destinations.
func Effective(tenant string, tenantPolicy, clusterDefault *pb.CodingToolEgressPolicy, imp Implicit) *pb.EffectiveCodingToolEgressPolicy {
	out := &pb.EffectiveCodingToolEgressPolicy{Tenant: tenant}
	var p *pb.CodingToolEgressPolicy
	switch {
	case tenantPolicy != nil:
		p = tenantPolicy
		out.Source = pb.CodingToolEgressPolicySource_CODING_TOOL_EGRESS_POLICY_SOURCE_TENANT
	case clusterDefault != nil:
		p = clusterDefault
		out.Source = pb.CodingToolEgressPolicySource_CODING_TOOL_EGRESS_POLICY_SOURCE_CLUSTER_DEFAULT
	default:
		out.Source = pb.CodingToolEgressPolicySource_CODING_TOOL_EGRESS_POLICY_SOURCE_NONE
		return out
	}
	out.Restricted = true
	out.Mode = p.GetMode()
	out.EgressCidrs = nilIfEmpty(append([]string(nil), p.GetEgressCidrs()...))
	out.EgressDomains = nilIfEmpty(append([]string(nil), p.GetEgressDomains()...))
	out.Revision = p.GetRevision()
	out.DenyAll = p.GetMode() == pb.NetworkPolicyMode_NETWORK_POLICY_MODE_ENFORCE &&
		len(out.EgressCidrs) == 0 && len(out.EgressDomains) == 0
	out.Implicit = []*pb.CodingToolEgressImplicitEntry{
		{
			Kind:        pb.CodingToolEgressImplicitKind_CODING_TOOL_EGRESS_IMPLICIT_KIND_DNS_RESOLVER,
			Description: "the box's DNS resolver, resolved per box at run start; without it no listed domain resolves",
		},
		{
			Kind:        pb.CodingToolEgressImplicitKind_CODING_TOOL_EGRESS_IMPLICIT_KIND_MODEL_GATEWAY,
			Destination: imp.GatewayEndpoint,
			Description: "the platform's model gateway, for gateway-credential runs only",
		},
	}
	return out
}

func nilIfEmpty(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}
