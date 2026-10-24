package netpolicy

import (
	"fmt"
	"slices"
	"strings"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// defaultEgressDomains is the built-in part of the default egress allow-list
// (#2577, stage 1 of the staged default-deny decision): git hosts and the
// package registries of the supported base images. DNS is not listed; the
// ALLOW_LIST_ONLY preset allows the box's resolver implicitly. The model
// gateway and the control plane are deployment-specific, so the operator adds
// them through DefaultEgressExtras.
//
// This is a starting point for the soak, not a final list: stage 2 reviews the
// logged denials (network_policy.deny_logged) and fixes this list, not the
// tenant.
var defaultEgressDomains = []string{
	// git hosts
	"github.com", "api.github.com", "codeload.github.com", "gitlab.com", "bitbucket.org",
	// language registries
	"registry.npmjs.org", "pypi.org", "files.pythonhosted.org",
	"proxy.golang.org", "sum.golang.org", "index.crates.io", "static.crates.io",
	// OS package mirrors for the supported base images
	"deb.debian.org", "security.debian.org", "archive.ubuntu.com", "security.ubuntu.com",
}

// DefaultEgressDomains returns a copy of the built-in default allow-list
// domains, sorted.
func DefaultEgressDomains() []string {
	out := slices.Clone(defaultEgressDomains)
	slices.Sort(out)
	return out
}

// DefaultEgressExtras are the operator-supplied additions to the default
// allow-list: typically the model gateway and the control plane.
type DefaultEgressExtras struct {
	Domains []string
	CIDRs   []string
}

// DefaultPolicy is the policy a tenant with no stored policy runs under. It is
// observe-only by construction (LOG_ONLY for both modes): arming enforce is a
// per-tenant decision made by storing a policy, never something the default
// does. A bad extra is an error rather than a silent drop, so a typo cannot
// quietly narrow the list.
func DefaultPolicy(tenant string, extras DefaultEgressExtras) (CompiledPolicy, error) {
	tenant = strings.TrimSpace(tenant)
	if tenant == "" {
		return CompiledPolicy{}, fmt.Errorf("default network policy: tenant is required")
	}
	p := &pb.NetworkPolicy{
		Tenant:        tenant,
		Mode:          pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY,
		EgressMode:    pb.NetworkPolicyMode_NETWORK_POLICY_MODE_LOG_ONLY,
		EgressPreset:  pb.EgressPreset_EGRESS_PRESET_ALLOW_LIST_ONLY,
		EgressDomains: append(DefaultEgressDomains(), extras.Domains...),
		EgressCidrs:   slices.Clone(extras.CIDRs),
	}
	return Compile(p)
}

// ParseDefaultEgress reads the raw CONTAINARIUM_NETWORK_DEFAULT_EGRESS* values.
// Like the NIC guards, only an explicit off-word disables the default
// posture; anything else, including a typo, keeps it on, because the default
// is observe-only and failing open on a typo would silently remove it.
func ParseDefaultEgress(mode, domains, cidrs string) (enabled bool, extras DefaultEgressExtras) {
	enabled = true
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "off", "0", "false", "no", "disabled", "disable":
		enabled = false
	}
	return enabled, DefaultEgressExtras{Domains: splitList(domains), CIDRs: splitList(cidrs)}
}

func splitList(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}
