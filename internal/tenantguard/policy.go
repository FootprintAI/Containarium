// Package tenantguard computes and reconciles the network ACLs that keep one
// tenant's containers off another tenant's containers on a shared Incus
// bridge.
//
// Design: docs/architecture/tenant-network-guard.md. This file is the pure
// half: Compute renders one incus.ACLConfig per tenant from the live
// addresses on a host — allow the host gateway, the core initiators and the
// tenant's own boxes; everything else is dropped by the NIC's default
// ingress action. No I/O lives here; the reconciler that reads the host
// and writes the ACLs is a separate file so the policy can be pinned by
// tests without a fake backend.
package tenantguard

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// Box is one tenant container as the reconciler sees it.
type Box struct {
	Name   string
	Tenant string
	// IPv4 is the box's bridge address; invalid when it has none yet.
	IPv4 netip.Addr
	// IPv6 lists any global/ULA IPv6 addresses on the bridge NIC. Empty on
	// daemons that only report IPv4 (today); the ACL still default-drops
	// IPv6, so an unlisted sibling is denied, never a stranger admitted.
	IPv6 []netip.Addr
}

// Inputs is everything Compute needs about a host.
type Inputs struct {
	// BridgeCIDR is the tenant bridge subnet (e.g. 10.100.0.0/24).
	BridgeCIDR netip.Prefix
	// HostGateway is the bridge address of the host itself: DHCP, DNS, the
	// daemon, the SSH sentinel path and passthrough routes all come from it.
	HostGateway netip.Addr
	// Initiators are the core-role containers that open connections to
	// tenant boxes (Caddy reverse-proxying an exposed port, a co-located
	// control plane actuating a box). Keyed by role; a role with no address
	// yet is absent and rendered on the next pass.
	Initiators map[incus.Role][]netip.Addr
	// Boxes are the tenant containers on the host. A box whose tenant could
	// not be resolved must not be here; the reconciler reports it instead.
	Boxes []Box
	// CrossTenantAllow maps a tenant to the tenants whose boxes may reach
	// it (NetworkPolicy.allow_from_tenants, #2359). One-directional: an
	// entry alice → [bob] admits bob's boxes on alice's NICs only. A listed
	// tenant with no box on this host contributes nothing.
	CrossTenantAllow map[string][]string
}

// Policy is Compute's output: one ACL per tenant present on the host.
type Policy struct {
	ACLs map[string]incus.ACLConfig // tenant → ACL
	// ByTenant lists each tenant's boxes, for status.
	ByTenant map[string][]string
}

// initiatorRoles are the core roles allowed to open connections to tenant
// boxes. Everything else in core (postgres, victoriametrics, otel, ...) only
// ever receives from tenants and is covered by the core guard. Keep in step
// with the table in the design doc; TestCompute_Initiators pins it.
var initiatorRoles = []incus.Role{incus.RoleCaddy, incus.RoleControlPlane}

// ACLName is the Incus network ACL name for a tenant's guard:
// containarium-tenant-<first 12 hex of sha256(tenant)>. Tenant ids are org
// UUIDs or free-form names; the hash keeps the name short, stable and
// Incus-safe regardless.
func ACLName(tenant string) string {
	sum := sha256.Sum256([]byte(tenant))
	return "containarium-tenant-" + hex.EncodeToString(sum[:])[:12]
}

// Compute renders the allow table for one host. It validates every IPv4
// address against the bridge first — a rule with a wrong subnet would be a
// silent allow for the wrong thing — and produces rules in a fixed order so
// an unchanged host yields byte-identical ACLs (the reconciler diffs on
// them).
func Compute(in Inputs) (Policy, error) {
	if err := validate(in); err != nil {
		return Policy{}, err
	}

	byTenant := map[string][]Box{}
	for _, b := range in.Boxes {
		byTenant[b.Tenant] = append(byTenant[b.Tenant], b)
	}

	pol := Policy{ACLs: make(map[string]incus.ACLConfig, len(byTenant)), ByTenant: make(map[string][]string, len(byTenant))}
	for tenant, boxes := range byTenant {
		acl := incus.ACLConfig{
			Name:        ACLName(tenant),
			Description: fmt.Sprintf("containarium tenant guard for %s — managed by containariumd, do not edit", tenant),
		}
		add := func(src, what string) {
			acl.IngressRules = append(acl.IngressRules, incus.ACLRule{
				Action:      "allow",
				Source:      src,
				Description: what,
			})
		}
		add(host32(in.HostGateway), "host gateway")
		for _, role := range initiatorRoles {
			for _, a := range sortedAddrs(in.Initiators[role]) {
				add(hostPrefix(a), string(role))
			}
		}
		names := make([]string, 0, len(boxes))
		for _, b := range sortedBoxes(boxes) {
			names = append(names, b.Name)
			if b.IPv4.IsValid() {
				add(host32(b.IPv4), "same tenant: "+b.Name)
			}
			for _, a := range sortedAddrs(b.IPv6) {
				add(hostPrefix(a), "same tenant: "+b.Name)
			}
		}
		// Cross-tenant allow (#2359): the boxes of every tenant this tenant
		// listed, after the siblings so the order stays stable.
		for _, from := range sortedUniq(in.CrossTenantAllow[tenant]) {
			if from == tenant {
				continue // siblings are already allowed; allow_intra_tenant's job
			}
			for _, b := range sortedBoxes(byTenant[from]) {
				if b.IPv4.IsValid() {
					add(host32(b.IPv4), "allowed tenant "+from+": "+b.Name)
				}
				for _, a := range sortedAddrs(b.IPv6) {
					add(hostPrefix(a), "allowed tenant "+from+": "+b.Name)
				}
			}
		}
		pol.ACLs[tenant] = acl
		pol.ByTenant[tenant] = names
	}
	return pol, nil
}

func validate(in Inputs) error {
	if !in.BridgeCIDR.IsValid() {
		return fmt.Errorf("tenantguard: bridge CIDR is not set")
	}
	if !in.BridgeCIDR.Addr().Is4() {
		return fmt.Errorf("tenantguard: bridge %s is not IPv4", in.BridgeCIDR)
	}
	bridge := in.BridgeCIDR.Masked()
	if err := inBridge("host gateway", in.HostGateway, bridge); err != nil {
		return err
	}
	for role, addrs := range in.Initiators {
		for _, a := range addrs {
			if a.Is4() {
				if err := inBridge(string(role), a, bridge); err != nil {
					return err
				}
			}
		}
	}
	for _, b := range in.Boxes {
		if b.Tenant == "" {
			return fmt.Errorf("tenantguard: box %s has no tenant", b.Name)
		}
		if b.IPv4.IsValid() {
			if err := inBridge(b.Name, b.IPv4, bridge); err != nil {
				return err
			}
			if b.IPv4 == in.HostGateway {
				return fmt.Errorf("tenantguard: box %s has the host gateway's address %s", b.Name, b.IPv4)
			}
		}
	}
	return nil
}

func inBridge(what string, a netip.Addr, bridge netip.Prefix) error {
	if !a.IsValid() {
		return fmt.Errorf("tenantguard: %s has no address", what)
	}
	if !a.Is4() {
		return fmt.Errorf("tenantguard: %s address %s is not IPv4", what, a)
	}
	if !bridge.Contains(a) {
		return fmt.Errorf("tenantguard: %s address %s is outside the bridge %s", what, a, bridge)
	}
	return nil
}

func host32(a netip.Addr) string { return netip.PrefixFrom(a, 32).String() }

func hostPrefix(a netip.Addr) string {
	if a.Is4() {
		return host32(a)
	}
	return netip.PrefixFrom(a, 128).String()
}

func sortedAddrs(in []netip.Addr) []netip.Addr {
	out := append([]netip.Addr(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

func sortedUniq(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func sortedBoxes(in []Box) []Box {
	out := append([]Box(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
