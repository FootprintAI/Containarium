// Package coreguard computes the network ACLs that isolate the platform's
// core-role containers (core-postgres, core-victoriametrics, ...) from
// tenant containers sharing the same Incus bridge.
//
// Design: docs/architecture/core-infra-network-guard.md. This file is the
// pure half — a typed table of "who may legitimately reach which role on
// which port" and Compute, which renders it into one incus.ACLConfig per
// guarded role from the live addresses on a host. No I/O lives here; the
// reconciler that reads the host and writes the ACLs is a separate file so
// the table can be pinned by tests without a fake backend.
package coreguard

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// Inputs is everything Compute needs about a host: the tenant bridge, the
// daemon's address on it, where each core-role container currently is, and
// any co-located control planes. Addresses are live — the reconciler feeds
// whatever incus reports, so a core container that moves gets its rules
// re-rendered rather than stranded.
type Inputs struct {
	// BridgeCIDR is the tenant bridge subnet (e.g. 10.100.0.0/24). It is the
	// only non-/32 source the table ever uses, and only for the two ports
	// tenants are meant to reach.
	BridgeCIDR netip.Prefix
	// HostGateway is the bridge address of the host itself — where the
	// daemon's own connections (Postgres pool, Caddy admin, metrics) come
	// from.
	HostGateway netip.Addr
	// Core maps each core role present on the host to its IPv4. A role with
	// no address (still booting) is simply absent; its rules are omitted
	// from peers for this pass and rendered on the next.
	Core map[incus.Role]netip.Addr
	// ControlPlane lists any co-located control-plane containers
	// (incus.RoleControlPlane). They are sources in the table, never
	// guarded subjects.
	ControlPlane []netip.Addr
}

// Policy is Compute's output: one ACL per guarded role, plus the roles the
// table does not know. An unknown role still gets an (empty) ACL — attached,
// it default-drops everything, which is the safe failure — and is reported
// so the table gets extended deliberately instead of silently.
type Policy struct {
	ACLs         map[incus.Role]incus.ACLConfig
	UnknownRoles []incus.Role
}

// ACLName is the Incus network ACL name for a role's guard:
// containarium-core-guard-<role without the core- prefix>.
func ACLName(role incus.Role) string {
	return "containarium-core-guard-" + strings.TrimPrefix(string(role), "core-")
}

// sourceKind says who a listener rule admits. Every rule's source is one of
// these — there is deliberately no "anyone" kind.
type sourceKind uint8

const (
	fromHost         sourceKind = iota // the host gateway /32
	fromBridge                         // the whole tenant bridge — only for tenant-facing ports
	fromControlPlane                   // each control-plane container /32
	fromCore                           // one named core role's /32
)

type source struct {
	kind sourceKind
	role incus.Role // set when kind == fromCore
}

// listener is one row of the table: a tcp port group on a role and the
// sources allowed to reach it.
type listener struct {
	ports string
	from  []source
}

// table is the allow-list. Sources are always the host gateway, a specific
// core/control-plane container, or — for exactly the ports tenants are meant
// to use — the bridge CIDR. Everything not listed is dropped by the NIC's
// default ingress action. Keep this in step with the table in the design
// doc; TestCompute_RoleTable pins it.
var table = map[incus.Role][]listener{
	incus.RolePostgres: {
		// daemon connection pool; Grafana's datastore. The live pg_stat_activity
		// client set observed during the incident that motivated the guard.
		{ports: "5432", from: []source{{kind: fromHost}, {kind: fromCore, role: incus.RoleVictoriaMetrics}}},
	},
	incus.RoleVictoriaMetrics: {
		// VictoriaMetrics + alertmanager: daemon and control plane write/query.
		{ports: "8428,8880,9093,9094", from: []source{{kind: fromHost}, {kind: fromControlPlane}}},
		// Grafana is fronted by Caddy; never reachable from tenants directly.
		{ports: "3000", from: []source{{kind: fromHost}, {kind: fromCore, role: incus.RoleCaddy}}},
	},
	incus.RoleOTelCollector: {
		// Tenants with monitoring=true push OTLP by design.
		{ports: "4317,4318", from: []source{{kind: fromBridge}}},
		// health + self-metrics
		{ports: "13133,8888", from: []source{{kind: fromHost}}},
	},
	incus.RoleCaddy: {
		// The base domain resolves in-bridge; tenants and agent boxes reach the
		// platform API through Caddy.
		{ports: "80,443", from: []source{{kind: fromBridge}}},
		// Admin API: the daemon drives it over the bridge from the host.
		{ports: "2019", from: []source{{kind: fromHost}}},
	},
	// No listeners: everything dropped.
	incus.RoleSecurity: {},
	incus.RoleGuacamole: {
		{ports: "8080", from: []source{{kind: fromHost}, {kind: fromCore, role: incus.RoleCaddy}}},
	},
}

// Compute renders the table for one host. It validates every address
// against the bridge first — a rule with a wrong subnet would be a silent
// allow for the wrong thing — and produces rules in a fixed order so an
// unchanged host yields byte-identical ACLs (a reconciler diffs on them).
func Compute(in Inputs) (Policy, error) {
	if err := validate(in); err != nil {
		return Policy{}, err
	}
	bridge := in.BridgeCIDR.Masked()

	pol := Policy{ACLs: make(map[incus.Role]incus.ACLConfig, len(in.Core))}
	for role := range in.Core {
		if role == incus.RoleControlPlane {
			// Platform infrastructure that tenants legitimately call and that
			// must reach every box (#780): a source, never a subject.
			continue
		}
		rows, known := table[role]
		if !known {
			pol.UnknownRoles = append(pol.UnknownRoles, role)
		}

		acl := incus.ACLConfig{
			Name:        ACLName(role),
			Description: fmt.Sprintf("containarium core-infra guard for %s — managed by containariumd, do not edit", role),
		}
		for _, l := range rows {
			for _, src := range l.from {
				for _, cidr := range resolve(src, in, bridge) {
					acl.IngressRules = append(acl.IngressRules, incus.ACLRule{
						Action:          "allow",
						Source:          cidr,
						Protocol:        "tcp",
						DestinationPort: l.ports,
						Description:     fmt.Sprintf("%s: %s from %s", role, l.ports, describe(src)),
					})
				}
			}
		}
		sort.SliceStable(acl.IngressRules, func(i, j int) bool {
			a, b := acl.IngressRules[i], acl.IngressRules[j]
			if a.DestinationPort != b.DestinationPort {
				return a.DestinationPort < b.DestinationPort
			}
			return a.Source < b.Source
		})
		pol.ACLs[role] = acl
	}
	sort.Slice(pol.UnknownRoles, func(i, j int) bool { return pol.UnknownRoles[i] < pol.UnknownRoles[j] })
	return pol, nil
}

// resolve turns a table source into concrete CIDR strings. A peer that is
// not present on the host resolves to nothing — the rule is omitted, not
// rendered with a placeholder.
func resolve(src source, in Inputs, bridge netip.Prefix) []string {
	switch src.kind {
	case fromHost:
		return []string{host32(in.HostGateway)}
	case fromBridge:
		return []string{bridge.String()}
	case fromControlPlane:
		out := make([]string, 0, len(in.ControlPlane))
		for _, a := range in.ControlPlane {
			out = append(out, host32(a))
		}
		return out
	case fromCore:
		if a, ok := in.Core[src.role]; ok {
			return []string{host32(a)}
		}
		return nil
	}
	return nil
}

func describe(src source) string {
	switch src.kind {
	case fromHost:
		return "host gateway"
	case fromBridge:
		return "tenant bridge"
	case fromControlPlane:
		return "control plane"
	case fromCore:
		return string(src.role)
	}
	return "unknown"
}

func host32(a netip.Addr) string {
	return netip.PrefixFrom(a, 32).String()
}

func validate(in Inputs) error {
	if !in.BridgeCIDR.IsValid() {
		return fmt.Errorf("coreguard: bridge CIDR is not set")
	}
	if !in.BridgeCIDR.Addr().Is4() {
		return fmt.Errorf("coreguard: bridge %s is not IPv4 (the guard is IPv4-only, like the bridge it protects)", in.BridgeCIDR)
	}
	bridge := in.BridgeCIDR.Masked()
	if err := inBridge("host gateway", in.HostGateway, bridge); err != nil {
		return err
	}
	for role, a := range in.Core {
		if err := inBridge(string(role), a, bridge); err != nil {
			return err
		}
		if a == in.HostGateway {
			return fmt.Errorf("coreguard: %s has the host gateway's address %s", role, a)
		}
	}
	for i, a := range in.ControlPlane {
		if err := inBridge(fmt.Sprintf("control plane[%d]", i), a, bridge); err != nil {
			return err
		}
	}
	return nil
}

func inBridge(what string, a netip.Addr, bridge netip.Prefix) error {
	if !a.IsValid() {
		return fmt.Errorf("coreguard: %s has no address", what)
	}
	if !a.Is4() {
		return fmt.Errorf("coreguard: %s address %s is not IPv4", what, a)
	}
	if !bridge.Contains(a) {
		return fmt.Errorf("coreguard: %s address %s is outside the bridge %s", what, a, bridge)
	}
	return nil
}
