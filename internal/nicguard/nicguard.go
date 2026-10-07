// Package nicguard holds what the two Incus NIC-ACL guards share: the arming
// mode and its parser, the firewall-driver precondition, the bridge parser,
// and the create-or-update-on-drift ACL writer.
//
// The core-infra guard (internal/coreguard, docs/architecture/core-infra-network-guard.md)
// protects core-role containers from tenants; the tenant guard
// (internal/tenantguard, docs/architecture/tenant-network-guard.md) protects
// tenants from each other. Both render an incus.ACLConfig per subject and
// reconcile it onto the subject's NIC; this package is the part of that
// loop that does not depend on who the subject is.
package nicguard

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/lxc/incus/v7/shared/api"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// Mode is a guard's arming state. There is no audit mode: an Incus NIC ACL
// either drops or it doesn't. Evidence comes from the logged default
// action, and rollout safety from the e2e scripts, not from a soft mode.
type Mode string

const (
	ModeOff     Mode = "off"
	ModeEnforce Mode = "enforce"
)

// ParseMode maps a CONTAINARIUM_*_GUARD value to a Mode. Unset is enforce:
// both guards are boundaries, not optional hardening, so a host that says
// nothing is guarded (docs/architecture/tenant-network-guard.md, Rollout).
// Only an explicit off-word disables; anything else — including a typo —
// fails closed to enforce.
func ParseMode(s string) Mode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "off", "0", "false", "no", "disabled", "disable":
		return ModeOff
	}
	return ModeEnforce
}

// ErrUnsupportedFirewall is returned when the host's Incus firewall driver
// cannot enforce bridge NIC ACLs (only nftables can). A reconciler refuses
// to attach anything rather than leave the operator believing they are
// guarded.
var ErrUnsupportedFirewall = errors.New("incus firewall driver is not nftables; bridge NIC ACLs cannot be enforced")

// ErrUnsupportedIncus is returned when the host's Incus predates NIC-level
// ACLs on bridged NICs (API extension network_bridge_acl_devices, Incus
// 6.9+; Ubuntu's packaged Incus 6.0.0 lacks it, the Zabbly 7.x builds
// have it). The older network_bridge_acl extension is the bridge-level
// key and is NOT sufficient.
var ErrUnsupportedIncus = errors.New("incus lacks the network_bridge_acl_devices API extension (Incus 6.9+); upgrade Incus to apply bridge NIC ACLs")

// RequiredFirewall is the only Incus firewall driver that renders NIC-level
// ACLs (doc/howto/network_acls.md, "Bridge limitations").
const RequiredFirewall = "nftables"

// RequiredExtension is the Incus API extension that brings security.acls
// (and the default action/logged keys) to bridged NIC devices.
const RequiredExtension = "network_bridge_acl_devices"

// Unsupported reports whether err means this host cannot carry bridge NIC
// ACLs at all (wrong firewall driver, Incus too old) — as opposed to a
// failure on a host that can. The distinction decides fail-open vs
// fail-closed: a host that cannot be guarded is reported loudly and left
// as it was; a box that could not be guarded on a capable host is refused.
func Unsupported(err error) bool {
	return errors.Is(err, ErrUnsupportedFirewall) || errors.Is(err, ErrUnsupportedIncus)
}

// CheckSupport reads the server and returns the firewall driver plus an
// Unsupported error when NIC ACLs cannot be applied here. Checked every
// pass: a driver or an Incus upgrade changes the answer without a daemon
// restart.
func CheckSupport(be incus.Backend) (string, error) {
	info, err := be.GetServerInfo()
	if err != nil {
		return "", fmt.Errorf("server info: %w", err)
	}
	driver := info.Environment.Firewall
	if driver != RequiredFirewall {
		return driver, fmt.Errorf("%w (driver=%q)", ErrUnsupportedFirewall, driver)
	}
	hasExt := false
	for _, e := range info.APIExtensions {
		if e == RequiredExtension {
			hasExt = true
			break
		}
	}
	if !hasExt {
		return driver, fmt.Errorf("%w (incus %s)", ErrUnsupportedIncus, info.Environment.ServerVersion)
	}
	return driver, nil
}

// ParseBridge turns Incus's ipv4.address ("10.100.0.1/24") into the bridge
// prefix and the host gateway. A network-form value ("10.100.0.0/24")
// yields base+1 as the gateway, which is what Incus assigns itself.
func ParseBridge(s string) (netip.Prefix, netip.Addr, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, netip.Addr{}, fmt.Errorf("bridge cidr %q: %w", s, err)
	}
	if !p.Addr().Is4() {
		return netip.Prefix{}, netip.Addr{}, fmt.Errorf("bridge cidr %q is not IPv4", s)
	}
	bridge := p.Masked()
	gw := p.Addr()
	if gw == bridge.Addr() {
		gw = gw.Next()
	}
	return bridge, gw, nil
}

// EnsureACL creates the ACL when Incus doesn't have it and updates it only
// when its rules differ from desired. Returns whether a write happened.
func EnsureACL(be incus.Backend, desired incus.ACLConfig) (bool, error) {
	existing, err := be.GetNetworkACL(desired.Name)
	if err != nil {
		// Treat any read failure as "absent": a create against an ACL that
		// does exist fails loudly and is retried next pass, which is safer
		// than assuming it matches.
		if cerr := be.CreateNetworkACL(desired); cerr != nil {
			return false, fmt.Errorf("create acl %s: %w", desired.Name, cerr)
		}
		return true, nil
	}
	if ACLEqual(existing, desired) {
		return false, nil
	}
	if uerr := be.UpdateNetworkACL(desired.Name, desired); uerr != nil {
		return false, fmt.Errorf("update acl %s: %w", desired.Name, uerr)
	}
	return true, nil
}

// ACLEqual compares what Incus holds with what a guard wants, on the fields
// the guards set. Order-insensitive: Incus may return rules in its own
// order.
func ACLEqual(have *api.NetworkACL, want incus.ACLConfig) bool {
	if have == nil || len(have.Egress) != len(want.EgressRules) || len(have.Ingress) != len(want.IngressRules) {
		return false
	}
	if have.Description != want.Description {
		return false
	}
	key := func(action, src, dst, proto, dport string) string {
		return action + "|" + src + "|" + dst + "|" + proto + "|" + dport
	}
	seen := map[string]int{}
	for _, rl := range have.Ingress {
		seen[key(rl.Action, rl.Source, rl.Destination, rl.Protocol, rl.DestinationPort)]++
	}
	for _, rl := range want.IngressRules {
		k := key(rl.Action, rl.Source, rl.Destination, rl.Protocol, rl.DestinationPort)
		if seen[k] == 0 {
			return false
		}
		seen[k]--
	}
	return true
}

// NICKeys are the per-device keys a guard sets next to the ACL name:
// ingress default-drop (logged), egress left to the eBPF enforcer.
func NICKeys(acl string) map[string]string {
	return map[string]string{
		"security.acls":                        acl,
		"security.acls.default.ingress.action": "drop",
		"security.acls.default.ingress.logged": "true",
		"security.acls.default.egress.action":  "allow",
	}
}
