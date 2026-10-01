package anonbox

import (
	"fmt"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// EgressACLName is the one shared Incus network ACL every anonymous box's
// NIC carries. Shared on purpose: the rules are identical for every box,
// and one ACL means one place an operator reads to see what the tier may
// reach.
const EgressACLName = "containarium-anon-egress"

// egressACL is "deny-by-default except DNS, HTTP, HTTPS" (PRD story 4).
// The deny itself is not a rule here — it is the NIC's
// security.acls.default.egress.action=drop (see nicACLKeys) — so the ACL
// only lists what is allowed. Ingress is left to the NIC default (allow):
// the sentinel must still reach sshd.
//
// Why an Incus ACL and not a NetworkPolicy (decision on #2197): the
// NetworkPolicy model allows by CIDR/domain only and hooks container
// veths, so it can neither express a port allow-list nor see a VM's NIC.
func egressACL() incus.ACLConfig {
	allow := func(proto, port string) incus.ACLRule {
		return incus.ACLRule{
			Action:          "allow",
			Destination:     "",
			DestinationPort: port,
			Protocol:        proto,
			Description:     fmt.Sprintf("anon tier: %s/%s", proto, port),
		}
	}
	return incus.ACLConfig{
		Name:        EgressACLName,
		Description: "anonymous-box egress: DNS, HTTP, HTTPS only; everything else dropped by the NIC default",
		EgressRules: []incus.ACLRule{
			allow("udp", "53"),
			allow("tcp", "53"),
			allow("tcp", "80"),
			allow("tcp", "443"),
		},
	}
}

// nicACLKeys are the per-device keys that attach the ACL and make the
// NIC drop any egress the ACL does not allow. Dropped egress is logged so
// an abuse investigation has evidence (#2200).
func nicACLKeys() map[string]string {
	return map[string]string{
		"security.acls":                        EgressACLName,
		"security.acls.default.egress.action":  "drop",
		"security.acls.default.egress.logged":  "true",
		"security.acls.default.ingress.action": "allow",
	}
}

// applyEgressGuard makes the ACL exist, then attaches it to the box's NIC.
// Same shape as the core-infra guard's reconciler: an ACL that could not
// be written is never attached.
func (m *Manager) applyEgressGuard(boxName string) error {
	desired := egressACL()
	if _, err := m.acls.GetNetworkACL(desired.Name); err != nil {
		// Any read failure is treated as absent; a create against an ACL
		// that does exist fails loudly rather than silently reusing
		// yesterday's rules.
		if cerr := m.acls.CreateNetworkACL(desired); cerr != nil {
			return fmt.Errorf("create acl %s: %w", desired.Name, cerr)
		}
	} else if err := m.acls.UpdateNetworkACL(desired.Name, desired); err != nil {
		return fmt.Errorf("update acl %s: %w", desired.Name, err)
	}
	if err := m.acls.EnsureNICDevice(boxName, incus.NICDevice{Name: m.cfg.NICDevice, Network: m.cfg.Bridge}); err != nil {
		return fmt.Errorf("nic device: %w", err)
	}
	if err := m.acls.SetDeviceConfig(boxName, m.cfg.NICDevice, nicACLKeys()); err != nil {
		return fmt.Errorf("nic acl keys: %w", err)
	}
	return nil
}

// liftEgressGuard detaches the anon ACL from the box's NIC and clears the
// default-action keys so the NIC falls back to Incus's defaults (allow) —
// what a claimed box on the tenant's plan gets (#2199). Clearing a device
// key is setting it to "", which SetDeviceConfig merges like any other.
func (m *Manager) liftEgressGuard(boxName string) error {
	keys := map[string]string{}
	for k := range nicACLKeys() {
		keys[k] = ""
	}
	if err := m.acls.SetDeviceConfig(boxName, m.cfg.NICDevice, keys); err != nil {
		return fmt.Errorf("nic acl keys: %w", err)
	}
	return nil
}
