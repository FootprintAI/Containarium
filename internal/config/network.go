package config

// CONTAINARIUM_NETWORK_* variable names — the single source of truth for the
// in-kernel network-policy (eBPF) namespace.
const (
	EnvNetworkPolicyBPFObject  = "CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT"
	EnvNetworkPolicyEnforce    = "CONTAINARIUM_NETWORK_POLICY_ENFORCE"
	EnvNetworkPolicySignatures = "CONTAINARIUM_NETWORK_POLICY_SIGNATURES"
	// EnvCoreGuard arms the core-infra network guard: Incus NIC ACLs that
	// keep tenant containers off the platform's core-role containers
	// (docs/architecture/core-infra-network-guard.md). "enforce" attaches
	// them; anything else is off.
	EnvCoreGuard = "CONTAINARIUM_CORE_GUARD"
	// EnvTenantGuard arms the tenant network guard: Incus NIC ACLs that keep
	// one tenant's containers off another tenant's containers
	// (docs/architecture/tenant-network-guard.md). Unset is enforce; only
	// "off" disables (nicguard.ParseMode).
	EnvTenantGuard = "CONTAINARIUM_TENANT_GUARD"
)

// Network is the typed view of the CONTAINARIUM_NETWORK_* namespace — the eBPF
// network-policy enforcer's startup wiring. Both arming flags are off unless
// explicitly set, matching the deny→audit (observation-only) default posture.
type Network struct {
	// PolicyBPFObject is the path to the loaded in-kernel network-policy program
	// object. Empty disables the enforcer entirely. Kept as the raw value;
	// consumers TrimSpace where they need to. (EnvNetworkPolicyBPFObject)
	PolicyBPFObject string

	// PolicyEnforce arms packet drops (the second opt-in). Off = observation-only:
	// even a stored enforce-mode policy only audits would-deny flows.
	// (EnvNetworkPolicyEnforce)
	PolicyEnforce bool

	// PolicySignatures arms inbound cleartext exploit-signature scanning (Tier 2,
	// #661) — separate from PolicyEnforce. (EnvNetworkPolicySignatures)
	PolicySignatures bool

	// CoreGuard is the raw CONTAINARIUM_CORE_GUARD value. Parsed by
	// nicguard.ParseMode: unset is enforce, only "off" disables.
	CoreGuard string

	// TenantGuard is the raw CONTAINARIUM_TENANT_GUARD value, parsed the
	// same way. (EnvTenantGuard)
	TenantGuard string
}

// LoadNetwork reads the CONTAINARIUM_NETWORK_* namespace once. The two arming
// flags use the shared truthy convention (1/true/yes/on), matching the switch /
// envTruthy parsing they replace.
func LoadNetwork() Network {
	return Network{
		PolicyBPFObject:  getString(EnvNetworkPolicyBPFObject, ""),
		PolicyEnforce:    getBool(EnvNetworkPolicyEnforce),
		PolicySignatures: getBool(EnvNetworkPolicySignatures),
		CoreGuard:        getString(EnvCoreGuard, ""),
		TenantGuard:      getString(EnvTenantGuard, ""),
	}
}
