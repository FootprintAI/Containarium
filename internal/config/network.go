package config

// CONTAINARIUM_NETWORK_* variable names — the single source of truth for the
// in-kernel network-policy (eBPF) namespace.
const (
	EnvNetworkPolicyBPFObject  = "CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT"
	EnvNetworkPolicyEnforce    = "CONTAINARIUM_NETWORK_POLICY_ENFORCE"
	EnvNetworkPolicySignatures = "CONTAINARIUM_NETWORK_POLICY_SIGNATURES"
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
}

// LoadNetwork reads the CONTAINARIUM_NETWORK_* namespace once. The two arming
// flags use the shared truthy convention (1/true/yes/on), matching the switch /
// envTruthy parsing they replace.
func LoadNetwork() Network {
	return Network{
		PolicyBPFObject:  getString(EnvNetworkPolicyBPFObject, ""),
		PolicyEnforce:    getBool(EnvNetworkPolicyEnforce),
		PolicySignatures: getBool(EnvNetworkPolicySignatures),
	}
}
