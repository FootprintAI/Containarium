package config

// EnvThreatSentry is the opt-in flag for the continuous threat-detection
// background sentry (#1640) — off by default, consistent with the
// platform's other opt-in security features (network-policy enforce,
// signature scanning above).
const EnvThreatSentry = "CONTAINARIUM_THREAT_SENTRY"

// ThreatDetect is the typed view of the CONTAINARIUM_THREAT_* namespace.
type ThreatDetect struct {
	// SentryEnabled arms the background detection engine. Requires the eBPF
	// network-policy object loaded (CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT)
	// but NOT enforce mode — detection runs in observation mode.
	// (EnvThreatSentry)
	SentryEnabled bool
}

// LoadThreatDetect reads the CONTAINARIUM_THREAT_* namespace once, using the
// shared truthy convention (1/true/yes/on).
func LoadThreatDetect() ThreatDetect {
	return ThreatDetect{SentryEnabled: getBool(EnvThreatSentry)}
}
