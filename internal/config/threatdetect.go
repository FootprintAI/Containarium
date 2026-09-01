package config

import "time"

// EnvThreatSentry is the opt-in flag for the continuous threat-detection
// background sentry (#1640) — off by default, consistent with the
// platform's other opt-in security features (network-policy enforce,
// signature scanning above).
const EnvThreatSentry = "CONTAINARIUM_THREAT_SENTRY"

// EnvThreatDenyBurstN and EnvThreatDenyBurstWindowMinutes tune the
// deny-burst fence-probe rule (#1642): N deny events for one tenant within
// M minutes raises a MEDIUM finding. Operator-tunable without a daemon
// rebuild — set the env var and restart. Live tuning via an
// UpdateThreatRuleConfig RPC without a restart is #1643's scope.
const (
	EnvThreatDenyBurstN             = "CONTAINARIUM_THREAT_DENY_BURST_N"
	EnvThreatDenyBurstWindowMinutes = "CONTAINARIUM_THREAT_DENY_BURST_WINDOW_MINUTES"
)

// ThreatDetect is the typed view of the CONTAINARIUM_THREAT_* namespace.
type ThreatDetect struct {
	// SentryEnabled arms the background detection engine. Requires the eBPF
	// network-policy object loaded (CONTAINARIUM_NETWORK_POLICY_BPF_OBJECT)
	// but NOT enforce mode — detection runs in observation mode.
	// (EnvThreatSentry)
	SentryEnabled bool
	// DenyBurstN and DenyBurstWindow are the deny-burst rule's threshold and
	// sliding window. Zero/unset falls back to the rule's own defaults (see
	// threatdetect.DefaultDenyBurstN/Window) — this struct only carries an
	// override when the operator actually set one.
	DenyBurstN      int
	DenyBurstWindow time.Duration
}

// LoadThreatDetect reads the CONTAINARIUM_THREAT_* namespace once, using the
// shared truthy convention (1/true/yes/on) for the enable flag.
func LoadThreatDetect() ThreatDetect {
	return ThreatDetect{
		SentryEnabled:   getBool(EnvThreatSentry),
		DenyBurstN:      getInt(EnvThreatDenyBurstN, 0),
		DenyBurstWindow: time.Duration(getInt(EnvThreatDenyBurstWindowMinutes, 0)) * time.Minute,
	}
}
