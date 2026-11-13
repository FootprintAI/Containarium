package config

import "strings"

// Environment switches for the per-box outbound connection-rate cap (#3709).
// The cap limits how many NEW outbound TCP connections a box may open per
// second to a public address: a DDoS or scraping tool shows
// up as a burst of them, and no allow-list sees it. It is daemon-wide and off
// unless a positive rate is set. It needs the eBPF network-policy object.
const (
	// EnvEgressConnCapPerSec is the cap, in new connections per second per
	// box. Unset, zero, negative, non-numeric or above MaxEgressConnCapPerSec
	// means no cap.
	EnvEgressConnCapPerSec = "CONTAINARIUM_EGRESS_CONN_CAP_PER_SEC"
	// EnvEgressConnCapMode is "log_only" (the default: count and report, never
	// drop) or "enforce". Enforcement additionally needs the daemon-wide
	// network-policy enforce switch to be armed, as every other drop does.
	EnvEgressConnCapMode = "CONTAINARIUM_EGRESS_CONN_CAP_MODE"
)

// MaxEgressConnCapPerSec is the largest cap: the BPF config carries it in 16
// bits.
const MaxEgressConnCapPerSec = 65535

// EgressConnCap is the typed view of the cap switches.
type EgressConnCap struct {
	// PerSec is the cap; 0 means off.
	PerSec uint16
	// Enforce drops connections over the cap; false counts and reports them.
	Enforce bool
	// Ignored explains why a set EnvEgressConnCapPerSec was not used (not a
	// positive integer, or above MaxEgressConnCapPerSec), so the daemon can say
	// so at startup instead of leaving the operator to assume a cap is active.
	// Empty when the variable is unset or valid.
	Ignored string
}

// LoadEgressConnCap reads the cap switches once. Anything but a valid positive
// rate leaves the cap off, so a typo can never lower a box's limit to a
// surprising value, and an unrecognised mode is the safe log-only one.
func LoadEgressConnCap() EgressConnCap {
	raw := strings.TrimSpace(getString(EnvEgressConnCapPerSec, ""))
	n := getInt(EnvEgressConnCapPerSec, 0)
	if n <= 0 || n > MaxEgressConnCapPerSec {
		if raw != "" && raw != "0" {
			return EgressConnCap{Ignored: raw + " is not a rate between 1 and 65535"}
		}
		return EgressConnCap{}
	}
	return EgressConnCap{
		PerSec:  uint16(n), // #nosec G115 -- bounded above
		Enforce: strings.EqualFold(strings.TrimSpace(getString(EnvEgressConnCapMode, "")), "enforce"),
	}
}
