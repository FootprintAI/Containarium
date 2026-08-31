package threatdetect

import (
	"math"

	"github.com/footprintai/containarium/internal/netbpf"
)

// safeInt64 clamps a uint64 traffic counter (flow bytes/packets, deny
// counts) to int64 range rather than letting a value above 2^63 wrap to a
// negative evidence field (same guarded-clamp pattern as
// internal/sentinel/metricsexport.go's safeInt64 — duplicated locally, not
// exported, for the same reason protoName is above). Real flow counters are
// nowhere near this; the clamp exists so a wrap would be impossible rather
// than merely unlikely.
func safeInt64(v uint64) int64 {
	if v > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(v)
}

// protoName renders an IP protocol number as the lowercase string used
// throughout the evidence types (mirrors the equivalent unexported helper in
// internal/server/network_policy_enforcer.go — duplicated here rather than
// exported across the package boundary, since it's three lines and pulling
// internal/server into internal/threatdetect would invert the dependency
// direction the enforcer's SetFlowHook/SetDenyHook wiring already relies on).
func protoName(proto uint8) string {
	switch proto {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return ""
	}
}

// denyReasonName renders a DenyEvent.Reason as the short label an operator
// sees in a finding's evidence.
func denyReasonName(reason uint8) string {
	switch reason {
	case netbpf.DenyReasonVirtualPatch:
		return "virtual-patch"
	case netbpf.DenyReasonSignature:
		return "signature"
	default:
		return "policy"
	}
}
