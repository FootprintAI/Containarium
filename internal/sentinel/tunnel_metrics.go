package sentinel

import (
	"bytes"
	"fmt"
)

// TunnelSessionStats is a point-in-time view of the tunnel sessions a
// sentinel holds, split by transport, plus the running count of cleartext
// sessions it has refused. Rendered on /metrics and /status so an operator
// can see when every peer has moved to the TLS transport.
type TunnelSessionStats struct {
	// TLS is the number of registered sessions carried over TLS.
	TLS int
	// Cleartext is the number of registered sessions carried in the clear.
	Cleartext int
	// CleartextRefused counts the cleartext sessions turned away since the
	// process started.
	CleartextRefused uint64
}

// renderTunnelMetrics builds the Prometheus exposition for the tunnel
// transport counters. Pure, so it is unit-testable without an HTTP round
// trip.
func renderTunnelMetrics(s TunnelSessionStats) string {
	var b bytes.Buffer
	fmt.Fprint(&b, "# HELP sentinel_tunnel_sessions_tls Registered tunnel sessions carried over TLS.\n")
	fmt.Fprint(&b, "# TYPE sentinel_tunnel_sessions_tls gauge\n")
	fmt.Fprintf(&b, "sentinel_tunnel_sessions_tls %d\n", s.TLS)
	fmt.Fprint(&b, "# HELP sentinel_tunnel_sessions_cleartext Registered tunnel sessions carried in the clear.\n")
	fmt.Fprint(&b, "# TYPE sentinel_tunnel_sessions_cleartext gauge\n")
	fmt.Fprintf(&b, "sentinel_tunnel_sessions_cleartext %d\n", s.Cleartext)
	fmt.Fprint(&b, "# HELP sentinel_tunnel_cleartext_refused_total Total cleartext tunnel sessions refused because TLS is required.\n")
	fmt.Fprint(&b, "# TYPE sentinel_tunnel_cleartext_refused_total counter\n")
	fmt.Fprintf(&b, "sentinel_tunnel_cleartext_refused_total %d\n", s.CleartextRefused)
	return b.String()
}
