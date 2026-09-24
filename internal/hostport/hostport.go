// Package hostport provides a single, permissive "host:port" splitter.
//
// Before this package existed, internal/cmd/egress_via_client.go,
// internal/sshconfig/generate.go, and
// internal/sentinel/sshsession/plugin.go each carried their own
// splitHostPort with a slightly different signature and fallback
// behavior — pure duplication with no behavioral reason for three copies
// (containarium#1980 PR review finding 5). This is the shared
// implementation all three now call.
package hostport

import (
	"net"
	"strconv"
	"strings"
)

// Split separates addr into a host and a port.
//
// addr may be a bare host ("example.com"), "host:port", or a bracketed
// IPv6 literal with or without a port ("[::1]:22", "[::1]"). Whenever addr
// doesn't carry an explicit, numeric port — no port at all, or a port that
// fails to parse as an integer — defaultPort is returned instead. Split
// never errors: an address it can't make sense of at all is returned
// verbatim as the host, alongside defaultPort. This covers every existing
// caller's need:
//   - sshconfig's Generate, building a Host block from an operator-supplied
//     "sentinel" address that may or may not include a port (default: 22).
//   - egress-via-client, extracting the port off its own freshly-listened
//     SOCKS address (always well-formed; default: 0, unused in practice).
//   - the sentinel session-record plugin, splitting a live connection's
//     RemoteAddr() (default: 0 — sshpiperd always supplies a port here,
//     so the fallback is never actually exercised).
func Split(addr string, defaultPort int) (host string, port int) {
	if h, p, err := net.SplitHostPort(addr); err == nil {
		if pi, err := strconv.Atoi(p); err == nil {
			return h, pi
		}
		return h, defaultPort
	}

	if strings.HasPrefix(addr, "[") && strings.HasSuffix(addr, "]") {
		return strings.TrimSuffix(strings.TrimPrefix(addr, "["), "]"), defaultPort
	}

	return addr, defaultPort
}
