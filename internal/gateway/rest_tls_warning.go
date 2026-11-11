package gateway

import (
	"net"
	"strings"
)

// RESTTLSWarning returns the startup warning for a REST listener bound to
// addr, or "" when none is due (#3522). The listener serves plain HTTP, so a
// bind reachable from off the host needs a TLS terminator in front of it.
// terminatorDeclared is the daemon's --rest-tls-terminator: the operator's
// statement that one is there. A loopback bind never warns.
func RESTTLSWarning(addr string, terminatorDeclared bool) string {
	if terminatorDeclared || isLoopbackBind(addr) {
		return ""
	}
	return "Warning: the HTTP/REST listener on " + addr + " serves plain HTTP (no TLS) on a non-loopback address. " +
		"Put a TLS terminator (reverse proxy or load balancer) in front of it and start the daemon with " +
		"--rest-tls-terminator to declare it, or keep this port off untrusted networks"
}

// isLoopbackBind reports whether addr (host:port) binds only loopback. An
// empty or unspecified host binds every interface, so it is not loopback.
func isLoopbackBind(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
