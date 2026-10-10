//go:build !windows && !containarium_client

package cmd

import (
	"fmt"
	"log"
	"net"

	"github.com/footprintai/containarium/internal/sentinel"
)

// applyTunnelAPIBindAddr validates --tunnel-api-bind-addr (a bare IP, no
// port) and installs it on ts. ts is left unchanged on error.
func applyTunnelAPIBindAddr(ts *sentinel.TunnelServer, addr string) error {
	ip := net.ParseIP(addr)
	if ip == nil {
		return fmt.Errorf("--tunnel-api-bind-addr %q: want an IP address with no port", addr)
	}
	ts.APIBindAddr = addr
	if !ip.IsLoopback() {
		log.Printf("[sentinel] per-backend tunnel API ports bind to %s (--tunnel-api-bind-addr)", addr)
	}
	return nil
}
