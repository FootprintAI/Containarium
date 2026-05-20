package server

import (
	"fmt"
	"net/netip"
	"strings"
)

// validateProxyProtocolTrusted refuses the daemon's --proxy-protocol
// flag setup when the trust list is empty or contains a wildcard.
// Audit finding C-MED-1.
//
// The L4 proxy layer (internal/app/l4_proxy.go) makes the same
// check lazily when Caddy is reconfigured. We replicate it at
// daemon startup so a misconfig fails visibly at boot instead of
// at first Caddy update — operators see the error in the boot
// log rather than in journalctl traces 30 minutes later.
func validateProxyProtocolTrusted(cidrs []string) error {
	if len(cidrs) == 0 {
		return fmt.Errorf("trust list is empty; --proxy-protocol requires at least one CIDR (typically the sentinel's VPC IP/32)")
	}
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			return fmt.Errorf("trust list contains an empty entry")
		}
		if c == "0.0.0.0/0" || c == "::/0" {
			return fmt.Errorf("trust list contains wildcard CIDR %q; refuse — anyone on the network could spoof X-Forwarded-For", c)
		}
		// Verify the entry parses as a real CIDR. Catches typos
		// like "10.0.0.0\8" (one backslash off) that would
		// silently treat the trust list as empty downstream.
		if _, err := netip.ParsePrefix(c); err != nil {
			return fmt.Errorf("trust list entry %q is not a valid CIDR: %w", c, err)
		}
	}
	return nil
}
