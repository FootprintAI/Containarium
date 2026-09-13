package server

import (
	"fmt"
	"net/netip"
	"strings"
)

// validateTrustedProxyCIDRs validates the daemon's --trusted-proxy-cidrs
// flag (#1829): the extra ranges appended to Caddy's trusted_proxies so a
// CDN-supplied client-IP header is honored only from the CDN's own networks.
//
// Unlike --proxy-protocol-trusted, an EMPTY list is valid — the feature is
// opt-in and off by default. Wildcards and malformed entries are refused at
// startup so a misconfig fails visibly at boot, matching
// validateProxyProtocolTrusted.
func validateTrustedProxyCIDRs(cidrs []string) error {
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			return fmt.Errorf("--trusted-proxy-cidrs contains an empty entry")
		}
		if c == "0.0.0.0/0" || c == "::/0" {
			return fmt.Errorf("--trusted-proxy-cidrs contains wildcard CIDR %q; refuse — every client could forge the client-IP header", c)
		}
		if _, err := netip.ParsePrefix(c); err != nil {
			return fmt.Errorf("--trusted-proxy-cidrs entry %q is not a valid CIDR: %w", c, err)
		}
	}
	return nil
}

// validateClientIPHeaders validates the daemon's --client-ip-header flag
// (#1829). Empty = feature off; any blank entry is a typo and is refused.
func validateClientIPHeaders(headers []string) error {
	for _, h := range headers {
		if strings.TrimSpace(h) == "" {
			return fmt.Errorf("--client-ip-header contains an empty entry")
		}
	}
	return nil
}
