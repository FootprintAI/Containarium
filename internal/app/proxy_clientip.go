package app

import (
	"fmt"
	"net/netip"
	"strings"
)

// ConfigureClientIP configures Caddy to derive the real client IP from a
// CDN / reverse-proxy header (e.g. Cf-Connecting-Ip) when the connection
// arrives from one of trustedCIDRs — typically the CDN's published ranges.
// Issue #1829.
//
// It sets the HTTP server's client_ip_headers and makes trusted_proxies the
// UNION of the PROXY-protocol trusted set (if EnableProxyProtocol ran, in
// either order) and trustedCIDRs. Caddy only honors client_ip_headers from a
// peer inside trusted_proxies, so the CDN ranges are what make the header
// trustworthy.
//
// It deliberately does NOT touch listener_wrappers: the proxy_protocol allow
// list stays the PROXY-sender set (the sentinel). A CDN never sends PROXY
// headers, and widening that allow list would let any CDN edge assert an
// arbitrary source via a forged PROXY header — trading a logging bug for a
// spoofing hole.
//
// Like EnableProxyProtocol it edits the server map in place and atomically
// POSTs /load, preserving listen/routes/automatic_https/etc. The settings are
// remembered so EnsureBaseConfig re-applies them after a stub-Caddyfile
// revert (#400) — the durability gap that motivated #1829.
func (p *ProxyManager) ConfigureClientIP(headers []string, trustedCIDRs []string) error {
	if len(headers) == 0 && len(trustedCIDRs) == 0 {
		return fmt.Errorf("ConfigureClientIP: nothing to configure (no client IP headers, no trusted CIDRs)")
	}
	for _, h := range headers {
		if strings.TrimSpace(h) == "" {
			return fmt.Errorf("ConfigureClientIP: client IP header list contains an empty entry")
		}
	}
	for _, c := range trustedCIDRs {
		c = strings.TrimSpace(c)
		if c == "" {
			return fmt.Errorf("ConfigureClientIP: trusted CIDR list contains an empty entry")
		}
		if c == "0.0.0.0/0" || c == "::/0" {
			return fmt.Errorf("ConfigureClientIP: refusing wildcard CIDR %q — trusting every source would let any client forge the client-IP header", c)
		}
		if _, err := netip.ParsePrefix(c); err != nil {
			return fmt.Errorf("ConfigureClientIP: trusted CIDR %q is not a valid CIDR: %w", c, err)
		}
	}

	config, err := p.getFullConfig()
	if err != nil {
		return fmt.Errorf("get full config: %w", err)
	}
	srv := getMapField(getMapField(getMapField(getMapField(config, "apps"), "http"), "servers"), p.serverName)
	if srv == nil {
		return fmt.Errorf("HTTP server %q missing from config", p.serverName)
	}

	applyClientIPTrust(srv, headers, trustedCIDRs, p.proxyProtocolTrusted)

	if err := p.loadConfig(config); err != nil {
		return fmt.Errorf("load config with client-IP trust: %w", err)
	}
	p.clientIPHeaders = append(p.clientIPHeaders[:0], headers...)
	p.trustedProxyCIDRs = append(p.trustedProxyCIDRs[:0], trustedCIDRs...)
	return nil
}

// applyClientIPTrust sets client_ip_headers (when any are configured) and
// trusted_proxies = union(proxyTrusted, extraTrusted) on the server map in
// place. Shared by ConfigureClientIP and EnableProxyProtocol so the two are
// order-independent and the self-heal path emits the same shape.
func applyClientIPTrust(srv map[string]interface{}, headers, extraTrusted, proxyTrusted []string) {
	if len(headers) > 0 {
		srv["client_ip_headers"] = toAnySlice(headers)
	}
	srv["trusted_proxies"] = map[string]interface{}{
		"source": "static",
		"ranges": toAnySlice(unionCIDRs(proxyTrusted, extraTrusted)),
	}
}

// unionCIDRs returns a followed by b, trimmed, with blanks and duplicates
// removed, preserving first-seen order.
func unionCIDRs(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, list := range [][]string{a, b} {
		for _, s := range list {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			if _, dup := seen[s]; dup {
				continue
			}
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}
