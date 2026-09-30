package server

import (
	"fmt"
	"strings"
)

// normalizeDNSHost lowercases h, trims surrounding spaces and one trailing dot,
// and reports whether the result is a syntactically valid DNS name. It is the
// gate between operator config and the generated dnsmasq file: anything it
// accepts contains only letters, digits, '-', '_' and '.', so it cannot smuggle
// a second directive (newline), a delimiter ('/') or a wildcard into
// raw.dnsmasq.
func normalizeDNSHost(h string) (string, bool) {
	h = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
	if h == "" || len(h) > 253 {
		return "", false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 {
			return "", false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			alnum := c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
			if !alnum && c != '-' && c != '_' {
				return "", false
			}
		}
	}
	return h, true
}

// validateDNSPassthroughHosts validates the daemon's --dns-passthrough-host
// flag (#2188). Empty = feature off; a blank or malformed entry is a typo and
// is refused at boot rather than silently dropped from the bridge DNS record.
func validateDNSPassthroughHosts(hosts []string) error {
	for _, h := range hosts {
		if strings.TrimSpace(h) == "" {
			return fmt.Errorf("--dns-passthrough-host contains an empty entry")
		}
		if _, ok := normalizeDNSHost(h); !ok {
			return fmt.Errorf("--dns-passthrough-host %q is not a valid hostname", h)
		}
	}
	return nil
}
