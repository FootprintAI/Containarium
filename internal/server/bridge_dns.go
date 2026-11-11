package server

import (
	"fmt"
	"log"
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

// bridgeDNSStore is the slice of the Incus client the upgrade cleanup needs.
type bridgeDNSStore interface {
	GetNetworkConfigValue(network, key string) (string, error)
	SetNetworkConfigValue(network, key, value string) error
}

// cleanupBridgeDNSRecord removes, once on upgrade, the bridge DNS record that
// earlier daemons wrote to the bridge's raw.dnsmasq (#2734, slice C of #2263).
// The kernel hairpin rule (#2732) replaced it. A host with no base domain,
// which includes a correctly brought-up BYOC backend, is left untouched and
// the bridge is not even read (decision Q36 on #2727). Writing only happens
// when there is something to remove, and an empty result unsets the key.
func cleanupBridgeDNSRecord(be bridgeDNSStore, bridge, baseDomain, sshHost string) error {
	if baseDomain == "" {
		return nil
	}
	current, err := be.GetNetworkConfigValue(bridge, "raw.dnsmasq")
	if err != nil {
		return fmt.Errorf("read %s raw.dnsmasq: %w", bridge, err)
	}
	stripped, changed := stripBridgeDNSRecord(current, baseDomain, sshHost)
	if !changed {
		return nil
	}
	if err := be.SetNetworkConfigValue(bridge, "raw.dnsmasq", stripped); err != nil {
		return fmt.Errorf("write %s raw.dnsmasq: %w", bridge, err)
	}
	if stripped == "" {
		log.Printf("[bridgedns] removed the old *.%s record from %s raw.dnsmasq (the key is now unset); boxes resolve the base domain upstream and reach this host's apps through the kernel hairpin rule", baseDomain, bridge)
	} else {
		log.Printf("[bridgedns] removed the old *.%s record from %s raw.dnsmasq; kept the other lines: %q", baseDomain, bridge, stripped)
	}
	return nil
}

// stripBridgeDNSRecord returns raw without the record earlier daemons wrote,
// and whether anything was removed. Per decision Q36 on #2727 it acts only
// when an `address=/<base-domain>/<ip>` line is present, and then removes that
// line plus every `server=/<h>/#` line whose h is the SSH host or a name at or
// under the base domain. Every other line is kept byte for byte, in order. A
// result that is only whitespace comes back as "", so the caller unsets the key.
func stripBridgeDNSRecord(raw, baseDomain, sshHost string) (string, bool) {
	base, ok := normalizeDNSHost(baseDomain)
	if !ok || raw == "" {
		return raw, false
	}
	ssh, _ := normalizeDNSHost(sshHost)
	lines := strings.Split(raw, "\n")
	hasRecord := false
	for _, l := range lines {
		if isBaseDomainAddressLine(l, base) {
			hasRecord = true
			break
		}
	}
	if !hasRecord {
		return raw, false
	}
	kept := make([]string, 0, len(lines))
	for _, l := range lines {
		if isBaseDomainAddressLine(l, base) {
			continue
		}
		if h, ok := carveoutHost(l); ok && (h == ssh || h == base || strings.HasSuffix(h, "."+base)) {
			continue
		}
		kept = append(kept, l)
	}
	out := strings.Join(kept, "\n")
	if strings.TrimSpace(out) == "" {
		out = ""
	}
	return out, true
}

// isBaseDomainAddressLine matches the daemon's `address=/<base>/<ip>` shape:
// exactly one domain, equal to base after normalization.
func isBaseDomainAddressLine(line, base string) bool {
	rest, ok := strings.CutPrefix(strings.TrimSpace(line), "address=/")
	if !ok {
		return false
	}
	domain, target, ok := strings.Cut(rest, "/")
	if !ok || strings.Contains(target, "/") {
		return false
	}
	n, ok := normalizeDNSHost(domain)
	return ok && n == base
}

// carveoutHost returns h for a `server=/<h>/#` line, the only carve-out shape
// the daemon wrote; a server line naming an upstream address is not one.
func carveoutHost(line string) (string, bool) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(line), "server=/")
	if !ok {
		return "", false
	}
	h, ok := strings.CutSuffix(rest, "/#")
	if !ok || strings.Contains(h, "/") {
		return "", false
	}
	return normalizeDNSHost(h)
}
