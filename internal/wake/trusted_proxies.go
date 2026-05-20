package wake

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// Phase 1.9 — trusted-proxy gate on the wake handler
// (audit A-MED-5).
//
// /wake/ and the root catch-all are intentionally outside the
// JWT auth middleware — Caddy forwards arbitrary user traffic
// to the wake handler when a container is in scale-to-zero
// state, and that traffic doesn't carry a daemon JWT.
//
// But "outside auth" means an attacker who can reach the
// daemon port directly (bypassing Caddy via a misrouted
// firewall, a leaked internal IP, an SSRF chain) can wake any
// container by crafting the Host header. The wake itself isn't
// directly destructive, but it triggers container starts that
// consume real CPU/disk/network — fine as a side effect of
// genuine user traffic, dangerous as a primitive an attacker
// can repeatedly invoke.
//
// The fix is a source-IP allowlist. The wake handler now
// accepts requests only from:
//   - loopback (127.0.0.0/8, ::1) — Caddy on the same host,
//     the production deployment shape
//   - any prefix in CONTAINARIUM_WAKE_TRUSTED_PROXIES — for
//     deployments where Caddy lives on a different VM
//
// An empty trust list with the env var unset preserves the
// pre-Phase-1.9 behavior with a startup WARNING — a backwards-
// compatible rollout step. Once operators have set the env
// var on every deployment that needs it, the warning branch
// can be removed.

const trustedProxiesEnv = "CONTAINARIUM_WAKE_TRUSTED_PROXIES"

// LoadTrustedProxies reads the env var, parses CIDR/IP entries,
// and returns the resulting prefix list. Empty list means
// "accept anything" (with a one-shot warning). Errors at parse
// time abort the load — better to log + return nil than to
// silently degrade.
func LoadTrustedProxies() ([]netip.Prefix, error) {
	raw := strings.TrimSpace(getEnv(trustedProxiesEnv))
	if raw == "" {
		log.Printf("WARNING: %s is unset — wake handler accepts requests from any source IP (audit A-MED-5)", trustedProxiesEnv)
		return nil, nil
	}
	var out []netip.Prefix
	for _, e := range strings.Split(raw, ",") {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		// Accept bare IPs as /32 (/128 for v6) for convenience.
		if !strings.Contains(e, "/") {
			addr, err := netip.ParseAddr(e)
			if err != nil {
				return nil, fmt.Errorf("invalid IP %q in %s: %w", e, trustedProxiesEnv, err)
			}
			out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(e)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q in %s: %w", e, trustedProxiesEnv, err)
		}
		if p.Bits() == 0 {
			return nil, fmt.Errorf("wildcard CIDR %q in %s would defeat the gate; refuse", e, trustedProxiesEnv)
		}
		out = append(out, p)
	}
	log.Printf("[wake] trusted proxies: %v", out)
	return out, nil
}

// isTrustedSource returns true if `r.RemoteAddr` is loopback or
// matches one of the configured trusted prefixes. When the
// allowlist is empty (env unset), returns true — backwards-
// compatible fail-open for the rollout window.
func isTrustedSource(r *http.Request, allowlist []netip.Prefix) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		// Unparseable RemoteAddr — fail closed.
		return false
	}
	if addr.IsLoopback() {
		return true
	}
	if len(allowlist) == 0 {
		return true // rollout-mode permissive default
	}
	for _, p := range allowlist {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// getEnv is overridable in tests; default reads from os.Getenv.
var getEnv = func(key string) string {
	// imported here so tests can swap it out without pulling
	// the os package into every callsite. The whole file uses
	// this single seam.
	return osGetenv(key)
}
