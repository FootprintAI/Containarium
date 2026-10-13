package sentinel

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
)

// CertScope is the set of domains one backend is registered for. A
// backend's certificate sync may only supply certificates inside its scope.
//
// For a tunnel backend the scope is its primary registration (the public
// hostname, aliases and base domains declared in the tunnel handshake). For
// the in-fleet backend it is the --backend-hostname, --backend-alias and
// --backend-base-domain flags. A backend with an empty scope supplies no
// certificates.
type CertScope struct {
	Hostname    string
	Aliases     []string
	BaseDomains []string
}

// Empty reports whether the scope names no domain at all.
func (s CertScope) Empty() bool {
	return s.Hostname == "" && len(s.Aliases) == 0 && len(s.BaseDomains) == 0
}

// matchExact is the match strength of a certificate domain equal to the
// scope's hostname or one of its aliases. It is larger than any base-domain
// match, whose strength is the base domain's length (at most 253).
const matchExact = 1 << 16

// match reports how strongly domain (a certificate's domain, possibly a
// "*." wildcard) falls inside the scope: 0 when it is outside, matchExact
// for the hostname or an alias, and len(base) for a base domain — the base
// domain itself, its wildcard, or any name under it. When several base
// domains cover domain the longest one counts.
func (s CertScope) match(domain string) int {
	domain = strings.ToLower(domain)
	if domain == "" {
		return 0
	}
	if domain == s.Hostname {
		return matchExact
	}
	for _, a := range s.Aliases {
		if domain == a {
			return matchExact
		}
	}
	name := strings.TrimPrefix(domain, "*.")
	best := 0
	for _, bd := range s.BaseDomains {
		if bd == "" {
			continue
		}
		if (name == bd || strings.HasSuffix(name, "."+bd)) && len(bd) > best {
			best = len(bd)
		}
	}
	return best
}

// Validate checks every name in the scope is a lowercase DNS name with at
// least two labels and no wildcard. An empty scope is valid.
func (s CertScope) Validate() error {
	if s.Hostname != "" {
		if err := validateScopeName(s.Hostname); err != nil {
			return fmt.Errorf("hostname %q: %w", s.Hostname, err)
		}
	}
	for _, a := range s.Aliases {
		if err := validateScopeName(a); err != nil {
			return fmt.Errorf("alias %q: %w", a, err)
		}
	}
	for _, bd := range s.BaseDomains {
		if err := validateScopeName(bd); err != nil {
			return fmt.Errorf("base domain %q: %w", bd, err)
		}
	}
	return nil
}

func validateScopeName(name string) error {
	if name == "" {
		return fmt.Errorf("empty name")
	}
	if len(name) > 253 {
		return fmt.Errorf("longer than 253 characters")
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return fmt.Errorf("need at least two labels")
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return fmt.Errorf("each label must be 1-63 characters")
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return fmt.Errorf("label %q starts or ends with a hyphen", l)
		}
		for _, c := range l {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return fmt.Errorf("label %q: only lowercase letters, digits and hyphens are allowed", l)
			}
		}
	}
	return nil
}

// renderCertSyncMetrics builds the Prometheus exposition for certificates
// dropped by scope checks, one series per backend. Empty when nothing has
// been dropped.
func renderCertSyncMetrics(rejected map[string]uint64) string {
	if len(rejected) == 0 {
		return ""
	}
	ids := make([]string, 0, len(rejected))
	for id := range rejected {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var b bytes.Buffer
	fmt.Fprint(&b, "# HELP sentinel_cert_sync_rejected_total Certificates from a backend's /certs response that were dropped because they name a domain the backend is not registered for.\n")
	fmt.Fprint(&b, "# TYPE sentinel_cert_sync_rejected_total counter\n")
	for _, id := range ids {
		fmt.Fprintf(&b, "sentinel_cert_sync_rejected_total{backend=%q} %d\n", id, rejected[id])
	}
	return b.String()
}
