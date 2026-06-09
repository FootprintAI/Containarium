// Package reqrate computes per-container HTTP request rates from the Caddy
// edge's structured (JSON) access log — the source for #231's request-rate
// plane. See docs/REQUEST-RATE-PLANE-DESIGN.md.
//
// The package is the offline, unit-tested building block (slice 1): it parses
// access-log lines, accumulates per-host counts over an interval, and joins
// hosts to containers using the route table + container list the collector
// already holds. The live tailer + collector wiring (which turn this into
// emitted metrics) are later slices; nothing here reads a file or talks to
// Caddy, so all of it is testable without a running edge.
package reqrate

import (
	"encoding/json"
	"net"
	"strings"
)

// accessEntry is the subset of a Caddy JSON access-log record we need. Caddy
// writes one such object per handled request when the server has a `logs`
// configuration with the json encoder. Fields we don't use are ignored by the
// decoder.
type accessEntry struct {
	Request struct {
		Host string `json:"host"`
	} `json:"request"`
}

// ParseHost extracts the (lower-cased, port-stripped) request host from one
// JSON access-log line. It returns ("", false) for lines that don't decode as
// JSON, that aren't access records (e.g. Caddy's own startup/info lines if they
// share the file), or that carry no host — callers skip those rather than
// counting them.
func ParseHost(line []byte) (string, bool) {
	var e accessEntry
	if err := json.Unmarshal(line, &e); err != nil {
		return "", false
	}
	return normalizeHost(e.Request.Host)
}

// normalizeHost lower-cases the host and strips an optional :port suffix
// (clients may send Host with a port). Returns ok=false for an empty host.
func normalizeHost(h string) (string, bool) {
	if h == "" {
		return "", false
	}
	// SplitHostPort only succeeds when a port is actually present; otherwise
	// keep the host as-is (it has no port to strip).
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.ToLower(strings.TrimSpace(h))
	if h == "" {
		return "", false
	}
	return h, true
}
