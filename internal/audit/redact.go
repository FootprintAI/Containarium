package audit

import (
	"regexp"
	"strings"
)

// Phase 4.4 — audit-log redaction policy (audit C-MED-5).
//
// The audit_logs.detail column is a free-text TEXT field. Today
// the HTTP audit middleware writes only `duration=...` there, but
// nothing prevents a future handler from logging a request body
// containing a secret, a token, a password, etc. — and once a
// secret lands in audit_logs it's hard to scrub (the table is
// often replicated off-host for compliance retention).
//
// The defense is layered:
//   1. NEVER write request bodies or response bodies to audit
//      detail. The middleware enforces this — see middleware.go.
//   2. NEVER write query strings; the middleware records only
//      r.URL.Path. (?token= and similar are already deprecated
//      by Phase 1.5, but the middleware is the belt-and-braces
//      check.)
//   3. Whatever else does end up in `detail`, run it through
//      Redact before storage so common sensitive patterns are
//      scrubbed.
//
// The redaction is deliberately conservative — false-positives
// (over-redaction) are fine in an audit trail; false-negatives
// (a leaked secret) aren't.

// sensitivePatterns each have a regex that matches a known
// sensitive shape and a replacement string. The replacement keeps
// enough of the shape to remain useful for incident investigation
// while removing the secret material.
var sensitivePatterns = []struct {
	pattern *regexp.Regexp
	replace string
}{
	// JWT shape: three base64url-segments separated by dots,
	// preceded by an optional "Bearer ".
	{
		pattern: regexp.MustCompile(`(?i)(?:bearer\s+)?eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`),
		replace: "[REDACTED-JWT]",
	},
	// `password=...` / `pass=...` until space or end of line.
	{
		pattern: regexp.MustCompile(`(?i)\b(password|passwd|pass|secret|api[_-]?key|access[_-]?token|refresh[_-]?token)\s*[=:]\s*\S+`),
		replace: "$1=[REDACTED]",
	},
	// AWS-style access key id (AKIA + 16 chars).
	{
		pattern: regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
		replace: "[REDACTED-AWS-AK]",
	},
	// SSH private-key block start. If a multi-line key got
	// flattened into detail, this neutralizes it.
	{
		pattern: regexp.MustCompile(`-----BEGIN [A-Z ]+PRIVATE KEY-----`),
		replace: "[REDACTED-PRIVATE-KEY]",
	},
	// PEM-style "PRIVATE KEY" anywhere — secondary catch for
	// non-standard headers that the previous pattern missed.
	{
		pattern: regexp.MustCompile(`(?i)private\s*key\s*[:=]\s*\S+`),
		replace: "private_key=[REDACTED]",
	},
}

// Redact scrubs common sensitive patterns from `s`. Returns the
// redacted form. Safe on empty input. The function is pure — no
// global state, no logging.
func Redact(s string) string {
	if s == "" {
		return s
	}
	out := s
	for _, p := range sensitivePatterns {
		out = p.pattern.ReplaceAllString(out, p.replace)
	}
	return out
}

// HasSensitive returns true if `s` looks like it contains a
// pattern Redact would scrub. Useful for tests and for asserting
// "the middleware never lets sensitive data flow through" in
// regression suites.
func HasSensitive(s string) bool {
	if s == "" {
		return false
	}
	for _, p := range sensitivePatterns {
		if p.pattern.MatchString(s) {
			return true
		}
	}
	return false
}

// TrimDetail enforces the upper-bound on audit detail length so
// a buggy handler that logs a 10MB request body can't bloat the
// audit table. The cap is generous (8 KiB) — anything realistic
// fits.
const MaxDetailLength = 8 * 1024

// SanitizeDetail combines Redact with a length cap; this is the
// canonical entry point for anything writing to audit_logs.detail.
func SanitizeDetail(s string) string {
	s = Redact(s)
	if len(s) > MaxDetailLength {
		s = s[:MaxDetailLength] + " [truncated]"
	}
	return strings.TrimSpace(s)
}
