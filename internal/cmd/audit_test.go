package cmd

import (
	"strings"
	"testing"
)

// Phase 4.5 follow-up — unit-level checks on the pure-Go
// helpers exposed by audit.go. The Postgres-touching paths
// (openAuditStore, runAuditQuery, runAuditVerify) need a
// live DB; those are covered by the integration smoke in
// the operator runbook.

func TestSanitizeDetailForCLI_NormalizesWhitespace(t *testing.T) {
	cases := map[string]string{
		"plain text":         "plain text",
		"line\nbreak":        "line break",
		"carriage\rreturn":   "carriage return",
		"with\ttabs":         "with tabs",
		"mix\n\tof\rwhite":   "mix  of white",
		"":                   "",
	}
	for in, want := range cases {
		if got := sanitizeDetailForCLI(in); got != want {
			t.Errorf("sanitizeDetailForCLI(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestSanitizeDetailForCLI_LeavesPrintableUntouched(t *testing.T) {
	// The redactor at insert time scrubs secrets — at
	// display time we must not be tempted to "also" redact
	// or escape. The only job here is putting each row on
	// one terminal line.
	in := `{"user":"alice","ip":"10.0.0.1","msg":"approved"}`
	if got := sanitizeDetailForCLI(in); got != in {
		t.Errorf("sanitizeDetailForCLI mutated printable text: %q -> %q", in, got)
	}
}

func TestTruncateAudit_ShorterThanLimit(t *testing.T) {
	if got := truncateAudit("hello", 10); got != "hello" {
		t.Errorf("truncateAudit short-string = %q", got)
	}
}

func TestTruncateAudit_ExactLimit(t *testing.T) {
	if got := truncateAudit("hello", 5); got != "hello" {
		t.Errorf("truncateAudit exact-len = %q", got)
	}
}

func TestTruncateAudit_LongerThanLimit(t *testing.T) {
	got := truncateAudit("hello world", 8)
	if !strings.HasSuffix(got, "…") {
		t.Errorf("expected ellipsis terminator, got %q", got)
	}
	// Visual length on a fixed-width terminal: n-1 chars +
	// the ellipsis glyph. The byte length is larger because
	// the ellipsis is multibyte UTF-8, but that's fine —
	// table layout is sized by visible rune count.
	runes := []rune(got)
	if len(runes) != 8 {
		t.Errorf("truncateAudit rune count = %d; want 8 (%q)", len(runes), got)
	}
}

func TestTruncateAudit_TinyLimitBypass(t *testing.T) {
	// The ellipsis is wider than a 3-char budget allows;
	// fall back to a raw slice rather than producing
	// nonsense like "h…".
	got := truncateAudit("hello", 3)
	if got != "hel" {
		t.Errorf("truncateAudit n=3 = %q; want %q", got, "hel")
	}
}
