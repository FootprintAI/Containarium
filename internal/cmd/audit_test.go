//go:build !containarium_client

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
		"plain text":       "plain text",
		"line\nbreak":      "line break",
		"carriage\rreturn": "carriage return",
		"with\ttabs":       "with tabs",
		"mix\n\tof\rwhite": "mix  of white",
		"":                 "",
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

// #1818 — `audit query --run-id` flag wiring. buildAuditQueryParams is the
// pure part of runAuditQuery's flag-to-filter translation, pulled out so
// this doesn't need a live Postgres connection to check.
func TestBuildAuditQueryParams_ThreadsRunID(t *testing.T) {
	params, err := buildAuditQueryParams("", "", "", "run-123", "", "", 50)
	if err != nil {
		t.Fatalf("buildAuditQueryParams: %v", err)
	}
	if params.RunID != "run-123" {
		t.Errorf("params.RunID = %q, want %q", params.RunID, "run-123")
	}
}

func TestBuildAuditQueryParams_ThreadsAllFilters(t *testing.T) {
	params, err := buildAuditQueryParams("alice", "container_create", "container", "run-123", "", "", 50)
	if err != nil {
		t.Fatalf("buildAuditQueryParams: %v", err)
	}
	if params.Username != "alice" || params.Action != "container_create" ||
		params.ResourceType != "container" || params.RunID != "run-123" || params.Limit != 50 {
		t.Errorf("params = %+v, want all five fields threaded through unchanged", params)
	}
}

func TestBuildAuditQueryParams_RejectsBadFrom(t *testing.T) {
	if _, err := buildAuditQueryParams("", "", "", "", "not-a-time", "", 50); err == nil {
		t.Error("expected an error for a non-RFC3339 --from value")
	}
}

func TestBuildAuditQueryParams_RejectsBadTo(t *testing.T) {
	if _, err := buildAuditQueryParams("", "", "", "", "", "not-a-time", 50); err == nil {
		t.Error("expected an error for a non-RFC3339 --to value")
	}
}

// TestAuditQueryFlags_RunIDIsRegisteredAndWired pins the user-facing
// --run-id flag itself (registered, empty default) and proves it actually
// reaches buildAuditQueryParams' RunID field the way runAuditQuery threads
// it — the tests above only ever exercised buildAuditQueryParams' own
// signature, never the flag name a real invocation types. Follows the
// flag-lookup precedent in pool_join_test.go's
// TestPoolJoinFlags_CloudControlPlaneIsOptOut and
// upgrade_watchdog_test.go's TestUpgradeWatchdogDefaultBinaryPath.
func TestAuditQueryFlags_RunIDIsRegisteredAndWired(t *testing.T) {
	f := auditQueryCmd.Flags().Lookup("run-id")
	if f == nil {
		t.Fatal("--run-id flag not registered on audit query")
	}
	if f.DefValue != "" {
		t.Errorf("--run-id default = %q, want empty (unset means no filter)", f.DefValue)
	}

	// Flags().Set mutates the package-level var directly and does not
	// restore itself; put it back so this test doesn't leak state into
	// whatever else in this package runs against the same *cobra.Command.
	t.Cleanup(func() {
		_ = auditQueryCmd.Flags().Set("run-id", "")
	})

	if err := auditQueryCmd.Flags().Set("run-id", "r-1"); err != nil {
		t.Fatalf("Set(run-id): %v", err)
	}
	params, err := buildAuditQueryParams(auditQueryUsername, auditQueryAction, auditQueryResource,
		auditQueryRunID, auditQueryFrom, auditQueryTo, auditQueryLimit)
	if err != nil {
		t.Fatalf("buildAuditQueryParams: %v", err)
	}
	if params.RunID != "r-1" {
		t.Errorf("params.RunID = %q, want %q after setting --run-id", params.RunID, "r-1")
	}
}
