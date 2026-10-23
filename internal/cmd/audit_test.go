//go:build !containarium_client

package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/audit"
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

// #2881 — verify-anchor against the bucket: flag/env resolution and the
// rendered ✓/⚠/✗ lines with their exit semantics.

func TestResolveAnchorBucket_FlagBeatsEnvAndEmptyMeansNoBucket(t *testing.T) {
	t.Setenv("CONTAINARIUM_AUDIT_ANCHOR_BUCKET", "gs://from-env")
	if got := resolveAnchorBucket("gs://from-flag"); got != "gs://from-flag" {
		t.Errorf("flag should win, got %q", got)
	}
	if got := resolveAnchorBucket(""); got != "gs://from-env" {
		t.Errorf("env should be the fallback, got %q", got)
	}
	t.Setenv("CONTAINARIUM_AUDIT_ANCHOR_BUCKET", "  ")
	if got := resolveAnchorBucket(""); got != "" {
		t.Errorf("blank env means no bucket, got %q", got)
	}
}

func TestPrintBucketAnchorReport(t *testing.T) {
	tests := []struct {
		name       string
		report     audit.BucketAnchorReport
		firstBad   int64
		wantErr    bool
		wantStdout []string
		wantStderr []string
	}{
		{
			name:       "clean",
			report:     audit.BucketAnchorReport{CheckedCheckpoints: 3, LatestCheckpoint: 30},
			wantStdout: []string{"✓", "3 checkpoint", "id=30"},
		},
		{
			name: "local newer than bucket warns and exits zero",
			report: audit.BucketAnchorReport{CheckedCheckpoints: 1, LatestCheckpoint: 10,
				Warnings: []audit.BucketAnchorFinding{{Kind: audit.FindingLocalNewerThanBucket, Checkpoint: 20, Detail: "ahead"}}},
			wantStdout: []string{"⚠", "ahead"},
		},
		{
			name: "planted checkpoint fails",
			report: audit.BucketAnchorReport{CheckedCheckpoints: 1, LatestCheckpoint: 10,
				Failures: []audit.BucketAnchorFinding{{Kind: audit.FindingAboveChainTip, Checkpoint: 9223372036854775807, Detail: "planted"}}},
			wantErr:    true,
			wantStderr: []string{"✗", "9223372036854775807", "planted"},
		},
		{
			name:       "tail break after the latest checkpoint fails",
			report:     audit.BucketAnchorReport{CheckedCheckpoints: 1, LatestCheckpoint: 10},
			firstBad:   12,
			wantErr:    true,
			wantStderr: []string{"✗", "id=12"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			err := printBucketAnchorReport(&out, &errOut, "gs://example-bucket/", tc.report, tc.firstBad)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			for _, w := range tc.wantStdout {
				if !strings.Contains(out.String(), w) {
					t.Errorf("stdout missing %q:\n%s", w, out.String())
				}
			}
			for _, w := range tc.wantStderr {
				if !strings.Contains(errOut.String(), w) {
					t.Errorf("stderr missing %q:\n%s", w, errOut.String())
				}
			}
			if tc.wantErr && strings.Contains(out.String(), "✓ Chain matches") {
				t.Errorf("a failing report must not print the success line:\n%s", out.String())
			}
		})
	}
}
