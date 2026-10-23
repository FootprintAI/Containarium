//go:build !containarium_client

package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
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

// --- verifyAnchorBucket glue (#2959 review) ------------------------------

// fakeAnchorChain is the database side: row hashes, plus a recording
// VerifyChainAgainstAnchor so a test can see which checkpoint the
// tail-consistency check was started from.
type fakeAnchorChain struct {
	maxID     int64
	hashes    map[int64]string
	firstBad  int64
	verifyErr error

	verifyCalls int
	sawCP       int64
	sawRoot     string
}

func (c *fakeAnchorChain) MaxRowID(context.Context) (int64, error) { return c.maxID, nil }

func (c *fakeAnchorChain) RowHashAt(_ context.Context, id int64) (string, bool, error) {
	h, ok := c.hashes[id]
	return h, ok, nil
}

func (c *fakeAnchorChain) VerifyChainAgainstAnchor(ctx context.Context, sink audit.RootSink) (audit.AnchorVerifyResult, error) {
	c.verifyCalls++
	if c.verifyErr != nil {
		return audit.AnchorVerifyResult{}, c.verifyErr
	}
	cp, root, ok, err := sink.LastPublished(ctx)
	if err != nil || !ok {
		return audit.AnchorVerifyResult{}, fmt.Errorf("sink had no anchor: ok=%v err=%v", ok, err)
	}
	c.sawCP, c.sawRoot = cp, root
	return audit.AnchorVerifyResult{Checkpoint: cp, AnchorRoot: root, CurrentRoot: c.hashes[cp], FirstBadAfterCheckpoint: c.firstBad}, nil
}

type fakeAnchorBucket struct {
	cps  []audit.BucketCheckpoint
	err  error
	lock audit.RetentionLockStatus
}

func (b *fakeAnchorBucket) URI() string { return "gs://example-bucket/" }
func (b *fakeAnchorBucket) ListCheckpoints(context.Context) ([]audit.BucketCheckpoint, []string, error) {
	return b.cps, nil, b.err
}
func (b *fakeAnchorBucket) CheckRetentionLock(context.Context) (audit.RetentionLockStatus, error) {
	return b.lock, nil
}

var lockedBucket = audit.RetentionLockStatus{HasPolicy: true, Locked: true, RetentionPeriod: "60"}

func newAnchorTestChain(maxID int64) *fakeAnchorChain {
	c := &fakeAnchorChain{maxID: maxID, hashes: map[int64]string{}}
	for id := int64(1); id <= maxID; id++ {
		c.hashes[id] = fmt.Sprintf("root-%d", id)
	}
	return c
}

func newAnchorTestFile(t *testing.T, checkpoints ...int64) *audit.FileSink {
	t.Helper()
	f, err := audit.NewFileSink(filepath.Join(t.TempDir(), "anchors.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, cp := range checkpoints {
		if err := f.PublishRoot(context.Background(), cp, fmt.Sprintf("root-%d", cp)); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func bucketAt(checkpoints ...int64) *fakeAnchorBucket {
	b := &fakeAnchorBucket{lock: lockedBucket}
	for _, cp := range checkpoints {
		b.cps = append(b.cps, audit.BucketCheckpoint{Checkpoint: cp, Root: fmt.Sprintf("root-%d", cp)})
	}
	return b
}

func TestVerifyAnchorBucket(t *testing.T) {
	tests := []struct {
		name         string
		chain        *fakeAnchorChain
		file         []int64
		bucket       *fakeAnchorBucket
		wantErr      string
		wantStdout   string
		wantStderr   string
		wantVerify   int
		wantTailCP   int64
		wantTailRoot string
	}{
		{
			name:  "clean: tail check starts from the latest checkpoint",
			chain: newAnchorTestChain(30), file: []int64{10, 20}, bucket: bucketAt(10, 20),
			wantStdout: "✓", wantVerify: 1, wantTailCP: 20, wantTailRoot: "root-20",
		},
		{
			name:  "tail check starts from a local-only checkpoint newer than the bucket",
			chain: newAnchorTestChain(30), file: []int64{10, 20}, bucket: bucketAt(10),
			wantStdout: "⚠", wantVerify: 1, wantTailCP: 20, wantTailRoot: "root-20",
		},
		{
			name:  "chain broken after the latest checkpoint",
			chain: func() *fakeAnchorChain { c := newAnchorTestChain(30); c.firstBad = 12; return c }(),
			file:  []int64{10}, bucket: bucketAt(10),
			wantErr: "failed", wantStderr: "id=12", wantVerify: 1, wantTailCP: 10, wantTailRoot: "root-10",
		},
		{
			name:  "rewritten local-only checkpoint fails even with an empty bucket",
			chain: func() *fakeAnchorChain { c := newAnchorTestChain(30); c.hashes[20] = "rewritten"; return c }(),
			file:  []int64{10, 20}, bucket: bucketAt(),
			wantErr: "failed", wantStderr: "checkpoint id=20", wantVerify: 1, wantTailCP: 20, wantTailRoot: "root-20",
		},
		{
			name:  "nothing verified, so no tail check is started",
			chain: newAnchorTestChain(5), file: []int64{50}, bucket: bucketAt(),
			wantErr: "failed", wantStderr: "checkpoint id=50", wantVerify: 0,
		},
		{
			name:  "no anchor anywhere is a warning, exit zero, no tail check",
			chain: newAnchorTestChain(30), file: nil, bucket: bucketAt(),
			wantStdout: "No anchor has been published yet", wantVerify: 0,
		},
		{
			name:  "bucket listing error is an error",
			chain: newAnchorTestChain(30), file: []int64{10}, bucket: &fakeAnchorBucket{err: errors.New("403 forbidden"), lock: lockedBucket},
			wantErr: "verify against anchor bucket", wantVerify: 0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			err := verifyAnchorBucket(context.Background(), tc.chain, newAnchorTestFile(t, tc.file...), "anchors.jsonl", tc.bucket, &out, &errOut)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
			}
			if tc.wantStdout != "" && !strings.Contains(out.String(), tc.wantStdout) {
				t.Errorf("stdout missing %q:\n%s", tc.wantStdout, out.String())
			}
			if tc.wantStderr != "" && !strings.Contains(errOut.String(), tc.wantStderr) {
				t.Errorf("stderr missing %q:\n%s", tc.wantStderr, errOut.String())
			}
			if tc.chain.verifyCalls != tc.wantVerify {
				t.Fatalf("tail checks started = %d, want %d", tc.chain.verifyCalls, tc.wantVerify)
			}
			if tc.chain.sawCP != tc.wantTailCP || tc.chain.sawRoot != tc.wantTailRoot {
				t.Errorf("tail check started from %d/%q, want %d/%q", tc.chain.sawCP, tc.chain.sawRoot, tc.wantTailCP, tc.wantTailRoot)
			}
		})
	}
}

func TestFixedRootSink(t *testing.T) {
	s := fixedRootSink{checkpoint: 7, root: "r7"}
	cp, root, ok, err := s.LastPublished(context.Background())
	if cp != 7 || root != "r7" || !ok || err != nil {
		t.Fatalf("LastPublished = %d %q %v %v", cp, root, ok, err)
	}
	if err := s.PublishRoot(context.Background(), 8, "r8"); err == nil {
		t.Fatal("a fixed view must refuse a publish")
	}
}

func TestRunAuditVerifyAnchorBucket_RejectsABadBucketURI(t *testing.T) {
	err := runAuditVerifyAnchorBucket(context.Background(), newAnchorTestChain(1), newAnchorTestFile(t), "anchors.jsonl", "s3://not-gcs")
	if err == nil || !strings.Contains(err.Error(), "open anchor bucket") {
		t.Fatalf("err = %v, want an 'open anchor bucket' error", err)
	}
}
