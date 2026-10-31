package client

import "testing"

// The gateway renders the proto int64 count as a quoted decimal string, so a
// plain int64 field would fail `containarium token unscoped-report` the same
// way #3250 broke `containarium info`.
func TestGetUnscopedTokenReportDecodesQuotedInt64(t *testing.T) {
	rec, c := newBodyRecorder(t, `{"unscopedCallCount":"17","since":"2026-10-29T00:00:00Z","strictModeEnabled":true}`)

	report, err := c.GetUnscopedTokenReport()
	if err != nil {
		t.Fatalf("GetUnscopedTokenReport: %v", err)
	}
	if rec.path != "/v1/tokens/unscoped-report" {
		t.Errorf("path = %q, want /v1/tokens/unscoped-report", rec.path)
	}
	if report.UnscopedCallCount != 17 {
		t.Errorf("unscopedCallCount = %d, want 17", report.UnscopedCallCount)
	}
	if report.Since != "2026-10-29T00:00:00Z" || !report.StrictModeEnabled {
		t.Errorf("report = %+v", report)
	}
}
