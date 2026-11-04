package cmd

import (
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/coderun"
)

// #3529: a note from the start (a stale skill-set apply marker was cleared)
// reaches the person running `code run`, before the started line, and nothing
// extra is printed without one.
func TestReportCodeRunStarted_SurfacesTheWarning(t *testing.T) {
	var with, without strings.Builder
	reportCodeRunStarted(&with, &coderun.ProcessStartResult{Name: "r", PID: 7, Warning: "cleared a stale skill-set apply marker"}, "alice")
	reportCodeRunStarted(&without, &coderun.ProcessStartResult{Name: "r", PID: 7}, "alice")
	if got := with.String(); !strings.HasPrefix(got, "warning: cleared a stale skill-set apply marker\n") || !strings.Contains(got, `✓ started "r" (pid 7) on alice`) {
		t.Fatalf("output = %q", got)
	}
	if got := without.String(); strings.Contains(got, "warning:") || !strings.HasPrefix(got, "✓ started") {
		t.Fatalf("output without a warning = %q", got)
	}
}
