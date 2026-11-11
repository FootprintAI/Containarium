package cmd

import (
	"context"
	"errors"
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

// fakeRunStarter stands in for the agent-box session a `code run` starts its
// run through.
type fakeRunStarter struct {
	result *coderun.ProcessStartResult
	err    error
	// got records the ProcessStart arguments.
	got []string
}

func (f *fakeRunStarter) ProcessStart(_ context.Context, name, command, cwd, captureMode string) (*coderun.ProcessStartResult, error) {
	f.got = []string{name, command, cwd, captureMode}
	return f.result, f.err
}

// #3540 (a surviving mutation of #3539): both `code run` paths (agent and
// --command) start their run through startCodeRun, so the start's warning is
// printed on every path: removing the report fails here, and a handler cannot
// get the started run without it.
func TestStartCodeRun_PrintsTheWarningBeforeTheStartedLine(t *testing.T) {
	starter := &fakeRunStarter{result: &coderun.ProcessStartResult{Name: "r", PID: 7, Warning: "cleared a stale skill-set apply marker"}}
	var diag strings.Builder
	started, err := startCodeRun(context.Background(), starter, &diag, "alice", "r", "cmd", "framed")
	if err != nil || started != starter.result {
		t.Fatalf("started = %v, err = %v", started, err)
	}
	if got := diag.String(); !strings.HasPrefix(got, "warning: cleared a stale skill-set apply marker\n✓ started \"r\" (pid 7) on alice\n") {
		t.Fatalf("output = %q", got)
	}
	if strings.Join(starter.got, "|") != "r|cmd||framed" {
		t.Fatalf("ProcessStart got %q", starter.got)
	}

	refused := &fakeRunStarter{err: errors.New("skill sets are being applied on this box")}
	diag.Reset()
	if _, err := startCodeRun(context.Background(), refused, &diag, "alice", "r", "cmd", ""); err == nil || diag.Len() != 0 {
		t.Fatalf("a refused start: err = %v, output = %q; want the error and nothing printed", err, diag.String())
	}
}
