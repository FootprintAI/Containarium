package agentbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The regression: a run whose connection dropped before it finished
// reported "unknown" forever, because the only thing that wrote the exit
// status was a goroutine inside the agent-box that died with the
// connection. This asserts the CHILD records it instead.
func TestExitSidecar_ChildRecordsItsOwnExit_NoReaperInvolved(t *testing.T) {
	dir := t.TempDir()
	sidecar := exitSidecarPath(dir, "run-a")

	// Run the wrapped command to completion with NO Go-side reaper at all —
	// this is what a detached run looks like after agent-box has exited.
	wrapped := buildRunScript("echo hi; exit 7", sidecar, nil)
	cmd := exec.Command("/bin/sh", "-c", wrapped)
	cmd.Stdout, cmd.Stderr = nil, nil
	err := cmd.Run()

	// The wrapper must preserve the original exit code for any caller that
	// IS still waiting.
	var ee *exec.ExitError
	if err == nil {
		t.Fatal("want non-zero exit from the wrapper")
	} else if !asExitError(err, &ee) || ee.ExitCode() != 7 {
		t.Fatalf("wrapper changed the exit code: %v", err)
	}

	code, finishedAt, found := readExitSidecar(dir, "run-a")
	if !found {
		t.Fatal("no sidecar written — the detached-run case is still broken")
	}
	if code != 7 {
		t.Errorf("exit code = %d, want 7", code)
	}
	if finishedAt.IsZero() {
		t.Error("finishedAt not recorded")
	}
}

func asExitError(err error, target **exec.ExitError) bool {
	ee, ok := err.(*exec.ExitError)
	if ok {
		*target = ee
	}
	return ok
}

func TestApplyExitSidecar(t *testing.T) {
	seven := 7
	tests := []struct {
		name        string
		record      RunRecord
		sidecar     string // "" = none written
		wantCode    *int
		wantApplied bool
	}{
		{
			name:        "no outcome, sidecar present -> folded in",
			record:      RunRecord{Name: "r1"},
			sidecar:     "7 1788000000",
			wantApplied: true,
		},
		{
			name:    "no outcome, no sidecar -> stays unresolved",
			record:  RunRecord{Name: "r2"},
			sidecar: "",
		},
		{
			name:     "record already has an exit code -> reaper's value wins",
			record:   RunRecord{Name: "r3", ExitCode: &seven},
			sidecar:  "99 1788000000",
			wantCode: &seven,
		},
		{
			name:    "corrupt sidecar -> stays unresolved, never a wrong code",
			record:  RunRecord{Name: "r4"},
			sidecar: "not-a-number",
		},
		{
			name:    "empty sidecar -> stays unresolved",
			record:  RunRecord{Name: "r5"},
			sidecar: "",
		},
		{
			name:        "sidecar without a timestamp still yields the code",
			record:      RunRecord{Name: "r6"},
			sidecar:     "3",
			wantApplied: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if tt.sidecar != "" {
				if err := os.WriteFile(exitSidecarPath(dir, tt.record.Name), []byte(tt.sidecar), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			got := applyExitSidecar(dir, tt.record)

			switch {
			case tt.wantCode != nil:
				if got.ExitCode == nil || *got.ExitCode != *tt.wantCode {
					t.Fatalf("ExitCode = %v, want %d", got.ExitCode, *tt.wantCode)
				}
			case tt.wantApplied:
				if got.ExitCode == nil {
					t.Fatal("sidecar was not folded in")
				}
				if got.FinishedAt == nil {
					t.Error("FinishedAt not set alongside ExitCode")
				}
			default:
				if got.ExitCode != nil {
					t.Fatalf("ExitCode = %d, want nil (must stay unresolved)", *got.ExitCode)
				}
			}
		})
	}
}

// A run killed outright writes nothing — and must stay "unknown" rather
// than being reported as a clean exit. This is the distinction the design
// doc's row 3 asks for (an OOM must not look like exit 0).
func TestExitSidecar_KilledRunStaysUnknown(t *testing.T) {
	dir := t.TempDir()
	name := "killed"
	sidecar := exitSidecarPath(dir, name)

	cmd := exec.Command("/bin/sh", "-c", buildRunScript("sleep 30", sidecar, nil))
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	_ = cmd.Process.Kill()
	_ = cmd.Wait()

	if _, _, found := readExitSidecar(dir, name); found {
		t.Fatal("a SIGKILLed wrapper must leave no sidecar — otherwise an OOM reads as a clean exit")
	}
	rec := applyExitSidecar(dir, RunRecord{Name: name})
	if rec.ExitCode != nil {
		t.Fatalf("ExitCode = %d, want nil", *rec.ExitCode)
	}
	if got := ResolveOutcome(rec, bootID, func(int) bool { return false }); got != RunOutcomeUnknown {
		t.Errorf("outcome = %q, want %q", got, RunOutcomeUnknown)
	}
}

func TestBuildRunScript_QuotesThePath(t *testing.T) {
	dir := t.TempDir()
	// A directory with a single quote in it would break naive concatenation.
	odd := filepath.Join(dir, "it's a dir")
	if err := os.MkdirAll(odd, 0o700); err != nil {
		t.Fatal(err)
	}
	sidecar := exitSidecarPath(odd, "q")
	cmd := exec.Command("/bin/sh", "-c", buildRunScript("exit 4", sidecar, nil))
	_ = cmd.Run()

	code, _, found := readExitSidecar(odd, "q")
	if !found || code != 4 {
		t.Fatalf("sidecar in an awkward path: found=%v code=%d", found, code)
	}
}

func TestBuildRunScript_LeavesNoTempBehind(t *testing.T) {
	dir := t.TempDir()
	cmd := exec.Command("/bin/sh", "-c", buildRunScript("exit 0", exitSidecarPath(dir, "t"), nil))
	_ = cmd.Run()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("leftover temp file: %s", e.Name())
		}
	}
}
