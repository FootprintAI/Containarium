package agentbox

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// setProcessLogDirForTest points processLogDir at an isolated temp dir (A1
// in the design doc: tests must not touch the real /tmp/agent-box) and
// returns a restore func for the caller to defer.
func setProcessLogDirForTest(dir string) func() {
	prev := processLogDir
	processLogDir = dir
	return func() { processLogDir = prev }
}

func writeFileForTest(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}

func fileExistsForTest(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// ----- ResolveOutcome: pure, table-driven per the #1672 design doc's 5-row
// matrix (docs/architecture/remote-coding-agent.md, Part A). -----

func TestResolveOutcome(t *testing.T) {
	exitCode := 0
	cases := []struct {
		name    string
		record  RunRecord
		curBoot string
		alive   bool
		want    RunOutcome
	}{
		{
			name:    "boot matches, exit code set -> exited",
			record:  RunRecord{BootID: "boot-a", ExitCode: &exitCode},
			curBoot: "boot-a",
			alive:   true, // ExitCode set is authoritative regardless of alive
			want:    RunOutcomeExited,
		},
		{
			name:    "boot matches, exit code absent, alive -> running",
			record:  RunRecord{BootID: "boot-a"},
			curBoot: "boot-a",
			alive:   true,
			want:    RunOutcomeRunning,
		},
		{
			name:    "boot matches, exit code absent, not alive -> unknown",
			record:  RunRecord{BootID: "boot-a"},
			curBoot: "boot-a",
			alive:   false,
			want:    RunOutcomeUnknown,
		},
		{
			name:    "boot differs, exit code set -> exited",
			record:  RunRecord{BootID: "boot-old", ExitCode: &exitCode},
			curBoot: "boot-new",
			alive:   true,
			want:    RunOutcomeExited,
		},
		{
			name:    "boot differs, exit code absent -> unknown regardless of alive",
			record:  RunRecord{BootID: "boot-old"},
			curBoot: "boot-new",
			alive:   true, // must be ignored: a stale-boot PID can be reassigned
			want:    RunOutcomeUnknown,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ResolveOutcome(tc.record, tc.curBoot, func(int) bool { return tc.alive })
			if got != tc.want {
				t.Errorf("ResolveOutcome(...) = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestResolveOutcome_NeverCallsAliveWhenExitCodeSet(t *testing.T) {
	// A killed-box scenario: PID may have been reassigned by the kernel, so
	// isAlive must never even be consulted once ExitCode is authoritative.
	exitCode := 1
	record := RunRecord{BootID: "boot-a", ExitCode: &exitCode}
	called := false
	ResolveOutcome(record, "boot-a", func(int) bool { called = true; return true })
	if called {
		t.Error("alive() must not be called when ExitCode is already set")
	}
}

func TestResolveOutcome_NeverCallsAliveOnBootMismatch(t *testing.T) {
	// A2/boot-mismatch case: consulting liveness on a stale boot is exactly
	// the bug (PID reuse) this design exists to prevent.
	record := RunRecord{BootID: "boot-old"}
	called := false
	ResolveOutcome(record, "boot-new", func(int) bool { called = true; return true })
	if called {
		t.Error("alive() must not be called when the record's boot id differs from the current boot")
	}
}

// ----- writeRunRecord / readRunRecord: atomic round-trip -----

func TestWriteReadRunRecord_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	restore := setProcessLogDirForTest(dir)
	defer restore()

	started := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	record := RunRecord{
		Version:     RunRecordVersion,
		Name:        "my-run",
		PID:         12345,
		BootID:      "boot-a",
		Command:     "sleep 5",
		Cwd:         "/tmp",
		CaptureMode: CaptureCombined,
		LogPath:     filepath.Join(dir, "my-run.log"),
		StartedAt:   started,
	}
	if err := writeRunRecord(record); err != nil {
		t.Fatalf("writeRunRecord: %v", err)
	}

	got, found, err := readRunRecord("my-run")
	if err != nil {
		t.Fatalf("readRunRecord: %v", err)
	}
	if !found {
		t.Fatal("readRunRecord: found = false, want true")
	}
	if got.Name != record.Name || got.PID != record.PID || got.Command != record.Command {
		t.Errorf("readRunRecord = %+v, want %+v", got, record)
	}
	if !got.StartedAt.Equal(record.StartedAt) {
		t.Errorf("StartedAt = %v, want %v", got.StartedAt, record.StartedAt)
	}
	if got.ExitCode != nil {
		t.Errorf("ExitCode = %v, want nil (unreaped run)", *got.ExitCode)
	}
	if got.FinishedAt != nil {
		t.Errorf("FinishedAt = %v, want nil (unreaped run)", *got.FinishedAt)
	}
}

func TestReadRunRecord_MissingReturnsNotFound(t *testing.T) {
	dir := t.TempDir()
	restore := setProcessLogDirForTest(dir)
	defer restore()

	_, found, err := readRunRecord("does-not-exist")
	if err != nil {
		t.Fatalf("readRunRecord: unexpected error %v", err)
	}
	if found {
		t.Error("found = true for a record that was never written")
	}
}

// TestWriteRunRecord_ExitCodeZeroDistinctFromAbsent is the regression named
// directly in #1672's design doc: ExitCode/FinishedAt are pointers so a
// clean `exit 0` is never confused with "not yet reaped."
func TestWriteRunRecord_ExitCodeZeroDistinctFromAbsent(t *testing.T) {
	dir := t.TempDir()
	restore := setProcessLogDirForTest(dir)
	defer restore()

	zero := 0
	finishedAt := time.Now()
	record := RunRecord{
		Version:    RunRecordVersion,
		Name:       "clean-exit",
		PID:        999,
		BootID:     "boot-a",
		StartedAt:  time.Now(),
		ExitCode:   &zero,
		FinishedAt: &finishedAt,
	}
	if err := writeRunRecord(record); err != nil {
		t.Fatalf("writeRunRecord: %v", err)
	}
	got, found, err := readRunRecord("clean-exit")
	if err != nil || !found {
		t.Fatalf("readRunRecord: found=%v err=%v", found, err)
	}
	if got.ExitCode == nil {
		t.Fatal("ExitCode = nil, want a pointer to 0")
	}
	if *got.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", *got.ExitCode)
	}
	if got.FinishedAt == nil {
		t.Fatal("FinishedAt = nil, want set")
	}
}

func TestReadRunRecord_VersionMismatchIsRejectedCleanly(t *testing.T) {
	dir := t.TempDir()
	restore := setProcessLogDirForTest(dir)
	defer restore()

	future := RunRecord{Version: RunRecordVersion + 1, Name: "future-run", PID: 1, BootID: "boot-a", StartedAt: time.Now()}
	if err := writeRunRecord(future); err != nil {
		t.Fatalf("writeRunRecord: %v", err)
	}
	_, _, err := readRunRecord("future-run")
	if err == nil {
		t.Error("expected an error for a run record with an unsupported version")
	}
}

// ----- listRunRecords -----

func TestListRunRecords_SkipsRotatedFiles(t *testing.T) {
	dir := t.TempDir()
	restore := setProcessLogDirForTest(dir)
	defer restore()

	// An old run under the name "svc", rotated aside (as name reuse does).
	old := RunRecord{Version: RunRecordVersion, Name: "svc", PID: 2, BootID: "boot-a", StartedAt: time.Now().Add(-time.Hour)}
	if err := writeRunRecord(old); err != nil {
		t.Fatalf("setup writeRunRecord(old): %v", err)
	}
	if err := rotateFinishedRun(old); err != nil {
		t.Fatalf("setup rotateFinishedRun: %v", err)
	}

	// The current run reusing that same name.
	current := RunRecord{Version: RunRecordVersion, Name: "svc", PID: 1, BootID: "boot-a", StartedAt: time.Now()}
	if err := writeRunRecord(current); err != nil {
		t.Fatalf("writeRunRecord(current): %v", err)
	}

	records, err := listRunRecords()
	if err != nil {
		t.Fatalf("listRunRecords: %v", err)
	}
	if len(records) != 1 || records[0].Name != "svc" || records[0].PID != 1 {
		t.Errorf("listRunRecords = %+v, want exactly 1 current record named svc with pid 1", records)
	}
}

// ----- rotateFinishedRun -----

func TestRotateFinishedRun_MovesRecordAndLogAside(t *testing.T) {
	dir := t.TempDir()
	restore := setProcessLogDirForTest(dir)
	defer restore()

	started := time.Unix(1780000000, 0).UTC()
	record := RunRecord{
		Version:   RunRecordVersion,
		Name:      "old-run",
		PID:       42,
		BootID:    "boot-a",
		StartedAt: started,
		LogPath:   logPathForName("old-run"),
	}
	if err := writeRunRecord(record); err != nil {
		t.Fatalf("writeRunRecord: %v", err)
	}
	if err := writeFileForTest(record.LogPath, "old output"); err != nil {
		t.Fatalf("setup log: %v", err)
	}

	if err := rotateFinishedRun(record); err != nil {
		t.Fatalf("rotateFinishedRun: %v", err)
	}

	if _, found, _ := readRunRecord("old-run"); found {
		t.Error("old-run record should no longer be readable under its original name after rotation")
	}
	if fileExistsForTest(record.LogPath) {
		t.Error("old-run.log should have been renamed aside, not left in place")
	}

	rotatedRecordPath := filepath.Join(dir, "old-run.1780000000.json")
	if !fileExistsForTest(rotatedRecordPath) {
		t.Errorf("expected rotated record at %s", rotatedRecordPath)
	}
	rotatedLogPath := filepath.Join(dir, "old-run.1780000000.log")
	if !fileExistsForTest(rotatedLogPath) {
		t.Errorf("expected rotated log at %s", rotatedLogPath)
	}
}

// ----- parseCaptureMode / captureModeFromProto -----

func TestParseCaptureMode(t *testing.T) {
	cases := []struct {
		in      string
		want    CaptureMode
		wantErr bool
	}{
		{"", CaptureCombined, false},
		{"combined", CaptureCombined, false},
		{"framed", CaptureFramed, false},
		{"bogus", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := parseCaptureMode(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseCaptureMode(%q): expected an error", tc.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseCaptureMode(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("parseCaptureMode(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestCaptureModeFromProto(t *testing.T) {
	cases := []struct {
		in   pb.CaptureMode
		want CaptureMode
	}{
		{pb.CaptureMode_CAPTURE_MODE_UNSPECIFIED, CaptureCombined},
		{pb.CaptureMode_CAPTURE_MODE_COMBINED, CaptureCombined},
		{pb.CaptureMode_CAPTURE_MODE_FRAMED, CaptureFramed},
	}
	for _, tc := range cases {
		t.Run(tc.in.String(), func(t *testing.T) {
			if got := captureModeFromProto(tc.in); got != tc.want {
				t.Errorf("captureModeFromProto(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
