package agentbox

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Durable run records (#1672). agent-box is a stdio MCP server spawned per
// SSH connection: processRegistry is in-memory and dies with the
// connection, so a reconnected agent-box has no way to find a still-running
// process, and a process's exit status was discarded outright
// (cmd.Wait() -> _). A RunRecord persists a run's identity and outcome
// beside its log, so any later agent-box instance — not just the one that
// started the run — can answer "is it alive?" and "how did it end?".
//
// See docs/architecture/remote-coding-agent.md (Part A) for the full design.

// RunRecordVersion is bumped when the on-disk shape changes incompatibly.
// readRunRecord rejects a mismatched version rather than guessing at a
// partially-compatible parse.
const RunRecordVersion = 2

// runRecordMinReadableVersion is the oldest on-disk shape this binary can
// still read. v1 records predate the Actor/DelegationChain fields (#1699);
// they load with those fields empty and report as unattributed, which is
// correct — nothing recorded who started them. Rejecting them instead would
// discard the only evidence of runs that died unresolved, which is exactly
// the evidence #1672 exists to preserve.
const runRecordMinReadableVersion = 1

// RunOutcome classifies a run record against the current boot id and PID
// liveness. See ResolveOutcome.
type RunOutcome string

const (
	// RunOutcomeRunning: same boot, no recorded exit code, PID still alive.
	RunOutcomeRunning RunOutcome = "running"
	// RunOutcomeExited: ExitCode is set and authoritative, regardless of boot.
	RunOutcomeExited RunOutcome = "exited"
	// RunOutcomeUnknown: either the record predates a reboot (its PID may
	// have been reassigned by the kernel, so liveness can't be trusted), or
	// the process died between exiting and the reaper goroutine writing the
	// exit code. Never conflate with "exited" — an OOM'd or killed run must
	// stay distinguishable from a clean exit.
	RunOutcomeUnknown RunOutcome = "unknown"
)

// CaptureMode names how a run's output stream is written to its log file.
// CaptureCombined is plain text (the only mode before #1674, still the
// default): stdout and stderr interleaved as-is, readable with a plain
// `cat`/`tail`. CaptureFramed multiplexes them using internal/logframe, so
// a demuxing client (containarium code) can split them back apart from the
// single offset stream tail_log still serves unchanged.
type CaptureMode string

const (
	CaptureCombined CaptureMode = "combined"
	CaptureFramed   CaptureMode = "framed"
)

// parseCaptureMode maps process_start's optional capture_mode argument to
// the typed enum. Empty input defaults to CaptureCombined — process_start's
// contract for callers who never pass capture_mode at all (every caller
// before #1674) is that nothing about their invocation changes. Anything
// else that isn't a recognized value is a caller error (most likely a
// typo), not a silent fallback.
func parseCaptureMode(s string) (CaptureMode, error) {
	switch s {
	case "", string(CaptureCombined):
		return CaptureCombined, nil
	case string(CaptureFramed):
		return CaptureFramed, nil
	default:
		return "", fmt.Errorf("capture_mode: unknown value %q (want %q or %q)", s, CaptureCombined, CaptureFramed)
	}
}

// captureModeFromProto maps SpawnRequest.CaptureMode (the gRPC transport's
// typed enum) to this package's CaptureMode. CAPTURE_MODE_UNSPECIFIED maps
// to CaptureCombined — additive/backward-compatible, per the proto field's
// own doc comment: every SpawnRequest sent before #1674 omits the field
// and gets today's behavior unchanged.
func captureModeFromProto(m pb.CaptureMode) CaptureMode {
	if m == pb.CaptureMode_CAPTURE_MODE_FRAMED {
		return CaptureFramed
	}
	return CaptureCombined
}

// RunRecord is the durable, on-disk counterpart to managedProcess: written
// by the agent-box process that started a run, read by whichever agent-box
// process — possibly a different one, after a reconnect — later needs to
// know the run's identity or outcome.
type RunRecord struct {
	Version     int         `json:"version"`
	Name        string      `json:"name"`
	PID         int         `json:"pid"`
	BootID      string      `json:"boot_id"`
	Command     string      `json:"command"`
	Cwd         string      `json:"cwd"`
	CaptureMode CaptureMode `json:"capture_mode"`
	LogPath     string      `json:"log_path"`
	StartedAt   time.Time   `json:"started_at"`

	// Actor is the principal the caller says authorized this run, and
	// DelegationChain the JSON-serialized auth.Actor chain behind it
	// (#1699). Both are OPTIONAL and, on this transport, CALLER-ASSERTED:
	// agent-box has no authenticated context to derive them from — it is
	// reached over SSH (authenticated by the SSH session) or a unix socket
	// (by filesystem permissions), never with a JWT. So these carry the same
	// trust as the command string beside them: as much as you trust whoever
	// reached this box.
	//
	// That is deliberately weaker than the audit store's `actor` column
	// (#1678), which is resolved server-side from a verified delegation
	// claim. Do not treat the two as equivalent evidence: this one answers
	// "who does the client say started this?", not "who did the platform
	// verify started this?".
	Actor           string `json:"actor,omitempty"`
	DelegationChain string `json:"delegation_chain,omitempty"`

	// Written only by the reaper goroutine, at exit. Pointers on purpose:
	// absent != zero, so a run that hasn't been reaped (or died before the
	// reaper could write) is never confused with a clean `exit 0`.
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	ExitCode   *int       `json:"exit_code,omitempty"`
}

// bootID is /proc/sys/kernel/random/boot_id, read once at package init. A
// var, not a const, so tests can override it directly instead of faking
// /proc. Empty on platforms without it (e.g. non-Linux dev/test sandboxes);
// an empty current boot id can only equal an empty record boot id, which is
// the same "trust it" behavior every record written on such a platform
// already has, so no records are ever incorrectly downgraded to unknown by
// this fallback.
var bootID = readHostBootID()

func readHostBootID() string {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// ResolveOutcome classifies a run record's current state. Pure — no
// filesystem, no clock, no processes — so it is table-driven-testable with
// a stub alive func. See the design doc's 5-row matrix:
//
//	Boot ID   ExitCode  isAlive(PID)  Outcome
//	matches   set       —             exited
//	matches   absent    true          running
//	matches   absent    false         unknown  (A2: died before the reaper wrote)
//	differs   set       —             exited   (status was recorded pre-reboot; still true)
//	differs   absent    —             unknown  (PID belongs to another boot — never trust it)
func ResolveOutcome(record RunRecord, currentBoot string, alive func(pid int) bool) RunOutcome {
	if record.ExitCode != nil {
		return RunOutcomeExited
	}
	if record.BootID != currentBoot {
		return RunOutcomeUnknown
	}
	if alive(record.PID) {
		return RunOutcomeRunning
	}
	return RunOutcomeUnknown
}

// recordPathIn returns the on-disk path for name's current run record
// under dir.
func recordPathIn(dir, name string) string {
	return filepath.Join(dir, sanitizeName(name)+".json")
}

// recordPath returns the on-disk path for name's current run record under
// the CURRENT processLogDir.
func recordPath(name string) string {
	return recordPathIn(processLogDir, name)
}

// logPathIn returns the on-disk path for name's current log file under dir.
func logPathIn(dir, name string) string {
	return filepath.Join(dir, sanitizeName(name)+".log")
}

// logPathForName returns the on-disk path for name's current log file
// under the CURRENT processLogDir.
func logPathForName(name string) string {
	return logPathIn(processLogDir, name)
}

// writeRunRecord persists record beside its log, atomically, under the
// CURRENT processLogDir. Only safe to call synchronously from the goroutine
// handling an MCP/gRPC call (handleProcessStart's initial write, or any
// synchronous read-modify-write); see writeRunRecordAt for why the
// asynchronous reap goroutine must NOT use this.
func writeRunRecord(record RunRecord) error {
	return writeRunRecordAt(processLogDir, record)
}

// writeRunRecordAt persists record beside its log under dir, atomically: a
// reader never observes a half-written record even if agent-box is killed
// mid-write. Reuses the temp-then-rename pattern already idiomatic in this
// package (files.go's write_file handler): os.CreateTemp in the same
// directory, write, fsync, os.Rename (atomic within a directory).
//
// dir is an explicit parameter, not the processLogDir package var, because
// spawnBackgroundProcess's reap goroutine writes the final exit status
// asynchronously, at an unpredictable later time — process.go captures
// processLogDir into a local once, at spawn time, and threads it through
// here so that write always lands in the run's own directory, never
// whatever processLogDir happens to hold when the goroutine finally runs
// (a real hazard: in tests, a later test may have already repointed
// processLogDir at its own dir by then; in production processLogDir never
// changes after startup, but the read would still be an unsynchronized
// cross-goroutine access to a mutable package var).
func writeRunRecordAt(dir string, record RunRecord) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal run record %q: %w", record.Name, err)
	}

	tmp, err := os.CreateTemp(dir, ".agent-box.*.tmp")
	if err != nil {
		return fmt.Errorf("run record temp create: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("run record write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("run record fsync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("run record close: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		cleanup()
		return fmt.Errorf("run record chmod: %w", err)
	}
	if err := os.Rename(tmpPath, recordPathIn(dir, record.Name)); err != nil {
		cleanup()
		return fmt.Errorf("run record rename: %w", err)
	}
	return nil
}

// readRunRecord reads name's current run record. found is false (with a nil
// error) when no record exists yet — the normal case for a name that has
// never been used. A record whose Version doesn't match RunRecordVersion is
// rejected with an error rather than parsed partially/incorrectly.
func readRunRecord(name string) (record RunRecord, found bool, err error) {
	data, err := os.ReadFile(recordPath(name))
	if err != nil {
		if os.IsNotExist(err) {
			return RunRecord{}, false, nil
		}
		return RunRecord{}, false, fmt.Errorf("read run record %q: %w", name, err)
	}
	if err := json.Unmarshal(data, &record); err != nil {
		return RunRecord{}, false, fmt.Errorf("parse run record %q: %w", name, err)
	}
	// Accept a RANGE, not an exact match. A newer binary must still read
	// records an older one wrote, or a version bump silently orphans every
	// in-flight run at upgrade time.
	if record.Version < runRecordMinReadableVersion || record.Version > RunRecordVersion {
		return RunRecord{}, false, fmt.Errorf("run record %q: unsupported version %d (this agent-box reads %d-%d)",
			name, record.Version, runRecordMinReadableVersion, RunRecordVersion)
	}
	// Fold in the child-written exit sidecar (#1693) when the record itself
	// carries no outcome — the case for every run whose connection dropped
	// before it finished, since the in-process reaper died with it.
	return applyExitSidecar(processLogDir, record), true, nil
}

// rotatedRecordSuffix matches the ".<started-at-unix-seconds>.json" suffix
// rotateFinishedRun appends, so listRunRecords can tell a rotated-aside
// historical record apart from the current one for its name.
var rotatedRecordSuffix = regexp.MustCompile(`\.\d+\.json$`)

// listRunRecords returns every CURRENT run record in processLogDir — one
// per name, excluding records rotateFinishedRun has renamed aside. A
// record that fails to parse (malformed, or a version this binary doesn't
// support) is skipped rather than failing the whole listing: one bad file
// must not hide every other run.
func listRunRecords() ([]RunRecord, error) {
	entries, err := os.ReadDir(processLogDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", processLogDir, err)
	}

	records := make([]RunRecord, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".json") || rotatedRecordSuffix.MatchString(name) {
			continue
		}
		// #nosec G304 -- name is a directory-entry name from os.ReadDir(processLogDir)
		// itself, not caller-supplied input; it cannot contain a path separator, so
		// this join can't escape processLogDir.
		data, err := os.ReadFile(filepath.Join(processLogDir, name))
		if err != nil {
			continue // best-effort: a file removed mid-scan isn't fatal to the listing
		}
		var record RunRecord
		if err := json.Unmarshal(data, &record); err != nil ||
			record.Version < runRecordMinReadableVersion || record.Version > RunRecordVersion {
			continue // malformed or an incompatible version; skip rather than fail the whole list
		}
		// Same sidecar fold as readRunRecord (#1693): process_list is the
		// surface a reconnecting client actually calls, so a run that
		// finished while disconnected must report its exit code here too.
		records = append(records, applyExitSidecar(processLogDir, record))
	}
	return records, nil
}

// rotateFinishedRun renames record's on-disk record and log aside to
// "<name>.<started-at-unix-seconds>.{json,log}" so a fresh run reusing the
// same name never truncates the previous run's output. Missing files (the
// record already gone, or a run that never produced a log) are not errors —
// rotation's job is "don't destroy what's there," not "guarantee it exists."
func rotateFinishedRun(record RunRecord) error {
	suffix := fmt.Sprintf(".%d", record.StartedAt.UTC().Unix())

	oldRecordPath := recordPath(record.Name)
	newRecordPath := strings.TrimSuffix(oldRecordPath, ".json") + suffix + ".json"
	if err := os.Rename(oldRecordPath, newRecordPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("rotate run record %q: %w", record.Name, err)
	}

	oldLogPath := logPathForName(record.Name)
	newLogPath := strings.TrimSuffix(oldLogPath, ".log") + suffix + ".log"
	if err := os.Rename(oldLogPath, newLogPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("rotate log %q: %w", record.Name, err)
	}

	// The exit sidecar (#1693) rotates with its record. Leaving it in place
	// would let the NEXT run under this name inherit the previous run's exit
	// code the moment applyExitSidecar looks — reporting a still-running run
	// as long since finished.
	oldExitPath := exitSidecarPath(processLogDir, record.Name)
	newExitPath := strings.TrimSuffix(oldExitPath, ".exit") + suffix + ".exit"
	if err := os.Rename(oldExitPath, newExitPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("rotate exit sidecar %q: %w", record.Name, err)
	}
	return nil
}
