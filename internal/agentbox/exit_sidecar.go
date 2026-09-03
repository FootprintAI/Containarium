package agentbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Exit sidecar (#1693). The reap goroutine in spawnBackgroundProcess runs
// INSIDE agent-box, and agent-box is a stdio MCP server spawned per SSH
// connection — so when the connection drops, the reaper dies with it while
// the setsid'd child keeps running. Its exit status was then never written
// anywhere, and every detached run reported "unknown" forever: precisely
// the case #1672 exists for.
//
// The child outlives the connection, so the child records its own outcome.
// spawnBackgroundProcess wraps the command in a shell that writes its exit
// status to "<log-dir>/<name>.exit" on completion, and readRunRecord folds
// that sidecar into a record whose ExitCode is still nil.
//
// What deliberately still yields "unknown": a run whose wrapper shell was
// itself SIGKILLed, or a box that died mid-run. Nothing wrote a status
// because nothing survived to write one — and an OOM must stay
// distinguishable from a clean exit (design doc Part A, row 3).

// exitSidecarPath returns the sidecar path for a run in dir.
func exitSidecarPath(dir, name string) string {
	return filepath.Join(dir, sanitizeName(name)+".exit")
}

// framingSpec describes the child-side framing a run needs. nil means
// combined mode (the child writes the log file directly).
type framingSpec struct {
	agentBox string // absolute path to this agent-box binary
	logPath  string
	outFIFO  string
	errFIFO  string
}

// buildRunScript composes the shell program a spawned run actually executes:
// the caller's command, its exit status durably recorded (#1693), and — in
// framed mode — the framing done by child processes rather than by agent-box
// (#1701).
//
// The command runs in a SUBSHELL — "( … )", not "{ …; }". A command ending in
// `exit N` (or any `exit` on an error path) terminates the whole shell from
// inside a brace group, so the sidecar write is never reached and #1693
// reappears for exactly the commands most likely to report a meaningful
// status. A subshell confines that exit and hands $? back.
//
// $? is captured into $__cx on the line immediately after the command, before
// anything else — `wait` and the sidecar write both clobber it otherwise. The
// script exits with the original code, so a reaper that IS still alive sees
// the true status through cmd.Wait() and the in-memory path is unchanged.
//
// In framed mode the two framers are started BEFORE the command and read from
// FIFOs it writes to. Opening a FIFO blocks until both ends are open, so the
// readers must be running first. They are children of this shell, which
// spawnBackgroundProcess has already setsid'd, so nothing here depends on
// agent-box surviving — which was the whole defect.
func buildRunScript(command, sidecar string, f *framingSpec) string {
	qs := shellSingleQuote(sidecar)

	var prologue, redirect, drain string
	if f != nil {
		qo, qe := shellSingleQuote(f.outFIFO), shellSingleQuote(f.errFIFO)
		qb, ql := shellSingleQuote(f.agentBox), shellSingleQuote(f.logPath)
		prologue = fmt.Sprintf(
			"rm -f %s %s; mkfifo %s %s || exit 1\n"+
				"%s frame 1 %s < %s &\n"+
				"%s frame 2 %s < %s &\n",
			qo, qe, qo, qe, qb, ql, qo, qb, ql, qe)
		redirect = fmt.Sprintf(" > %s 2> %s", qo, qe)
		// Drain before recording the exit status: the sidecar's appearance is
		// what a reconnecting client reads as "finished", so the log must be
		// complete by then or a reader can see a finished run with output
		// still arriving.
		drain = fmt.Sprintf("wait; rm -f %s %s; ", qo, qe)
	}

	return fmt.Sprintf(
		"%s( %s\n)%s; __cx=$?; %sprintf '%%s %%s' \"$__cx\" \"$(date -u +%%s)\" > %s.tmp 2>/dev/null && mv -f %s.tmp %s 2>/dev/null; exit $__cx",
		prologue, command, redirect, drain, qs, qs, qs,
	)
}

// shellSingleQuote renders s as a single-quoted shell word, closing the
// quote around any embedded single quote. sanitizeName already constrains
// the name, but the log dir is configurable, so the path is quoted rather
// than assumed safe.
func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// readExitSidecar reads a sidecar written by the wrapper. Returns found=false
// when absent or unparseable — a corrupt sidecar must leave the run
// "unknown" rather than assert a wrong exit code.
func readExitSidecar(dir, name string) (code int, finishedAt time.Time, found bool) {
	data, err := os.ReadFile(exitSidecarPath(dir, name)) // #nosec G304 -- path built from sanitizeName + the configured log dir
	if err != nil {
		return 0, time.Time{}, false
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0, time.Time{}, false
	}
	code, err = strconv.Atoi(fields[0])
	if err != nil {
		return 0, time.Time{}, false
	}
	finishedAt = time.Now()
	if len(fields) > 1 {
		if secs, cerr := strconv.ParseInt(fields[1], 10, 64); cerr == nil {
			finishedAt = time.Unix(secs, 0).UTC()
		}
	}
	return code, finishedAt, true
}

// applyExitSidecar fills in ExitCode/FinishedAt from the sidecar when the
// record itself carries no outcome. A record that already has an ExitCode
// wins: the in-process reaper wrote it with cmd.ProcessState, which
// distinguishes a signaled exit that the shell's $? flattens.
func applyExitSidecar(dir string, record RunRecord) RunRecord {
	if record.ExitCode != nil {
		return record
	}
	code, finishedAt, found := readExitSidecar(dir, record.Name)
	if !found {
		return record
	}
	record.ExitCode = &code
	record.FinishedAt = &finishedAt
	return record
}
