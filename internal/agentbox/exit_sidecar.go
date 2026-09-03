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

// wrapCommandWithExitSidecar returns a shell command that runs the caller's
// command and then durably records its exit status.
//
// Written temp-then-rename so a reader never observes a half-written status,
// matching writeRunRecordAt. The status is captured into $__cx immediately
// after the command so nothing between can clobber $?, and the wrapper exits
// with the original code so cmd.Wait() (when a reaper IS still alive) still
// sees the true status and the in-memory path is unchanged.
//
// The command runs in a SUBSHELL — "( … )", not "{ …; }". A command ending
// in `exit N` (or any `exit` on an error path) terminates the whole shell
// from inside a brace group, so the sidecar write is never reached and the
// bug this fixes reappears for exactly the commands most likely to report a
// meaningful status. A subshell confines that exit and hands $? back.
func wrapCommandWithExitSidecar(command, sidecar string) string {
	q := shellSingleQuote(sidecar)
	return fmt.Sprintf(
		"( %s\n); __cx=$?; printf '%%s %%s' \"$__cx\" \"$(date -u +%%s)\" > %s.tmp 2>/dev/null && mv -f %s.tmp %s 2>/dev/null; exit $__cx",
		command, q, q, q,
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
