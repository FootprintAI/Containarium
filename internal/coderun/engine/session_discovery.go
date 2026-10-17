package engine

import (
	"strconv"
	"strings"
)

// Session id discovery (#2193).
//
// `BoxRun.session_id` and `code run --session <id>` need a way to learn the
// id an engine assigned to a just-started run, so a LATER call can resume
// that exact conversation rather than "whatever this engine considers most
// recent". Neither engine's CLI prints its session id directly on a
// non-interactive run, so this reads it back from the file each engine
// writes its own session state to:
//
//   - Claude Code: the newest *.jsonl file under
//     ~/.claude/projects/<cwd-slug>/, where <cwd-slug> is the run's working
//     directory with every "/" replaced by "-". The file's basename (minus
//     ".jsonl") is the session id.
//   - pi: the newest file under ~/.pi/agent/sessions/; the file's own name
//     IS the session id (docs/integrations/pi.md:189-190 confirms pi takes a
//     native `--session <id>` flag to resume one).
//
// UNVERIFIED against a live, signed-in box for either engine — nothing in
// this repo's docs states the on-disk layout explicitly, and this change was
// developed without one. The decision to proceed on this assumption (rather
// than block the issue again) is recorded on #2193; the PR flags it again as
// the first thing to confirm once someone can test against a real
// installation, and to fix here if reality differs — this is the one place
// in the codebase that assumes it.
//
// The "replace / with -" slug rule is not a guess made up for this change:
// it is the same convention this very development environment's own
// scratchpad path uses for a project-scoped directory (observed directly,
// not from documentation), which is reassuring corroborating evidence for a
// convention Anthropic tooling uses elsewhere — but still not a substitute
// for testing it against Claude Code itself.

// A FRESH run adopts only a session file CREATED BY THAT RUN. Taking "the
// newest file" is wrong: the engine has not written its own file yet when
// discovery starts, so the newest file is the previous conversation (the
// member's own, or the previous run's), and a later --resume would then
// continue somebody else's conversation. So discovery works from a snapshot:
//
//  1. SessionDiscoveryPrepareCommand lists the session directory into a
//     snapshot file BEFORE the engine is launched.
//  2. SessionDiscoveryBackgroundCommand polls the directory and considers
//     only entries absent from that snapshot. Exactly one new entry is the
//     run's session. The poll runs the whole budget (it must not stop at the
//     first new entry: that may be a member's interactive session that began
//     before this run's engine wrote its own file) and writes the sidecar
//     only if exactly one new entry exists at the end. More than one new
//     entry means another conversation started meanwhile (a concurrent run or
//     a member's interactive session, in either order): which one is ours
//     cannot be told from the directory, so NOTHING is written. No new entry
//     within the budget also writes nothing. A --continue run gets no id
//     here at all: it appends to an existing file, which is never new. It never falls back to an older
//     file; an absent sidecar is the safe outcome.
//
// A snapshot (rather than "modified after a marker") is used because an
// older conversation that is still being appended to would pass a
// modification-time test.

// sessionDiscoveryAttempts * sessionDiscoveryIntervalMS bounds how long the
// background poll looks for the run's newly-created session file before
// giving up (60 x 200 ms = 12 s: the engine creates its transcript only after
// it has started and sent its first message, which is slower than a bare
// process spawn). Both paths that start a run (the CLI's SSH-driven `code
// run` and the daemon's StartBoxRun) run this as a DETACHED background job,
// never in the foreground, so the budget only delays when `session_id` first
// appears on `code runs`/`BoxRun`, never the run's own startup or output.
// A var only so tests can shorten it.
var sessionDiscoveryAttempts = 60

const sessionDiscoveryIntervalMS = 200

// ClaudeProjectSlug renders Claude Code's own project-directory name for cwd:
// every "/" replaced with "-". Exported so both the discovery script below
// and its tests share one definition.
func ClaudeProjectSlug(cwd string) string {
	return strings.ReplaceAll(cwd, "/", "-")
}

// sessionSearchDir names the directory an engine's newest file names the
// current session, and the suffix to strip from that file's name to get the
// session id. ok=false means this engine exposes no discoverable session id.
func sessionSearchDir(n Name, home, cwd string) (dir, trimSuffix string, ok bool) {
	switch n {
	case NameClaude:
		return home + "/.claude/projects/" + ClaudeProjectSlug(cwd), ".jsonl", true
	case NamePi:
		return home + "/.pi/agent/sessions", "", true
	default:
		return "", "", false
	}
}

// SessionSnapshotPath is where the pre-launch directory snapshot for the run
// whose session sidecar is sidecarPath lives.
func SessionSnapshotPath(sidecarPath string) string { return sidecarPath + ".snap" }

// SessionDiscoveryPrepareCommand renders a POSIX shell command that records
// which session entries already exist, to SessionSnapshotPath(sidecarPath).
// It MUST run before the engine is launched; entries that appear afterwards
// are the candidates for this run's session. ok=false means the engine
// exposes no discoverable session id.
func SessionDiscoveryPrepareCommand(n Name, home, cwd, sidecarPath string) (cmd string, ok bool) {
	dir, trimSuffix, ok := sessionSearchDir(n, home, cwd)
	if !ok {
		return "", false
	}
	snap := SessionSnapshotPath(sidecarPath)
	return "{ ls -1 " + shellQuoteSingle(dir) + " 2>/dev/null" + sessionEntryFilter(trimSuffix) + " || true; } > " +
		shellQuoteSingle(snap) + " 2>/dev/null || true", true
}

// sessionEntryFilter keeps only entries that are session files (Claude Code's
// project directory also holds per-session sub-directories).
func sessionEntryFilter(trimSuffix string) string {
	if trimSuffix == "" {
		return ""
	}
	return " | grep " + shellQuoteSingle(strings.ReplaceAll(trimSuffix, ".", "\\.")+"$")
}

// SessionDiscoveryBackgroundCommand renders a POSIX shell command that
// BACKGROUNDS (and detaches via setsid, so it outlives the exec call that
// launched it) a short poll loop: look for a session entry that is NOT in the
// snapshot SessionDiscoveryPrepareCommand took. It waits out the whole budget
// (or until the run's sibling <name>.exit sidecar exists), then, only if
// EXACTLY ONE new entry exists, writes its id to sidecarPath atomically
// (temp-then-rename). No new entry, or several (a member's session and this
// run's both appeared, in either order), writes nothing — an absent sidecar
// is a normal, expected outcome, never an error the caller needs to see.
// Plain-mode ids are best-effort: callers needing one reliably must use
// structured output.
//
// ok=false (empty command) means this engine exposes no discoverable session
// id at all; callers skip running anything.
func SessionDiscoveryBackgroundCommand(n Name, home, cwd, sidecarPath string) (cmd string, ok bool) {
	dir, trimSuffix, ok := sessionSearchDir(n, home, cwd)
	if !ok {
		return "", false
	}
	qdir := shellQuoteSingle(dir)
	qsidecar := shellQuoteSingle(sidecarPath)
	qtmp := shellQuoteSingle(sidecarPath + ".tmp")
	qsnap := shellQuoteSingle(SessionSnapshotPath(sidecarPath))
	qexit := shellQuoteSingle(strings.TrimSuffix(sidecarPath, ".session") + ".exit")

	// New entries = listing minus snapshot. An unreadable/absent snapshot
	// means we cannot tell old from new, so fail closed (write nothing).
	// basename then strips trimSuffix when the engine's file name carries one
	// (pi's own session file name already IS the id).
	// The loop does NOT stop at the first new entry: a member's own
	// interactive session (or any other process) may create a transcript
	// before this run's engine writes its own, and adopting the first one
	// would hand out somebody else's conversation. It runs the whole budget,
	// or until the run's exit sidecar exists, and only then requires EXACTLY
	// ONE new entry. Several (or none) writes nothing, in either ordering.
	body := "[ -f " + qsnap + " ] || exit 0; " +
		"i=0; while [ $i -lt " + strconv.Itoa(sessionDiscoveryAttempts) + " ] && [ ! -e " + qexit + " ]; do " +
		"sleep " + sleepArg() + "; i=$((i+1)); done; " +
		"new=$(ls -1 " + qdir + " 2>/dev/null" + sessionEntryFilter(trimSuffix) + " | grep -vxF -f " + qsnap + "); " +
		"[ -n \"$new\" ] || exit 0; " +
		"[ $(printf '%s\\n' \"$new\" | wc -l) -eq 1 ] || exit 0; " +
		"b=$(basename \"$new\"); id=\"${b%" + trimSuffix + "}\"; " +
		"printf '%s' \"$id\" > " + qtmp + " 2>/dev/null && mv -f " + qtmp + " " + qsidecar

	// setsid + redirected stdio + disown-by-construction: this must survive
	// the parent script (or SSH session, or exec call) returning, exactly
	// like spawnBackgroundProcess's own detached children.
	return "(setsid sh -c " + shellQuoteSingle(body) + " </dev/null >/dev/null 2>&1 &) 2>/dev/null || true", true
}

// sleepArg renders sessionDiscoveryIntervalMS as the fractional-second
// argument `sleep` takes (POSIX sleep on Linux boxes accepts sub-second
// values; GNU coreutils' sleep does).
func sleepArg() string {
	whole := sessionDiscoveryIntervalMS / 1000
	frac := sessionDiscoveryIntervalMS % 1000
	if frac == 0 {
		return strconv.Itoa(whole)
	}
	fracStr := strconv.Itoa(frac)
	for len(fracStr) < 3 {
		fracStr = "0" + fracStr
	}
	return strconv.Itoa(whole) + "." + fracStr
}
