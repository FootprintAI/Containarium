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

// sessionDiscoveryAttempts * sessionDiscoveryIntervalMS bounds how long the
// background poll looks for a newly-created session file before giving up.
// Both paths that start a run (the CLI's SSH-driven `code run` and the
// daemon's StartBoxRun) run this as a DETACHED background job, never in the
// foreground — so this budget only delays when `session_id` first appears on
// `code runs`/`BoxRun`, never the run's own startup or output.
const (
	sessionDiscoveryAttempts   = 20
	sessionDiscoveryIntervalMS = 200
)

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

// SessionDiscoveryBackgroundCommand renders a POSIX shell command that
// BACKGROUNDS (and detaches via setsid, so it outlives the exec call that
// launched it) a short poll loop: look for the newest file under the
// engine's session directory, and once one appears, write its id to
// sidecarPath atomically (temp-then-rename, the same pattern
// internal/agentbox's exit sidecar uses) and stop. Gives up silently after
// sessionDiscoveryAttempts tries — an absent sidecar is a normal, expected
// outcome (a run whose engine exposes no session, or one discovery simply
// didn't win the race for), never an error the caller needs to see.
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

	// `ls -t` newest-first; `head -1` the newest. basename then strips
	// trimSuffix (e.g. ".jsonl") when the engine's file name carries one —
	// pi's own session file name already IS the id, so trimSuffix is empty
	// there and the parameter expansion is a no-op.
	body := "i=0; while [ $i -lt " + strconv.Itoa(sessionDiscoveryAttempts) + " ]; do " +
		"f=$(ls -t " + qdir + " 2>/dev/null | head -1); " +
		"if [ -n \"$f\" ]; then " +
		"b=$(basename \"$f\"); id=\"${b%" + trimSuffix + "}\"; " +
		"printf '%s' \"$id\" > " + qtmp + " 2>/dev/null && mv -f " + qtmp + " " + qsidecar + "; " +
		"break; fi; " +
		"i=$((i+1)); sleep " + sleepArg() + "; done"

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
