package server

import (
	"regexp"
	"strconv"
	"strings"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// The box's run wrapper records which tools were available to a run (#2954): a probe
// runs before the engine starts and again after it exits, inside the run's own shell,
// and both write one sidecar, <name>.tools. No model is involved, so the report costs
// no tokens and is written whatever the engine's exit status (a run that stops on its
// usage limit still reports). The daemon reads the sidecar when it lists runs.
//
// It says what was AVAILABLE on the run's PATH, never what was USED.

// boxRunToolSpec is one entry of the fixed allowlist: the only binaries the probe
// ever executes, each with the arguments that make it print its version. A binary a
// run drops somewhere unexpected is never run by the probe, and a sidecar naming a
// tool outside this table is ignored on read.
type boxRunToolSpec struct {
	Name string
	// VersionArgs are passed as separate words.
	VersionArgs []string
}

var boxRunToolAllowlist = []boxRunToolSpec{
	{"go", []string{"version"}},
	{"node", []string{"--version"}},
	{"npm", []string{"--version"}},
	{"pnpm", []string{"--version"}},
	{"yarn", []string{"--version"}},
	{"tsc", []string{"--version"}},
	{"python3", []string{"--version"}},
	{"pip3", []string{"--version"}},
	{"buf", []string{"--version"}},
	{"protoc", []string{"--version"}},
	{"staticcheck", []string{"-version"}},
	{"make", []string{"--version"}},
	{"git", []string{"--version"}},
	{"gcc", []string{"--version"}},
	{"rustc", []string{"--version"}},
	{"cargo", []string{"--version"}},
	{"java", []string{"-version"}},
	{"jq", []string{"--version"}},
	{"curl", []string{"--version"}},
}

const (
	// boxRunToolVersionMax caps a version string: the values end up in public pull requests.
	boxRunToolVersionMax = 64
	// boxRunToolsReadLimit caps how much of the sidecar the list script reads.
	boxRunToolsReadLimit = 8192
	// boxRunToolPhaseStart / End tag the lines of the two probes in the sidecar.
	boxRunToolPhaseStart = "S"
	boxRunToolPhaseEnd   = "E"
)

// The run wrapper measures in TWO phases, and only the second runs any tool:
//
//   - START (before the engine): for each allowlisted name that resolves on PATH, record an
//     opaque FINGERPRINT of the resolved binary (a checksum of its path, size and mtime).
//     Nothing is executed, so it takes milliseconds and cannot delay the run: a version
//     command can be slow (a package-manager shim may even try the network), and the engine
//     must not wait for it.
//   - END (after the engine exits, whatever its status): for each name that resolves, run its
//     own version command under a short timeout and a total budget, and record the version,
//     the location class and the same fingerprint.
//
// Provenance falls out of the two fingerprints: absent at the start is ADDED, the same
// fingerprint is PRESENT, a different one is CHANGED (replaced or upgraded in place).

// boxRunToolFingerprintFn defines __fp in the run's shell: prints the fingerprint of the
// binary at $1 as one opaque number. It never prints the path. It uses `stat -c` (GNU and
// busybox, i.e. every Linux box); where stat has no -c the size and mtime are empty and the
// fingerprint degrades to the path alone, so an in-place upgrade of the same path is then
// reported as present at the start rather than changed.
const boxRunToolFingerprintFn = `__fp() { printf '%s %s' "$1" "$(stat -c '%s %Y' "$1" 2>/dev/null)" | cksum | cut -d' ' -f1; }; `

// boxRunToolStartProbeFn defines __probe_start: one line "S<TAB>name<TAB>fingerprint" per
// allowlisted tool on PATH. It executes none of them.
func boxRunToolStartProbeFn() string {
	q := shellSingleQuote
	var b strings.Builder
	b.WriteString(boxRunToolFingerprintFn)
	b.WriteString("__probe_start() { ")
	for _, t := range boxRunToolAllowlist {
		b.WriteString("__p=$(command -v " + q(t.Name) + " 2>/dev/null) && printf 'S\\t%s\\t%s\\n' " + q(t.Name) + " \"$(__fp \"$__p\")\"; ")
	}
	b.WriteString("true; }")
	return b.String()
}

// boxRunToolEndProbeFn defines __probe_end. Called as `__probe_end <prefix>`, it prints one line
// "E<TAB>name<TAB>version<TAB>location<TAB>fingerprint" per allowlisted tool on PATH, in allowlist
// order. The version is the first line of the tool's own version command, reduced to printable
// characters, stripped of filesystem paths and capped. The version commands run IN PARALLEL, each
// under a short `timeout`, so the whole probe takes about as long as the slowest tool rather than
// the sum of all of them (the exit sidecar waits for it). If `timeout` does not exist no version
// command is run at all (versions are empty): nothing may hold a finished run open. Each tool
// writes its own line to <prefix>.<NN> and the lines are concatenated in order, then removed.
// Location is a class only: "home" for a binary under $HOME, otherwise "system", never a path.
func boxRunToolEndProbeFn() string {
	q := shellSingleQuote
	var b strings.Builder
	b.WriteString(boxRunToolFingerprintFn)
	b.WriteString("__to() { if command -v timeout >/dev/null 2>&1; then timeout 3 \"$@\"; else return 1; fi; }; ")
	b.WriteString("__probe_end() { __b=\"$1\"; __i=10; ")
	for _, t := range boxRunToolAllowlist {
		args := make([]string, 0, len(t.VersionArgs))
		for _, a := range t.VersionArgs {
			args = append(args, q(a))
		}
		b.WriteString("__p=$(command -v " + q(t.Name) + " 2>/dev/null) && { __i=$((__i+1)); ( " +
			"__v=$(__to " + q(t.Name) + " " + strings.Join(args, " ") + " </dev/null 2>&1 | head -n 1 | tr -cd '[:print:]' | sed -e 's# from /[^ ]*##' -e 's#^/[^ ]*##' -e 's# /[^ ]*##g' | cut -c1-" + strconv.Itoa(boxRunToolVersionMax) + "); " +
			"case \"$__p\" in \"$HOME\"/*) __l=home;; *) __l=system;; esac; " +
			"printf 'E\\t%s\\t%s\\t%s\\t%s\\n' " + q(t.Name) + " \"$__v\" \"$__l\" \"$(__fp \"$__p\")\" " +
			") > \"$__b.$__i\" 2>/dev/null & }; ")
	}
	b.WriteString("wait; cat \"$__b\".[0-9]* 2>/dev/null; rm -f \"$__b\".[0-9]* 2>/dev/null; true; }")
	return b.String()
}

// boxRunToolsPreProbe / PostProbe are the wrapper fragments: the first starts the sidecar's
// temp file with the instant START probe, the second appends the END probe and moves it into
// place atomically, so a reader never sees a half-written file.
func boxRunToolsPreProbe(tmpPath string) string {
	return boxRunToolStartProbeFn() + "; __probe_start > " + shellSingleQuote(tmpPath) + " 2>/dev/null; "
}

func boxRunToolsPostProbe(tmpPath, finalPath string) string {
	q := shellSingleQuote
	return boxRunToolEndProbeFn() + "; __probe_end " + q(tmpPath+".e") + " >> " + q(tmpPath) + " 2>/dev/null; mv -f " + q(tmpPath) + " " + q(finalPath) + " 2>/dev/null; "
}

type boxRunToolEnd struct {
	version     string
	location    pb.BoxRunToolLocation
	fingerprint string
}

// toolVersionPathFrom / toolVersionPath match filesystem paths a tool prints about itself. pip, for
// one, prints "pip 24.0 from /home/<user>/.local/lib/python3.12/site-packages/pip (python 3.12)": the
// value ends up in a public pull request, and a path can carry the box user's name.
var (
	toolVersionPathFrom = regexp.MustCompile(`\s+from\s+/\S*`)
	toolVersionPath     = regexp.MustCompile(`(^|\s)/\S*`)
	toolVersionSpaces   = regexp.MustCompile(`\s{2,}`)
)

// sanitizeToolVersion reduces a version string to printable ASCII, removes any filesystem path,
// and caps it: a second time on the daemon side, because the sidecar is a file the box's user can
// write.
func sanitizeToolVersion(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 && r < 0x7f {
			b.WriteRune(r)
		}
	}
	v := toolVersionPathFrom.ReplaceAllString(b.String(), "")
	v = toolVersionPath.ReplaceAllString(v, "$1")
	v = strings.TrimSpace(toolVersionSpaces.ReplaceAllString(v, " "))
	if len(v) > boxRunToolVersionMax {
		v = strings.TrimSpace(v[:boxRunToolVersionMax])
	}
	return v
}

func toolLocationFromWord(w string) pb.BoxRunToolLocation {
	switch w {
	case "home":
		return pb.BoxRunToolLocation_BOX_RUN_TOOL_LOCATION_HOME
	case "system":
		return pb.BoxRunToolLocation_BOX_RUN_TOOL_LOCATION_SYSTEM
	}
	return pb.BoxRunToolLocation_BOX_RUN_TOOL_LOCATION_UNSPECIFIED
}

// parseBoxRunTools turns a run's .tools sidecar into typed tools: the tools found by the END
// probe, each compared with the START probe by fingerprint. Anything outside the allowlist,
// malformed, or past the line cap is dropped; an unreadable sidecar yields no tools, never an
// error.
func parseBoxRunTools(data []byte) []*pb.BoxRunTool {
	start := map[string]string{}
	end := map[string]boxRunToolEnd{}
	lines := strings.Split(string(data), "\n")
	if len(lines) > 4*len(boxRunToolAllowlist) {
		lines = lines[:4*len(boxRunToolAllowlist)]
	}
	for _, line := range lines {
		f := strings.Split(line, "\t")
		switch {
		case len(f) == 3 && f[0] == boxRunToolPhaseStart:
			start[f[1]] = sanitizeFingerprint(f[2])
		case len(f) == 5 && f[0] == boxRunToolPhaseEnd:
			end[f[1]] = boxRunToolEnd{version: sanitizeToolVersion(f[2]), location: toolLocationFromWord(f[3]), fingerprint: sanitizeFingerprint(f[4])}
		}
	}
	// Iterating the ALLOWLIST (not the sidecar) is what enforces it: a name the box user wrote
	// into the file that is not in the table can never be emitted, and the order is stable.
	var out []*pb.BoxRunTool
	for _, t := range boxRunToolAllowlist {
		e, ok := end[t.Name]
		if !ok {
			continue
		}
		prov := pb.BoxRunToolProvenance_BOX_RUN_TOOL_PROVENANCE_ADDED_DURING_RUN
		if was, seen := start[t.Name]; seen {
			if was == e.fingerprint {
				prov = pb.BoxRunToolProvenance_BOX_RUN_TOOL_PROVENANCE_PRESENT_AT_START
			} else {
				prov = pb.BoxRunToolProvenance_BOX_RUN_TOOL_PROVENANCE_CHANGED_DURING_RUN
			}
		}
		out = append(out, &pb.BoxRunTool{Name: t.Name, Version: e.version, Provenance: prov, Location: e.location})
	}
	return out
}

// sanitizeFingerprint keeps only digits (the fingerprint is a checksum number), capped.
func sanitizeFingerprint(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' && b.Len() < 20 {
			b.WriteRune(r)
		}
	}
	return b.String()
}
