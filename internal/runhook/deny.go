package runhook

import (
	"path"
	"strings"
)

// Hard denies: refused whatever the run's level or allowlist says. Matched
// fail-closed, like the level's own git deny rules: a harmless argument that
// happens to be one of these words is refused too.

// NetworkClients are executables whose purpose is outbound connections to a
// host named on their command line. Matched by base name anywhere in a
// command. (Package managers and git reach their registries and remotes; a
// network-level policy, not this list, governs those.)
var NetworkClients = []string{
	"curl", "wget", "nc", "ncat", "netcat", "socat", "telnet", "ftp", "lftp",
	"ssh", "scp", "sftp", "rsync", "aria2c", "http", "https", "xh",
}

// GitDeniedSubcommands may not appear anywhere after `git`: the platform, not
// the agent, publishes.
var GitDeniedSubcommands = []string{"push", "remote"}

// GitDeniedOptionsAnywhere make git run a program or load configuration chosen
// by the command line, wherever they appear.
var GitDeniedOptionsAnywhere = []string{"--exec-path*", "--upload-pack*", "--receive-pack*", "--config-env*"}

// GitDeniedGlobalOptions are refused between `git` and its subcommand.
var GitDeniedGlobalOptions = []string{"-c*"}

// gitCloneNoArgShorts are the short options of `git clone` that take no value;
// git lets them bundle in front of one that does (`-qu <cmd>`).
var gitCloneNoArgShorts = []string{"l", "s", "q", "v", "n", "4", "6"}

// GitTransportDenied are, per subcommand, the option words that make git run a
// program or load configuration chosen by the command line (#3397). Git
// accepts any unambiguous prefix of a long option, so the shortest forms are
// listed. The daemon's level deny rules are built from the same lists.
func GitTransportDenied() map[string][]string {
	clone := []string{"--u*", "-u*", "--receive-pack*", "--con*", "-c*", "--te*"}
	for _, l := range gitCloneNoArgShorts {
		clone = append(clone, "-"+l+"u*", "-"+l+"c*")
	}
	return map[string][]string{
		"fetch": {"--upload-pack*", "--upl*", "--receive-pack*", "--config*"},
		"clone": clone,
	}
}

// gitOptionsWithValue are git's global options whose value is the next word.
var gitOptionsWithValue = map[string]bool{"-C": true, "-c": true, "--git-dir": true, "--work-tree": true, "--namespace": true, "--config-env": true}

// maxNestedShell bounds how deep a quoted word is re-read as a command line
// (`sh -c 'git push'`).
const maxNestedShell = 3

// HardDeny reports the first hard deny c hits, with a short reason.
func HardDeny(c Command) (string, bool) {
	r, ok, _ := scanHardDeny(c)
	return r, ok
}

// scanState is one scan of a command for hard denies.
type scanState struct {
	reason string
	hit    bool
	// tooDeep is set when a quoted shell command is nested past maxNestedShell,
	// where the rescan stops: what is inside it was not read.
	tooDeep bool
}

// scanHardDeny reports the first hard deny c hits and whether a nested shell
// command went deeper than the rescan reads.
func scanHardDeny(c Command) (reason string, hit, tooDeep bool) {
	var st scanState
	denyCommand(c, 0, &st)
	return st.reason, st.hit, st.tooDeep
}

func denyCommand(c Command, depth int, st *scanState) bool {
	for _, w := range c.AssignWords {
		if denyAssignment(w, depth, st) {
			return true
		}
	}
	for _, seg := range c.Segments {
		if denySegment(seg, depth, st) {
			return true
		}
	}
	return false
}

// denyAssignment refuses any GIT_* assignment (GIT_SSH, GIT_SSH_COMMAND,
// GIT_CONFIG_*, GIT_EXEC_PATH, ... make git run a program or load
// configuration chosen by the caller) and scans every other value for a
// hard-denied command.
func denyAssignment(w string, depth int, st *scanState) bool {
	eq := strings.IndexByte(w, '=')
	name, val := w[:eq], w[eq+1:]
	if strings.HasPrefix(strings.ToUpper(name), "GIT_") {
		return st.deny("git environment assignment " + name)
	}
	return denySegment([]string{val}, depth, st)
}

func (st *scanState) deny(reason string) bool {
	st.reason, st.hit = reason, true
	return true
}

func anyGlob(patterns []string, w string) bool {
	for _, p := range patterns {
		if globMatch(p, w) {
			return true
		}
	}
	return false
}

// hasShellMeta reports whether a word may itself be a command line.
func hasShellMeta(w string) bool { return strings.ContainsAny(w, " \t\n;&|`$()<>") }

func denySegment(words []string, depth int, st *scanState) bool {
	for i, w := range words {
		if isAssignment(w) {
			if denyAssignment(w, depth, st) {
				return true
			}
			continue
		}
		base := path.Base(w)
		for _, n := range NetworkClients {
			if base == n {
				return st.deny("network client " + n)
			}
		}
		if base == "git" {
			if r, ok := denyGit(words[i+1:]); ok {
				return st.deny(r)
			}
		}
		if depth < maxNestedShell && hasShellMeta(w) {
			if inner, err := ParseCommand(w); err == nil {
				if denyCommand(inner, depth+1, st) {
					return true
				}
			}
		}
	}
	// At the last depth the rescan stops. A shell handed more text to run
	// there is a nest this scan did not read.
	if depth >= maxNestedShell && len(words) > 1 && isInterpreter(words[0]) {
		for _, w := range words[1:] {
			if hasShellMeta(w) {
				st.tooDeep = true
			}
		}
	}
	return false
}

func denyGit(rest []string) (string, bool) {
	for _, w := range rest {
		for _, s := range GitDeniedSubcommands {
			if w == s {
				return "git " + s, true
			}
		}
		if anyGlob(GitDeniedOptionsAnywhere, w) {
			return "git transport option " + w, true
		}
	}
	// The global options before the subcommand.
	i := 0
	for i < len(rest) && strings.HasPrefix(rest[i], "-") {
		if anyGlob(GitDeniedGlobalOptions, rest[i]) {
			return "git transport option " + rest[i], true
		}
		if gitOptionsWithValue[rest[i]] {
			i++
		}
		i++
	}
	if i >= len(rest) {
		return "", false
	}
	if denied, ok := GitTransportDenied()[rest[i]]; ok {
		for _, w := range rest[i+1:] {
			if anyGlob(denied, w) {
				return "git " + rest[i] + " transport option " + w, true
			}
		}
	}
	return "", false
}
