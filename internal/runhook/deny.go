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
	for _, seg := range c.Segments {
		if r, ok := denySegment(seg, 0); ok {
			return r, true
		}
	}
	return "", false
}

func anyGlob(patterns []string, w string) bool {
	for _, p := range patterns {
		if globMatch(p, w) {
			return true
		}
	}
	return false
}

func denySegment(words []string, depth int) (string, bool) {
	for i, w := range words {
		base := path.Base(w)
		for _, n := range NetworkClients {
			if base == n {
				return "network client " + n, true
			}
		}
		if base == "git" {
			if r, ok := denyGit(words[i+1:]); ok {
				return r, true
			}
		}
		if depth < maxNestedShell && strings.ContainsAny(w, " \t\n;&|`$()<>") {
			if inner, err := ParseCommand(w); err == nil {
				for _, s := range inner.Segments {
					if r, ok := denySegment(s, depth+1); ok {
						return r, true
					}
				}
			}
		}
	}
	return "", false
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
