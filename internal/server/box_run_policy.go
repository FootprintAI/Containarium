package server

import (
	"fmt"
	"strings"

	"github.com/footprintai/containarium/internal/toolaccess"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// What an unprivileged platform-started run may do, per recorded tool-access
// level (#2944, slice 2). It is expressed as flags on the run command itself:
// the daemon builds that command as root, so the agent cannot change its own
// flags, and `--restricted` makes the agent CLI ignore every settings file except
// `--settings` and managed ones, so neither the run user's home nor the cloned
// repository can add allow rules or hooks of its own. Nothing is written to
// /etc and nothing the box owner sees (their own sessions) is affected.
//
// The flags are specific to the Claude Code CLI; any other engine is refused
// rather than started without a policy.

// boxRunSkillFetchTool is the agent CLI's permission name for the one tool of the
// box's skills MCP server a skill-aware run is told to call. Read-only.
const boxRunSkillFetchTool = "mcp__containarium-skills__get_skill_content"

// boxRunPolicy is the command-line policy for one level.
type boxRunPolicy struct {
	// Tools are the built-in tools the run may use at all (--tools).
	Tools []string
	// Allowed are the permission rules that need no approval (--allowedTools).
	Allowed []string
	// Denied are rules that refuse a command even when an Allowed rule matches
	// (--disallowedTools).
	Denied []string
}

// bashRules spells each command prefix both bare and with arguments, because
// the CLI matches `Bash(git status)` and `Bash(git status *)` separately.
func bashRules(prefixes ...string) []string {
	rules := make([]string, 0, 2*len(prefixes))
	for _, p := range prefixes {
		rules = append(rules, "Bash("+p+")", "Bash("+p+" *)")
	}
	return rules
}

// boxRunGitSubcommands are the git subcommands every level may run, deliberately
// WITHOUT push or remote, so the platform, not the agent, publishes.
var boxRunGitSubcommands = []string{
	"clone", "fetch", "checkout", "switch", "branch", "add", "commit",
	"status", "diff", "log", "show", "rev-parse", "ls-files",
}

// boxRunGitLeadOptions are the global options an allowed git command may start
// with (#3385): `-C <dir>`, `--git-dir=`, `--work-tree=`. They only choose which
// repository the same subcommand runs in. `-c` (runs arbitrary commands through
// config), `--exec-path` and the like are not here.
var boxRunGitLeadOptions = []string{"-C", "--git-dir=", "--work-tree="}

// boxRunGitOptionRules allows each allowed subcommand after a leading global
// option. The CLI's `*` also matches spaces, so these rules alone would match
// `git -C x push status`, `git -C x -c k=v fetch` and the like; boxRunGitDenyRules
// closes that, and deny wins over allow.
func boxRunGitOptionRules() []string {
	var prefixes []string
	for _, opt := range boxRunGitLeadOptions {
		for _, sub := range boxRunGitSubcommands {
			prefixes = append(prefixes, "git "+opt+"* "+sub)
		}
	}
	return bashRules(prefixes...)
}

// boxRunGitDenyRules refuses the dangerous words anywhere after a leading
// global option. Fail-closed by design: a harmless argument that happens to be
// one of these words (`git -C x log --grep push`) is refused too.
func boxRunGitDenyRules() []string {
	var prefixes []string
	for _, opt := range boxRunGitLeadOptions {
		for _, w := range []string{"push", "remote", "-c", "--exec-path*", "--upload-pack*", "--receive-pack*", "--config-env*"} {
			prefixes = append(prefixes, "git "+opt+"* "+w)
		}
	}
	return bashRules(prefixes...)
}

// The base every level gets: the file tools, git (by subcommand), a few
// read-only shell words, and the skills fetch tool. This is the same set the box
// bootstrap writes for today's runs, plus the option-led git forms.
var boxRunBaseAllowed = append(append(append([]string{"Read", "Edit", "Write", "Glob", "Grep"},
	bashRules(gitRulePrefixes()...)...),
	bashRules("ls", "pwd", "cd", "mkdir", "command -v")...),
	append(boxRunGitOptionRules(), boxRunSkillFetchTool)...)

func gitRulePrefixes() []string {
	out := make([]string, 0, len(boxRunGitSubcommands))
	for _, s := range boxRunGitSubcommands {
		out = append(out, "git "+s)
	}
	return out
}

// BUILD_TOOLS adds the build and test toolchains. Building and testing run code
// the repository provides; that is the consent the level records.
var boxRunBuildToolRules = bashRules(
	"go build", "go test", "go vet", "go mod", "go fmt", "gofmt",
	"make",
	"npm ci", "npm install", "npm run", "npm test",
	"pnpm install", "pnpm run", "pnpm test",
	"buf lint", "buf build", "buf generate", "buf format",
	"protoc", "staticcheck",
)

// FULL_SUDO adds sudo. The flags are then advisory: the run user also gets a
// passwordless sudoers rule, so it can step around any rule written here.
var boxRunSudoRules = bashRules("sudo")

var boxRunTools = []string{"Bash", "Read", "Edit", "Write", "Glob", "Grep"}

// boxRunPolicyFor maps a recorded level (the stored string) to its policy. An
// unknown or empty level is an error, never a default: a run must not start under
// a policy nobody chose.
func boxRunPolicyFor(level string) (boxRunPolicy, error) {
	allowed := append([]string(nil), boxRunBaseAllowed...)
	switch toolaccess.FromConfig(level) {
	case pb.BoxToolAccess_BOX_TOOL_ACCESS_NONE:
	case pb.BoxToolAccess_BOX_TOOL_ACCESS_BUILD_TOOLS:
		allowed = append(allowed, boxRunBuildToolRules...)
	case pb.BoxToolAccess_BOX_TOOL_ACCESS_FULL_SUDO:
		allowed = append(append(allowed, boxRunBuildToolRules...), boxRunSudoRules...)
	default:
		return boxRunPolicy{}, fmt.Errorf("no policy for tool-access level %q", level)
	}
	return boxRunPolicy{Tools: append([]string(nil), boxRunTools...), Allowed: allowed, Denied: boxRunGitDenyRules()}, nil
}

// commandFlags renders the policy as flags to append to the run command. Every
// value is single-quoted; --disallowedTools and --allowedTools are variadic, so
// they come last, allowed last of all.
func (p boxRunPolicy) commandFlags() string {
	q := shellSingleQuote
	var b strings.Builder
	b.WriteString(" --restricted --tools " + q(strings.Join(p.Tools, ",")))
	if len(p.Denied) > 0 {
		b.WriteString(" --disallowedTools")
		for _, r := range p.Denied {
			b.WriteString(" " + q(r))
		}
	}
	b.WriteString(" --allowedTools")
	for _, r := range p.Allowed {
		b.WriteString(" " + q(r))
	}
	return b.String()
}

// boxRunSudoersScript is run as root before each unprivileged run: it grants the
// run user passwordless sudo for FULL_SUDO and removes any such grant for every
// other level, so lowering the level takes effect on the next run. The rule is
// validated with visudo before it is installed; a box without sudo cannot honour
// FULL_SUDO, and the run is refused instead of starting without it.
func boxRunSudoersScript(level string) string {
	const file = "/etc/sudoers.d/90-" + boxRunUnprivilegedUser
	if toolaccess.FromConfig(level) != pb.BoxToolAccess_BOX_TOOL_ACCESS_FULL_SUDO {
		return "rm -f '" + file + "'\n"
	}
	return `set -e
command -v visudo >/dev/null 2>&1 || { echo "sudo is not installed on this box: full-sudo cannot be granted" >&2; exit 1; }
mkdir -p /etc/sudoers.d
tmp=$(mktemp /etc/sudoers.d/.` + boxRunUnprivilegedUser + `.XXXXXX)
printf '%s ALL=(ALL) NOPASSWD:ALL\n' '` + boxRunUnprivilegedUser + `' > "$tmp"
chmod 0440 "$tmp"
visudo -cf "$tmp" >/dev/null || { rm -f "$tmp"; echo "refusing to install an invalid sudoers rule" >&2; exit 1; }
mv -f "$tmp" '` + file + `'
`
}
