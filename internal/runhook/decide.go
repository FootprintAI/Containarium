package runhook

import (
	"strings"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Box paths. Everything lives under AuditDir, which root owns: the hooks read
// their configuration from it and reach the sink's socket in it, and only the
// sink (root) writes the events directory.
const (
	AuditDir = "/var/lib/containarium-run-audit"
	// AgentBoxPath is the root-owned copy of agent-box the hooks and the sink
	// run, so the run user cannot swap the hook binary.
	AgentBoxPath = AuditDir + "/bin/agent-box"
	// EnginePath is the root-owned copy of the engine (Claude Code) a run under
	// a command policy executes, in the same root-owned directory. The run
	// user's own staged copy is writable by it, so an agent could replace that
	// one and start the next run without the hooks.
	EnginePath = AuditDir + "/bin/claude"
)

// ConfigPath is a run's hook and sink configuration (root-owned, 0644).
func ConfigPath(runName string) string { return AuditDir + "/" + runName + ".policy.json" }

// SocketPath is a run's sink socket, named by run id (a run name can be longer
// than a unix socket path allows).
func SocketPath(runID string) string { return AuditDir + "/s/" + runID + ".sock" }

// EventsPath is a run name's append-only audit file (root-owned, 0600, in a
// 0700 directory). Every start of the run appends to it under its own run id.
func EventsPath(runName string) string { return EventsPathUnder(AuditDir, runName) }

// EventsPathUnder is EventsPath for an audit directory other than AuditDir.
func EventsPathUnder(auditDir, runName string) string {
	return auditDir + "/events/" + runName + ".jsonl"
}

// DonePath is the marker the sink creates next to eventsPath after its last
// event: once it exists nothing more is appended. Same owner and mode as the
// events file.
func DonePath(eventsPath string) string { return eventsPath + ".done" }

// ExitPath is where the root supervisor (`agent-box run-supervise`) records a
// run's exit status ("<status> <epoch>", root-owned 0600 in a 0700 directory).
// The sink reads the run's end from it, never from the run directory's
// <name>.exit, which the run user can write.
func ExitPath(runName string) string { return AuditDir + "/exit/" + runName + ".exit" }

// LaunchPath is where the supervisor reports the run's "<pid> <boot_id>" to
// the root launch script (root-owned, in the same directory as ExitPath).
func LaunchPath(runName string) string { return AuditDir + "/exit/" + runName + ".launch" }

// Approval is the approval a re-run carries.
type Approval struct {
	ID       string `json:"id"`
	Approver string `json:"approver"`
}

// Config is the per-run configuration the daemon writes, as root, for the
// hooks and the sink.
type Config struct {
	RunName    string `json:"run_name"`
	RunID      string `json:"run_id"`
	Socket     string `json:"socket"`
	EventsPath string `json:"events_path"`
	// ExitPath is the run's root-owned exit status (see ExitPath). Empty
	// means the sink has no trusted status and every end is an interruption.
	ExitPath string `json:"exit_path,omitempty"`
	// Allow is the org allowlist (AgentCommandPolicy.allow).
	Allow []string `json:"allow"`
	// LevelAllowed and LevelDenied are the run's tool-access level as the
	// engine's own permission rules (--allowedTools / --disallowedTools).
	LevelAllowed []string `json:"level_allowed"`
	LevelDenied  []string `json:"level_denied"`
	// RedactPatterns are the operator's additions to the default redactions.
	RedactPatterns []string  `json:"redact_patterns,omitempty"`
	Approval       *Approval `json:"approval,omitempty"`
	// Command is a command-mode run's shell command (StartBoxRunRequest.command):
	// `agent-box permission-hook command` decides and runs exactly this text, so
	// what is decided is what the daemon wrote as root. Empty for engine runs.
	Command string `json:"command,omitempty"`
}

// Verdict is what the pre hook tells the engine.
type Verdict int

const (
	// VerdictDefer leaves the command to the engine's own permission rules.
	VerdictDefer Verdict = iota
	// VerdictAllow runs it even if those rules would not.
	VerdictAllow
	// VerdictDeny refuses it and ends the run.
	VerdictDeny
)

// Decision is the pre hook's classification of one command.
type Decision struct {
	Class       pb.AgentCommandClass
	Verdict     Verdict
	CloseReason pb.AgentCommandCloseReason
	// Reason is a short human-readable reason for a deny.
	Reason string
	// Argv is what the audit event records: redacted, assignments dropped.
	Argv []string
}

// Decide classifies command under cfg. Order: hard denies, then the
// allowlist (which widens the level for matching entries only), then the
// level. Anything else is refused, as is a line that does not parse.
func Decide(cfg Config, command string) Decision {
	red, err := NewRedactor(cfg.RedactPatterns)
	if err != nil {
		red, _ = NewRedactor(nil)
	}
	c, err := ParseCommand(command)
	if err != nil {
		return Decision{Class: pb.AgentCommandClass_AGENT_COMMAND_CLASS_NOT_ALLOWED, Verdict: VerdictDeny,
			CloseReason: pb.AgentCommandCloseReason_AGENT_COMMAND_CLOSE_REASON_NOT_ALLOWED,
			Reason:      "the command does not parse: " + err.Error(), Argv: []string{Redacted}}
	}
	argv := red.Argv(c.Log)
	hard, ok, tooDeep := scanHardDeny(c)
	if r := hard; ok {
		return Decision{Class: pb.AgentCommandClass_AGENT_COMMAND_CLASS_HARD_DENIED, Verdict: VerdictDeny,
			CloseReason: pb.AgentCommandCloseReason_AGENT_COMMAND_CLOSE_REASON_HARD_DENY,
			Reason:      "hard deny: " + r, Argv: argv}
	}
	// What the parser cannot resolve to the program it runs cannot be checked
	// against the hard denies, so it is refused here by name: brace expansion,
	// a glob in the executable word, ANSI-C quoting and arithmetic expansion in
	// a command word, and a quoted shell command nested past the rescan depth.
	// Compound lines, pipes, redirections, substitutions and globs in arguments
	// are not refused for their shape: the hard-deny scan above read every
	// segment, and the level covers them segment by segment below.
	if why := unresolvableReason(c, tooDeep); why != "" {
		return Decision{Class: pb.AgentCommandClass_AGENT_COMMAND_CLASS_NOT_ALLOWED, Verdict: VerdictDeny,
			CloseReason: pb.AgentCommandCloseReason_AGENT_COMMAND_CLOSE_REASON_UNRESOLVABLE,
			Reason:      "unresolvable command: " + why, Argv: argv}
	}
	if allow, err := ParseAllowlist(cfg.Allow); err == nil && allow.Match(c) {
		return Decision{Class: pb.AgentCommandClass_AGENT_COMMAND_CLASS_ALLOWLISTED, Verdict: VerdictAllow, Argv: argv}
	}
	if levelCovers(cfg, command, c) {
		return Decision{Class: pb.AgentCommandClass_AGENT_COMMAND_CLASS_LEVEL, Verdict: VerdictDefer, Argv: argv}
	}
	return Decision{Class: pb.AgentCommandClass_AGENT_COMMAND_CLASS_NOT_ALLOWED, Verdict: VerdictDeny,
		CloseReason: pb.AgentCommandCloseReason_AGENT_COMMAND_CLOSE_REASON_NOT_ALLOWED,
		Reason:      "not within the run's tool-access level and no allowlist entry matches", Argv: argv}
}

// levelCovers reports whether the level's rules allow the line. A simple
// command is matched whole; any other line only when every one of its commands
// (segments, substitutions included) is allowed on its own. The engine still
// applies its own rules to a line this lets through (the hook defers), so this
// can only be stricter.
func levelCovers(cfg Config, command string, c Command) bool {
	if c.Simple {
		return levelAllows(cfg.LevelAllowed, cfg.LevelDenied, command)
	}
	if len(c.Segments) == 0 {
		return false
	}
	for i, s := range c.Segments {
		// A leading assignment is part of the command as written, exactly as
		// for a simple line: the level's rule must match it with the assignment.
		words := append(append([]string(nil), c.SegmentAssigns[i]...), s...)
		if !levelAllows(cfg.LevelAllowed, cfg.LevelDenied, strings.Join(words, " ")) {
			return false
		}
	}
	return true
}

// unresolvableReason says why c cannot be resolved to the program it runs, or
// "" when it can.
func unresolvableReason(c Command, tooDeep bool) string {
	switch {
	case c.Unresolvable != "":
		return c.Unresolvable
	case tooDeep:
		return "a quoted shell command is nested deeper than the supported depth"
	}
	return ""
}
