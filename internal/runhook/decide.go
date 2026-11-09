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
)

// ConfigPath is a run's hook and sink configuration (root-owned, 0644).
func ConfigPath(runName string) string { return AuditDir + "/" + runName + ".policy.json" }

// SocketPath is a run's sink socket, named by run id (a run name can be longer
// than a unix socket path allows).
func SocketPath(runID string) string { return AuditDir + "/s/" + runID + ".sock" }

// EventsPath is a run name's append-only audit file (root-owned, 0600, in a
// 0700 directory). Every start of the run appends to it under its own run id.
func EventsPath(runName string) string { return AuditDir + "/events/" + runName + ".jsonl" }

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
	if r, ok := HardDeny(c); ok {
		return Decision{Class: pb.AgentCommandClass_AGENT_COMMAND_CLASS_HARD_DENIED, Verdict: VerdictDeny,
			CloseReason: pb.AgentCommandCloseReason_AGENT_COMMAND_CLOSE_REASON_HARD_DENY,
			Reason:      "hard deny: " + r, Argv: argv}
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
// command is matched whole; a compound line only when every one of its
// commands is allowed on its own. The engine still applies its own rules to a
// line this lets through (the hook defers), so this can only be stricter.
func levelCovers(cfg Config, command string, c Command) bool {
	if c.Simple {
		return levelAllows(cfg.LevelAllowed, cfg.LevelDenied, command)
	}
	if len(c.Segments) == 0 {
		return false
	}
	for _, s := range c.Segments {
		if !levelAllows(cfg.LevelAllowed, cfg.LevelDenied, strings.Join(s, " ")) {
			return false
		}
	}
	return true
}
