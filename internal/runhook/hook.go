package runhook

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// The engine's (Claude Code's) hook contract: a JSON object on stdin, and for
// PreToolUse a JSON decision on stdout. Only the fields used here are named.

// shellTool is the engine's tool name for shell commands. The hooks are
// registered for it and for the observed read-only tools below.
const shellTool = "Bash"

// HookMatcher is the matcher the run's hooks are registered under: the shell
// tool and every observed read-only tool.
const HookMatcher = "Bash|Read|Grep|Glob"

// observedTools are the read-only engine tools the hooks record without
// deciding: the audit covers what the agent read and searched for. They are
// never refused here; the engine's own rules still apply to them.
var observedTools = map[string]pb.AgentToolKind{
	"Read": pb.AgentToolKind_AGENT_TOOL_KIND_READ,
	"Grep": pb.AgentToolKind_AGENT_TOOL_KIND_GREP,
	"Glob": pb.AgentToolKind_AGENT_TOOL_KIND_GLOB,
}

type hookInput struct {
	HookEventName string          `json:"hook_event_name"`
	ToolName      string          `json:"tool_name"`
	ToolUseID     string          `json:"tool_use_id"`
	ToolInput     hookToolInput   `json:"tool_input"`
	ToolResponse  json.RawMessage `json:"tool_response,omitempty"`
	// PostToolUseFailure only.
	Error       string `json:"error,omitempty"`
	IsInterrupt bool   `json:"is_interrupt,omitempty"`
}

// hookToolInput holds the fields of each tool this hook reads: a shell command, or
// a Read's file_path, a Grep's or Glob's pattern and search path.
type hookToolInput struct {
	Command  string `json:"command"`
	FilePath string `json:"file_path"`
	Pattern  string `json:"pattern"`
	Path     string `json:"path"`
}

// shellToolResponse is the part of a shell tool's response that may carry an
// exit code (the field name differs between engine releases). Output fields
// are deliberately not decoded.
type shellToolResponse struct {
	ExitCode   *int32 `json:"exit_code,omitempty"`
	ExitCode2  *int32 `json:"exitCode,omitempty"`
	ReturnCode *int32 `json:"returnCode,omitempty"`
}

type hookSpecific struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision,omitempty"`
	PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
}

type preToolUseOutput struct {
	Continue           *bool         `json:"continue,omitempty"`
	StopReason         string        `json:"stopReason,omitempty"`
	HookSpecificOutput *hookSpecific `json:"hookSpecificOutput,omitempty"`
}

// Sender delivers one event to the run's sink and returns once it is stored.
type Sender func(*pb.AgentCommandEvent) error

// RunPre is the PreToolUse hook. It records a START before an allowed or
// deferred command and writes the engine decision; a refused command gets a
// BLOCKED event, a deny, and continue:false, which ends the run (it is not
// paused for an answer: an approval starts a new run). A command whose START
// cannot be recorded is refused the same way.
func RunPre(cfg Config, in io.Reader, out io.Writer, send Sender) error {
	var hi hookInput
	if err := json.NewDecoder(io.LimitReader(in, 1<<20)).Decode(&hi); err != nil {
		return writeDeny(out, pb.AgentCommandCloseReason_AGENT_COMMAND_CLOSE_REASON_NOT_ALLOWED, "unreadable hook input")
	}
	if kind, ok := observedTools[hi.ToolName]; ok {
		// Observation only: a failed record does not refuse a read.
		_ = send(observedEvent(hi, kind, pb.AgentCommandEventKind_AGENT_COMMAND_EVENT_KIND_START))
		return nil
	}
	if hi.ToolName != shellTool {
		return nil
	}
	d := Decide(cfg, hi.ToolInput.Command)
	ev := &pb.AgentCommandEvent{ToolUseId: hi.ToolUseID, Argv: d.Argv, Class: d.Class}
	if d.Verdict == VerdictDeny {
		ev.Kind = pb.AgentCommandEventKind_AGENT_COMMAND_EVENT_KIND_BLOCKED
		ev.CloseReason = d.CloseReason
		_ = send(ev) // refused either way
		return writeDeny(out, d.CloseReason, d.Reason)
	}
	ev.Kind = pb.AgentCommandEventKind_AGENT_COMMAND_EVENT_KIND_START
	if err := send(ev); err != nil {
		return writeDeny(out, pb.AgentCommandCloseReason_AGENT_COMMAND_CLOSE_REASON_AUDIT_UNAVAILABLE,
			"the start event could not be recorded: "+err.Error())
	}
	if d.Verdict == VerdictAllow {
		return json.NewEncoder(out).Encode(preToolUseOutput{HookSpecificOutput: &hookSpecific{
			HookEventName: "PreToolUse", PermissionDecision: "allow",
			PermissionDecisionReason: "matched the org command allowlist",
		}})
	}
	return nil // deferred to the level's own rules
}

// observedEvent is the START or END for a read-only tool. It names the tool,
// its file or search target and pattern; never its output or its content.
func observedEvent(hi hookInput, kind pb.AgentToolKind, eventKind pb.AgentCommandEventKind) *pb.AgentCommandEvent {
	ev := &pb.AgentCommandEvent{Kind: eventKind, ToolUseId: hi.ToolUseID, Tool: kind}
	switch kind {
	case pb.AgentToolKind_AGENT_TOOL_KIND_READ:
		ev.Target = hi.ToolInput.FilePath
	case pb.AgentToolKind_AGENT_TOOL_KIND_GREP, pb.AgentToolKind_AGENT_TOOL_KIND_GLOB:
		ev.Target = hi.ToolInput.Path
		ev.Pattern = hi.ToolInput.Pattern
	}
	if eventKind == pb.AgentCommandEventKind_AGENT_COMMAND_EVENT_KIND_END {
		ev.Outcome = pb.AgentCommandOutcome_AGENT_COMMAND_OUTCOME_RAN
	}
	return ev
}

func writeDeny(out io.Writer, reason pb.AgentCommandCloseReason, why string) error {
	stop := false
	msg := fmt.Sprintf("command refused (%s): %s. The run ends; an approval starts a new run.", reason, why)
	return json.NewEncoder(out).Encode(preToolUseOutput{
		Continue:   &stop,
		StopReason: msg,
		HookSpecificOutput: &hookSpecific{
			HookEventName: "PreToolUse", PermissionDecision: "deny", PermissionDecisionReason: msg,
		},
	})
}

// failureExitCode is the first line of a PostToolUseFailure error text from
// Claude Code's shell tool: "Exit code N", then a newline and the output (or
// nothing). It is the engine's display text, not a documented field: the only
// source of a failed command's exit code the hook input has (observed with
// Claude Code 2.1.319). Nothing but that exact first line is accepted, so a
// changed format, or output that happens to contain the phrase, yields an
// unknown code rather than a wrong one.
var failureExitCode = regexp.MustCompile(`\AExit code ([0-9]{1,3})(?:\r?\n|\z)`)

// RunPost is the PostToolUse / PostToolUseFailure hook: it records an END,
// outcome RAN, with the exit code when it is known. Output is never read into
// the event.
func RunPost(cfg Config, in io.Reader, send Sender) error {
	var hi hookInput
	if err := json.NewDecoder(io.LimitReader(in, 64<<20)).Decode(&hi); err != nil {
		return fmt.Errorf("unreadable hook input: %w", err)
	}
	if _, ok := observedTools[hi.ToolName]; ok {
		return send(observedEvent(hi, observedTools[hi.ToolName], pb.AgentCommandEventKind_AGENT_COMMAND_EVENT_KIND_END))
	}
	if hi.ToolName != shellTool {
		return nil
	}
	ev := &pb.AgentCommandEvent{Kind: pb.AgentCommandEventKind_AGENT_COMMAND_EVENT_KIND_END, ToolUseId: hi.ToolUseID}
	if c, err := ParseCommand(hi.ToolInput.Command); err == nil {
		red, rerr := NewRedactor(cfg.RedactPatterns)
		if rerr != nil {
			red, _ = NewRedactor(nil)
		}
		ev.Argv = red.Argv(c.Log)
	}
	ev.ExitCode = exitCode(hi)
	ev.Outcome = pb.AgentCommandOutcome_AGENT_COMMAND_OUTCOME_RAN
	return send(ev)
}

func exitCode(hi hookInput) *int32 {
	var r shellToolResponse
	if len(hi.ToolResponse) > 0 && json.Unmarshal(hi.ToolResponse, &r) == nil {
		for _, c := range []*int32{r.ExitCode, r.ExitCode2, r.ReturnCode} {
			if c != nil {
				return c
			}
		}
	}
	switch hi.HookEventName {
	case "PostToolUse":
		zero := int32(0) // the engine fires PostToolUse only for exit status 0
		return &zero
	case "PostToolUseFailure":
		return failureTextExitCode(hi.Error)
	}
	return nil // not a post event this hook knows: unknown, not 0
}

// failureTextExitCode reads N from a PostToolUseFailure error text that begins
// with the line "Exit code N" (0-255). Anything else is unknown (nil): an
// interrupt, a missing line, a non-numeric or out-of-range value.
func failureTextExitCode(text string) *int32 {
	m := failureExitCode.FindStringSubmatch(text)
	if m == nil {
		return nil
	}
	n, err := strconv.ParseUint(m[1], 10, 8) // 0-255; 256 and up fail
	if err != nil {
		return nil
	}
	v := int32(uint8(n))
	return &v
}
