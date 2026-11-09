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

// shellTool is the engine's tool name for shell commands, the hooks' matcher.
const shellTool = "Bash"

type hookInput struct {
	HookEventName string          `json:"hook_event_name"`
	ToolName      string          `json:"tool_name"`
	ToolUseID     string          `json:"tool_use_id"`
	ToolInput     shellToolInput  `json:"tool_input"`
	ToolResponse  json.RawMessage `json:"tool_response,omitempty"`
	// PostToolUseFailure only.
	Error       string `json:"error,omitempty"`
	IsInterrupt bool   `json:"is_interrupt,omitempty"`
}

type shellToolInput struct {
	Command string `json:"command"`
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

var exitCodePrefix = regexp.MustCompile(`^Exit code (-?\d+)`)

// RunPost is the PostToolUse / PostToolUseFailure hook: it records an END with
// the exit code when the engine reports one. Output is never read into the
// event.
func RunPost(cfg Config, in io.Reader, send Sender) error {
	var hi hookInput
	if err := json.NewDecoder(io.LimitReader(in, 64<<20)).Decode(&hi); err != nil {
		return fmt.Errorf("unreadable hook input: %w", err)
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
	if hi.HookEventName == "PostToolUseFailure" {
		if m := exitCodePrefix.FindStringSubmatch(hi.Error); m != nil {
			if n, err := strconv.ParseInt(m[1], 10, 32); err == nil {
				v := int32(n)
				return &v
			}
		}
		return nil // interrupted or no code reported
	}
	zero := int32(0) // the engine reports success only for exit status 0
	return &zero
}
