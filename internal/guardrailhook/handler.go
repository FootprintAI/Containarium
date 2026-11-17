// Package guardrailhook is the handler behind `containarium guardrail hook
// <event>`: a coding-agent hook that redacts what the agent gives the model,
// inside the box (docs/architecture/guardrail.md, "Coding-agent hooks").
//
// It reads one hook event as JSON, asks a guardrail engine what is sensitive,
// and answers in the agent's hook protocol: replace a tool result with a
// redacted copy, restore personal-data markers in a file edit, deny a call,
// or block a prompt. Nothing leaves the machine: the engine is in-process or
// on a local socket, and the marker key, the marker map and the findings
// spool live in a per-user state directory.
//
// The package detects nothing itself and never reads a credential.
package guardrailhook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/guardrail"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Defaults for a zero Config field.
const (
	DefaultEngineWait       = 3 * time.Second
	DefaultScanTimeout      = 2 * time.Second
	DefaultFullScanMaxBytes = 16 << 10
	DefaultSpoolMaxBytes    = 1 << 20
)

// Config is one invocation's settings. The zero value of every field but
// StateDir has a usable default.
type Config struct {
	// StateDir holds the marker key, the marker map, the stamps and the
	// findings spool. Created 0700 on first use.
	StateDir string
	// Engine does the full scan. nil means the in-tree reference rules
	// engine, in-process.
	Engine guardrail.Engine
	// EngineWait is how long PreToolUse waits for the engine before it
	// denies the call.
	EngineWait time.Duration
	// ScanTimeout bounds one engine scan.
	ScanTimeout time.Duration
	// FullScanMaxBytes is the largest text the engine is asked to scan. A
	// larger one gets the in-process pattern pass and is recorded as
	// partially scanned, except a prompt, which can still be stopped and so
	// always goes to the engine.
	FullScanMaxBytes int
	// SpoolMaxBytes bounds the findings spool. A row that would not fit is
	// dropped.
	SpoolMaxBytes int64
	// BlockOnBatchFinding makes a PostToolBatch finding stop the turn and
	// refuse later prompts in that session until it is cleared. Off by
	// default.
	BlockOnBatchFinding bool

	// ReadFile reads an instruction file. Defaults to os.ReadFile.
	ReadFile func(string) ([]byte, error)
	// ParentPID and Proc locate the agent process for the stamp. Default to
	// os.Getppid and /proc.
	ParentPID int
	Proc      ProcTable
	// Now defaults to time.Now.
	Now func() time.Time
}

// Handler handles hook events under one Config.
type Handler struct {
	cfg  Config
	fast guardrail.Engine
}

// New fills in the defaults.
func New(cfg Config) *Handler {
	if cfg.Engine == nil {
		cfg.Engine = guardrail.RulesEngine{}
	}
	if cfg.EngineWait <= 0 {
		cfg.EngineWait = DefaultEngineWait
	}
	if cfg.ScanTimeout <= 0 {
		cfg.ScanTimeout = DefaultScanTimeout
	}
	if cfg.FullScanMaxBytes <= 0 {
		cfg.FullScanMaxBytes = DefaultFullScanMaxBytes
	}
	if cfg.SpoolMaxBytes <= 0 {
		cfg.SpoolMaxBytes = DefaultSpoolMaxBytes
	}
	if cfg.ReadFile == nil {
		cfg.ReadFile = os.ReadFile
	}
	if cfg.ParentPID == 0 {
		cfg.ParentPID = os.Getppid()
	}
	if cfg.Proc == nil {
		cfg.Proc = procFS{}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Handler{cfg: cfg, fast: guardrail.RulesEngine{}}
}

// hookInput is the hook event as the agent sends it. Only the fields the
// handler reads are named. tool_input and tool_response stay raw here: their
// shape belongs to each tool, so they are decoded where they are used.
type hookInput struct {
	SessionID string `json:"session_id"`
	AgentID   string `json:"agent_id"`
	CWD       string `json:"cwd"`

	ToolName     string          `json:"tool_name"`
	ToolInput    json.RawMessage `json:"tool_input"`
	ToolResponse json.RawMessage `json:"tool_response"`
	// PostToolBatch.
	ToolCalls []toolCall `json:"tool_calls"`
	// UserPromptSubmit.
	Prompt string `json:"prompt"`
	// SessionStart: startup, resume, clear, compact or fork.
	Source string `json:"source"`
	// InstructionsLoaded.
	FilePath string `json:"file_path"`
}

type toolCall struct {
	ToolName     string          `json:"tool_name"`
	ToolInput    json.RawMessage `json:"tool_input"`
	ToolResponse json.RawMessage `json:"tool_response"`
}

// hookOutput is what the handler prints. The field names and the decision
// values are the agent's hook protocol, not ours.
type hookOutput struct {
	Decision           string        `json:"decision,omitempty"`
	Reason             string        `json:"reason,omitempty"`
	HookSpecificOutput *hookSpecific `json:"hookSpecificOutput,omitempty"`
}

type hookSpecific struct {
	HookEventName            string                     `json:"hookEventName"`
	PermissionDecision       string                     `json:"permissionDecision,omitempty"`
	PermissionDecisionReason string                     `json:"permissionDecisionReason,omitempty"`
	UpdatedInput             map[string]json.RawMessage `json:"updatedInput,omitempty"`
	UpdatedToolOutput        json.RawMessage            `json:"updatedToolOutput,omitempty"`
	AdditionalContext        string                     `json:"additionalContext,omitempty"`
	SuppressOriginalPrompt   bool                       `json:"suppressOriginalPrompt,omitempty"`
}

const (
	decisionBlock  = "block"
	permissionDeny = "deny"
)

// eventNames maps the event to the name the agent uses for it.
var eventNames = map[pb.GuardrailHookEvent]string{
	pb.GuardrailHookEvent_GUARDRAIL_HOOK_EVENT_SESSION_START:       "SessionStart",
	pb.GuardrailHookEvent_GUARDRAIL_HOOK_EVENT_PRE_TOOL_USE:        "PreToolUse",
	pb.GuardrailHookEvent_GUARDRAIL_HOOK_EVENT_POST_TOOL_USE:       "PostToolUse",
	pb.GuardrailHookEvent_GUARDRAIL_HOOK_EVENT_POST_TOOL_BATCH:     "PostToolBatch",
	pb.GuardrailHookEvent_GUARDRAIL_HOOK_EVENT_USER_PROMPT_SUBMIT:  "UserPromptSubmit",
	pb.GuardrailHookEvent_GUARDRAIL_HOOK_EVENT_INSTRUCTIONS_LOADED: "InstructionsLoaded",
}

// ParseEvent turns the agent's event name into the enum.
func ParseEvent(name string) (pb.GuardrailHookEvent, error) {
	names := make([]string, 0, len(eventNames))
	for ev, n := range eventNames {
		if n == name {
			return ev, nil
		}
		names = append(names, n)
	}
	return pb.GuardrailHookEvent_GUARDRAIL_HOOK_EVENT_UNSPECIFIED,
		fmt.Errorf("unknown hook event %q (supported: %s)", name, strings.Join(sortedStrings(names), ", "))
}

// call is one event being handled.
type call struct {
	h     *Handler
	ev    pb.GuardrailHookEvent
	in    hookInput
	state *state
}

// Handle runs one event and returns what to print on stdout: a JSON object,
// or nothing when the handler has nothing to say. A denial or a block is a
// normal answer. An error means the handler could not do its job; the caller
// must exit with status 2 and print nothing on stdout, never 0: an agent
// reads "exit 0 with no usable output" as "go ahead".
func (h *Handler) Handle(ctx context.Context, ev pb.GuardrailHookEvent, stdin []byte) ([]byte, error) {
	if _, ok := eventNames[ev]; !ok {
		return nil, fmt.Errorf("unsupported hook event %v", ev)
	}
	c := &call{h: h, ev: ev}
	if err := json.Unmarshal(stdin, &c.in); err != nil {
		return nil, fmt.Errorf("hook input is not valid JSON: %w", err)
	}
	st, err := openState(h.cfg)
	if err != nil {
		return nil, err
	}
	c.state = st
	st.touchStamp(stampPID(h.cfg.ParentPID, h.cfg.Proc))

	var out *hookOutput
	switch ev {
	case pb.GuardrailHookEvent_GUARDRAIL_HOOK_EVENT_SESSION_START:
		out, err = c.sessionStart()
	case pb.GuardrailHookEvent_GUARDRAIL_HOOK_EVENT_PRE_TOOL_USE:
		out, err = c.preToolUse(ctx)
	case pb.GuardrailHookEvent_GUARDRAIL_HOOK_EVENT_POST_TOOL_USE:
		out, err = c.postToolUse(ctx)
	case pb.GuardrailHookEvent_GUARDRAIL_HOOK_EVENT_POST_TOOL_BATCH:
		out, err = c.postToolBatch(ctx)
	case pb.GuardrailHookEvent_GUARDRAIL_HOOK_EVENT_USER_PROMPT_SUBMIT:
		out, err = c.userPromptSubmit(ctx)
	case pb.GuardrailHookEvent_GUARDRAIL_HOOK_EVENT_INSTRUCTIONS_LOADED:
		err = c.instructionsLoaded(ctx)
	}
	if err != nil {
		return nil, err
	}
	if out == nil {
		return nil, nil
	}
	return marshalJSON(out)
}

func (c *call) eventName() string { return eventNames[c.ev] }

// requireTool rejects a tool event that does not name its tool: a rule that
// keys on the tool name must not run against an empty one.
func (c *call) requireTool() error {
	if c.in.ToolName == "" {
		return errors.New("hook input has no tool_name")
	}
	return nil
}

// record appends one row to the spool. Best effort by design: a full or
// unwritable spool drops the row and never fails the agent's call.
func (c *call) record(r *pb.GuardrailHookRecord) {
	r.SessionId = c.in.SessionID
	r.AgentId = c.in.AgentID
	r.Event = c.ev
	if r.ToolName == "" {
		r.ToolName = c.in.ToolName
	}
	c.state.appendRecord(r)
}
