package guardrailhook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// fileTool names the input fields of a tool that works on local files: the
// only places a marker is ever turned back into its value.
type fileTool struct {
	// paths name a local file or directory (or, for a glob, a pattern of
	// them).
	paths []string
	// content is text the tool writes into a file. The text an edit
	// replaces is deliberately not here: the agent checks it against the
	// file before any hook runs, so a marker there can never match.
	content []string
}

var fileTools = map[string]fileTool{
	"Read":         {paths: []string{"file_path"}},
	"Edit":         {paths: []string{"file_path"}, content: []string{"new_string"}},
	"Write":        {paths: []string{"file_path"}, content: []string{"content"}},
	"NotebookEdit": {paths: []string{"notebook_path"}, content: []string{"new_source"}},
	"Glob":         {paths: []string{"path", "pattern"}},
	"Grep":         {paths: []string{"path"}},
}

// shellTools run a command line, in the named input field.
var shellTools = map[string]string{"Bash": "command", "PowerShell": "command"}

// webFetchTool hands the fetched page to the model from inside the tool,
// before any hook sees it, so it cannot be redacted and is denied.
const webFetchTool = "WebFetch"

// credentialsFile is the agent's own credentials file. The handler never
// opens it, whatever an event names.
const credentialsFile = ".credentials.json"

// taskNotificationPrefix opens a prompt the agent generated from a
// background event rather than one a person typed.
const taskNotificationPrefix = "<task-notification>"

const sessionContext = "A guardrail is active in this environment. Text of the form [[TYPE:0123456789ab]] is a marker that stands in for a value removed before you saw it; TYPE says what kind of value it was. " +
	"A marker for personal data (an email address, for example) can be used in a file path and in the new content of a file edit or write: the real value is put back when the tool runs. " +
	"An edit, a write or a path that contains a marker for a secret is refused, and so is a marker this environment did not issue. " +
	"Markers cannot be used as the text an edit replaces (old_string): quote surrounding text that has no marker instead. " +
	"Markers are not turned back into values in shell commands, URLs, search queries or any other tool input. " +
	"WebFetch is refused while the guardrail is active; fetch a page with a shell command instead."

func (c *call) sessionStart() (*hookOutput, error) {
	if c.in.Source == "clear" {
		c.state.unblockSession(c.in.SessionID)
	}
	return &hookOutput{HookSpecificOutput: &hookSpecific{HookEventName: c.eventName(), AdditionalContext: sessionContext}}, nil
}

// deny refuses a tool call and records why.
func (c *call) deny(reason, detail string) (*hookOutput, error) {
	c.record(&pb.GuardrailHookRecord{
		Source:  pb.GuardrailHookSource_GUARDRAIL_HOOK_SOURCE_TOOL_INPUT,
		Outcome: pb.GuardrailHookOutcome_GUARDRAIL_HOOK_OUTCOME_DENIED,
		Detail:  detail,
	})
	return &hookOutput{HookSpecificOutput: &hookSpecific{
		HookEventName: c.eventName(), PermissionDecision: permissionDeny, PermissionDecisionReason: "Guardrail: " + reason,
	}}, nil
}

// toolInputFields decodes a tool input one level deep, leaving each field
// raw so the fields the handler does not touch go back byte for byte.
func toolInputFields(raw json.RawMessage) (map[string]json.RawMessage, error) {
	fields := map[string]json.RawMessage{}
	if len(raw) == 0 || string(raw) == "null" {
		return fields, nil
	}
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("tool_input is not a JSON object: %w", err)
	}
	return fields, nil
}

// stringField returns fields[name] when it is a JSON string.
func stringField(fields map[string]json.RawMessage, name string) (string, bool) {
	var s string
	if raw, ok := fields[name]; !ok || json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

func (c *call) preToolUse(ctx context.Context) (*hookOutput, error) {
	if err := c.requireTool(); err != nil {
		return nil, err
	}
	tool := c.in.ToolName
	// The gate: a tool whose output could not be scanned does not run.
	if err := c.h.ready(ctx); err != nil {
		return c.deny("the local detection engine is not ready, so this call was not run.", "engine not ready")
	}
	if tool == webFetchTool {
		return c.deny("WebFetch is refused while the guardrail is active, because the page would reach the model before it could be checked. Fetch it with a shell command instead.", "WebFetch denied")
	}
	fields, err := toolInputFields(c.in.ToolInput)
	if err != nil {
		return nil, err
	}
	if field, ok := shellTools[tool]; ok {
		if cmd, ok := stringField(fields, field); ok && c.namesStateDir(cmd) {
			return c.deny("this command names the guardrail's own state directory, which is not readable from a session.", "state directory named in a command")
		}
		return nil, nil
	}
	spec, ok := fileTools[tool]
	if !ok {
		// Never rehydrate in any other tool's input.
		return nil, nil
	}
	changed := false
	rehydrate := func(names []string, what string) (*hookOutput, error) {
		for _, name := range names {
			s, ok := stringField(fields, name)
			if !ok {
				continue
			}
			restored, problem := c.rehydrate(s)
			if problem != "" {
				return c.deny(fmt.Sprintf("this %s contains %s. Nothing was written or read. %s", what, problem, denyAdvice[what]), "marker refused in "+name)
			}
			if restored != s {
				b, err := marshalJSON(restored)
				if err != nil {
					return nil, err
				}
				fields[name] = b
				changed = true
			}
		}
		return nil, nil
	}
	if out, err := rehydrate(spec.paths, "path"); out != nil || err != nil {
		return out, err
	}
	for _, name := range spec.paths {
		if p, ok := stringField(fields, name); ok && c.underStateDir(p) {
			return c.deny("the guardrail's own state directory is not readable from a session.", "state directory named in "+name)
		}
	}
	if out, err := rehydrate(spec.content, "edit"); out != nil || err != nil {
		return out, err
	}
	if !changed {
		return nil, nil
	}
	// updatedInput with no permission decision: the user's own permission
	// rules and mode decide about the call, as they would have without us.
	return &hookOutput{HookSpecificOutput: &hookSpecific{HookEventName: c.eventName(), UpdatedInput: fields}}, nil
}

var denyAdvice = map[string]string{
	"path": "A file whose path holds a removed secret cannot be reached with file tools.",
	"edit": "Change that line yourself, or leave the marker out.",
}

// rehydrate puts the value back for every personal-data marker in s. It
// returns a non-empty problem, naming no value, when s holds a marker that
// must not or cannot be restored.
func (c *call) rehydrate(s string) (restored, problem string) {
	restored = markerRE.ReplaceAllStringFunc(s, func(tok string) string {
		e, known := c.state.markers[tok]
		switch {
		case !known:
			problem = "a marker this environment has no value for"
		case e.Kind != pb.GuardrailKind_GUARDRAIL_KIND_PII:
			problem = "a marker for a removed secret (" + e.Type + "), and secrets are never put back"
		default:
			return e.Value
		}
		return tok
	})
	return restored, problem
}

// underStateDir reports whether p is the state directory or inside it.
func (c *call) underStateDir(p string) bool {
	if !filepath.IsAbs(p) {
		p = filepath.Join(c.in.CWD, p)
	}
	p = filepath.Clean(p)
	dir := filepath.Clean(c.state.dir)
	return p == dir || strings.HasPrefix(p, dir+string(filepath.Separator))
}

// namesStateDir is the best-effort check for a command line: it catches the
// directory written out, absolute or relative to the home directory, and
// nothing cleverer. A shell can always build a path another way.
func (c *call) namesStateDir(cmd string) bool {
	dir := filepath.Clean(c.state.dir)
	if strings.Contains(cmd, dir) {
		return true
	}
	if home, err := os.UserHomeDir(); err == nil {
		if rel, err := filepath.Rel(home, dir); err == nil && !strings.HasPrefix(rel, "..") {
			return strings.Contains(cmd, rel)
		}
	}
	return false
}

func (c *call) postToolUse(ctx context.Context) (*hookOutput, error) {
	if err := c.requireTool(); err != nil {
		return nil, err
	}
	if err := c.recordMarkersLeftInInput(); err != nil {
		return nil, err
	}
	if len(c.in.ToolResponse) == 0 {
		return nil, nil
	}
	// The tool has already run and its result goes to the model unless it
	// is replaced here, so an engine failure degrades to the pattern pass
	// instead of failing the hook.
	redacted, res, err := c.scanValue(ctx, c.in.ToolName, c.in.ToolResponse, scanMode{rewrite: true})
	if err != nil {
		return nil, err
	}
	c.recordScan(c.in.ToolName, pb.GuardrailHookSource_GUARDRAIL_HOOK_SOURCE_TOOL_RESULT,
		pb.GuardrailHookOutcome_GUARDRAIL_HOOK_OUTCOME_REDACTED, res)
	if redacted == nil {
		return nil, nil
	}
	return &hookOutput{HookSpecificOutput: &hookSpecific{HookEventName: c.eventName(), UpdatedToolOutput: redacted}}, nil
}

// recordMarkersLeftInInput notes a marker still present, after the tool
// ran, in a field this handler restores at PreToolUse. A marker it refused
// would have denied the call, so one that is still here means another
// hook's input rewrite replaced ours and the marker may now be in a file.
func (c *call) recordMarkersLeftInInput() error {
	spec, ok := fileTools[c.in.ToolName]
	if !ok {
		return nil
	}
	fields, err := toolInputFields(c.in.ToolInput)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, name := range append(append([]string{}, spec.paths...), spec.content...) {
		s, _ := stringField(fields, name)
		for _, m := range markerRE.FindAllStringSubmatch(s, -1) {
			if seen[m[0]] {
				continue
			}
			seen[m[0]] = true
			c.record(&pb.GuardrailHookRecord{
				Source:  pb.GuardrailHookSource_GUARDRAIL_HOOK_SOURCE_TOOL_INPUT,
				Outcome: pb.GuardrailHookOutcome_GUARDRAIL_HOOK_OUTCOME_MARKER_IN_TOOL_INPUT,
				Kind:    c.state.markers[m[0]].Kind,
				Type:    m[1],
				Excerpt: m[0],
				Detail:  "marker still present in " + name + " after the tool ran",
			})
		}
	}
	return nil
}

func (c *call) postToolBatch(ctx context.Context) (*hookOutput, error) {
	// A rescan with no memory of what PostToolUse did: whatever is found
	// here is about to reach the model, whether a replacement was rejected
	// or the PostToolUse hook never ran.
	var found []hit
	for _, tc := range c.in.ToolCalls {
		if len(tc.ToolResponse) == 0 {
			continue
		}
		_, res, err := c.scanValue(ctx, tc.ToolName, tc.ToolResponse, scanMode{})
		if err != nil {
			return nil, err
		}
		c.recordScan(tc.ToolName, pb.GuardrailHookSource_GUARDRAIL_HOOK_SOURCE_TOOL_RESULT,
			pb.GuardrailHookOutcome_GUARDRAIL_HOOK_OUTCOME_UNREDACTED_AT_BATCH, res)
		found = append(found, res.hits...)
	}
	if len(found) == 0 || !c.h.cfg.BlockOnBatchFinding {
		return nil, nil
	}
	// Stopping here ends the turn but does not take the result out of the
	// conversation: it would go out with the next prompt. So the session
	// refuses prompts from now on.
	if err := c.state.blockSession(c.in.SessionID); err != nil {
		return nil, fmt.Errorf("guardrail: could not hold the session: %w", err)
	}
	return &hookOutput{Decision: decisionBlock, Reason: "Guardrail: a tool result containing " + hitTypes(found) +
		" was about to reach the model unredacted, so the turn was stopped. " + heldAdvice}, nil
}

const heldAdvice = "This session still holds that result: run /clear or start a new session to continue."

func (c *call) userPromptSubmit(ctx context.Context) (*hookOutput, error) {
	block := func(reason string) *hookOutput {
		return &hookOutput{Decision: decisionBlock, Reason: "Guardrail: " + reason,
			HookSpecificOutput: &hookSpecific{HookEventName: c.eventName(), SuppressOriginalPrompt: true}}
	}
	if c.h.cfg.BlockOnBatchFinding && c.state.sessionBlocked(c.in.SessionID) {
		return block("an unredacted tool result is held in this session, so prompts are refused. " + heldAdvice), nil
	}
	source, what := pb.GuardrailHookSource_GUARDRAIL_HOOK_SOURCE_PROMPT, "this prompt contains %s and was not sent. Remove it and send the prompt again."
	if strings.HasPrefix(strings.TrimSpace(c.in.Prompt), taskNotificationPrefix) {
		// A background event cannot be rewritten, only dropped whole.
		source, what = pb.GuardrailHookSource_GUARDRAIL_HOOK_SOURCE_TASK_NOTIFICATION, "a background event contained %s and was dropped."
	}
	// The prompt can still be stopped, so a scan that fails is an error (the
	// command exits 2, which blocks the prompt), never a pass.
	res, err := c.scanUnits(ctx, []*unit{{lines: []string{c.in.Prompt}}}, scanMode{strict: true})
	if err != nil {
		return nil, err
	}
	c.recordScan("", source, pb.GuardrailHookOutcome_GUARDRAIL_HOOK_OUTCOME_BLOCKED, res)
	if len(res.hits) == 0 {
		return nil, nil
	}
	return block(fmt.Sprintf(what, hitTypes(res.hits))), nil
}

// instructionsLoaded scans an instruction or memory file the agent loaded
// by itself. The agent discards this event's output and ignores its exit
// status, so all it can do is record.
func (c *call) instructionsLoaded(ctx context.Context) error {
	if c.in.FilePath == "" || filepath.Base(c.in.FilePath) == credentialsFile {
		return nil
	}
	b, err := c.h.cfg.ReadFile(c.in.FilePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("guardrail: read instruction file: %w", err)
	}
	res := &scanned{skippedBinary: 1}
	if utf8.Valid(b) {
		if res, err = c.scanUnits(ctx, []*unit{{lines: []string{string(b)}}}, scanMode{}); err != nil {
			return err
		}
	}
	c.recordScan("", pb.GuardrailHookSource_GUARDRAIL_HOOK_SOURCE_INSTRUCTIONS,
		pb.GuardrailHookOutcome_GUARDRAIL_HOOK_OUTCOME_RECORDED, res)
	return nil
}
