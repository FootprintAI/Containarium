package runhook

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

type recorder struct {
	events []*pb.AgentCommandEvent
	err    error
}

func (r *recorder) send(e *pb.AgentCommandEvent) error {
	if r.err != nil {
		return r.err
	}
	r.events = append(r.events, e)
	return nil
}

func preInput(cmd string) string {
	b, _ := json.Marshal(map[string]any{
		"hook_event_name": "PreToolUse",
		"tool_name":       "Bash",
		"tool_use_id":     "toolu_1",
		"tool_input":      map[string]string{"command": cmd},
	})
	return string(b)
}

func decodeOutput(t *testing.T, out string) preToolUseOutput {
	t.Helper()
	var o preToolUseOutput
	if strings.TrimSpace(out) == "" {
		return o
	}
	if err := json.Unmarshal([]byte(out), &o); err != nil {
		t.Fatalf("hook output is not JSON: %v\n%s", err, out)
	}
	return o
}

// Every command writes a start event before it runs.
func TestRunPre_LevelCommandWritesStartAndDefers(t *testing.T) {
	var rec recorder
	var out strings.Builder
	if err := RunPre(testConfig(), strings.NewReader(preInput("git status")), &out, rec.send); err != nil {
		t.Fatal(err)
	}
	if len(rec.events) != 1 || rec.events[0].GetKind() != pb.AgentCommandEventKind_AGENT_COMMAND_EVENT_KIND_START {
		t.Fatalf("events = %v, want one START", rec.events)
	}
	e := rec.events[0]
	if e.GetToolUseId() != "toolu_1" || e.GetClass() != pb.AgentCommandClass_AGENT_COMMAND_CLASS_LEVEL ||
		strings.Join(e.GetArgv(), " ") != "git status" {
		t.Errorf("start event = %v", e)
	}
	if o := decodeOutput(t, out.String()); o.HookSpecificOutput != nil && o.HookSpecificOutput.PermissionDecision != "" {
		t.Errorf("a level command must be left to the engine's rules, got %q", out.String())
	}
}

func TestRunPre_AllowlistedCommandIsAllowed(t *testing.T) {
	var rec recorder
	var out strings.Builder
	if err := RunPre(testConfig("make lint"), strings.NewReader(preInput("make lint")), &out, rec.send); err != nil {
		t.Fatal(err)
	}
	o := decodeOutput(t, out.String())
	if o.HookSpecificOutput == nil || o.HookSpecificOutput.PermissionDecision != "allow" || o.Continue != nil {
		t.Fatalf("output = %s, want an allow that keeps the run going", out.String())
	}
	if len(rec.events) != 1 || rec.events[0].GetClass() != pb.AgentCommandClass_AGENT_COMMAND_CLASS_ALLOWLISTED {
		t.Errorf("events = %v, want one ALLOWLISTED start", rec.events)
	}
}

// A non-matching command is denied with a typed close reason and a blocked
// event, and the run ends (continue:false) instead of pausing for an answer.
func TestRunPre_NonMatchingCommandBlocksAndEndsTheRun(t *testing.T) {
	var rec recorder
	var out strings.Builder
	if err := RunPre(testConfig(), strings.NewReader(preInput("rm -rf /tmp/x")), &out, rec.send); err != nil {
		t.Fatal(err)
	}
	o := decodeOutput(t, out.String())
	if o.HookSpecificOutput == nil || o.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("output = %s, want a deny", out.String())
	}
	if o.Continue == nil || *o.Continue || o.StopReason == "" {
		t.Errorf("the run must end: continue=false with a stop reason, got %s", out.String())
	}
	if len(rec.events) != 1 {
		t.Fatalf("events = %v, want exactly one BLOCKED (no START)", rec.events)
	}
	e := rec.events[0]
	if e.GetKind() != pb.AgentCommandEventKind_AGENT_COMMAND_EVENT_KIND_BLOCKED ||
		e.GetCloseReason() != pb.AgentCommandCloseReason_AGENT_COMMAND_CLOSE_REASON_NOT_ALLOWED ||
		e.GetClass() != pb.AgentCommandClass_AGENT_COMMAND_CLASS_NOT_ALLOWED {
		t.Errorf("blocked event = %v", e)
	}
}

// A command whose start event cannot be recorded does not run.
func TestRunPre_NoSinkFailsClosed(t *testing.T) {
	rec := recorder{err: errors.New("sink down")}
	var out strings.Builder
	_ = RunPre(testConfig(), strings.NewReader(preInput("git status")), &out, rec.send)
	o := decodeOutput(t, out.String())
	if o.HookSpecificOutput == nil || o.HookSpecificOutput.PermissionDecision != "deny" || o.Continue == nil || *o.Continue {
		t.Fatalf("output = %s, want deny and stop", out.String())
	}
	if !strings.Contains(o.StopReason, pb.AgentCommandCloseReason_AGENT_COMMAND_CLOSE_REASON_AUDIT_UNAVAILABLE.String()) {
		t.Errorf("stop reason %q lacks the typed close reason", o.StopReason)
	}
}

func TestRunPre_NonBashToolIsIgnored(t *testing.T) {
	var rec recorder
	var out strings.Builder
	in := `{"hook_event_name":"PreToolUse","tool_name":"Read","tool_use_id":"t","tool_input":{"file_path":"/x"}}`
	if err := RunPre(testConfig(), strings.NewReader(in), &out, rec.send); err != nil {
		t.Fatal(err)
	}
	if len(rec.events) != 0 || strings.TrimSpace(out.String()) != "" {
		t.Errorf("a non-shell tool must pass untouched: events=%v out=%q", rec.events, out.String())
	}
}

// The end event carries the exit code; command output is never sent.
func TestRunPost_EndEventWithExitCodeAndNoOutput(t *testing.T) {
	for _, tc := range []struct {
		name, in string
		want     int32
		known    bool
	}{
		{"success", `{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_use_id":"toolu_1","tool_input":{"command":"git status"},"tool_response":{"stdout":"SECRET-OUTPUT","stderr":"","interrupted":false}}`, 0, true},
		{"failure", `{"hook_event_name":"PostToolUseFailure","tool_name":"Bash","tool_use_id":"toolu_1","tool_input":{"command":"git status"},"error":"Exit code 3\nSECRET-OUTPUT"}`, 3, true},
		{"explicit code", `{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_use_id":"toolu_1","tool_input":{"command":"git status"},"tool_response":{"stdout":"SECRET-OUTPUT","exit_code":7}}`, 7, true},
		{"interrupted", `{"hook_event_name":"PostToolUseFailure","tool_name":"Bash","tool_use_id":"toolu_1","tool_input":{"command":"git status"},"error":"SECRET-OUTPUT","is_interrupt":true}`, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var rec recorder
			if err := RunPost(testConfig(), strings.NewReader(tc.in), rec.send); err != nil {
				t.Fatal(err)
			}
			if len(rec.events) != 1 {
				t.Fatalf("events = %v, want one END", rec.events)
			}
			e := rec.events[0]
			if e.GetKind() != pb.AgentCommandEventKind_AGENT_COMMAND_EVENT_KIND_END || e.GetToolUseId() != "toolu_1" {
				t.Errorf("end event = %v", e)
			}
			if (e.ExitCode != nil) != tc.known || (tc.known && e.GetExitCode() != tc.want) {
				t.Errorf("exit code = %v, want %d (known=%v)", e.ExitCode, tc.want, tc.known)
			}
			b, _ := json.Marshal(e)
			if strings.Contains(string(b), "SECRET-OUTPUT") {
				t.Errorf("command output reached the event: %s", b)
			}
		})
	}
}
