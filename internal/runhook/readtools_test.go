package runhook

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

func readToolPre(tool, input string) string {
	return `{"hook_event_name":"PreToolUse","tool_name":"` + tool + `","tool_use_id":"toolu_r","tool_input":` + input + `}`
}

func readToolPost(tool, input string) string {
	return `{"hook_event_name":"PostToolUse","tool_name":"` + tool + `","tool_use_id":"toolu_r","tool_input":` + input + `,"tool_response":{"content":"SECRET-OUTPUT"}}`
}

// Read, Grep and Glob are observed: a START is recorded with the tool kind
// and its target, and the engine is never told to allow or deny them.
func TestRunPre_ReadToolsAreRecordedWithoutADecision(t *testing.T) {
	for _, tc := range []struct {
		name, in string
		tool     pb.AgentToolKind
		target   string
		pattern  string
	}{
		{"read", readToolPre("Read", `{"file_path":"/work/app/main.go","offset":10}`), pb.AgentToolKind_AGENT_TOOL_KIND_READ, "/work/app/main.go", ""},
		{"grep", readToolPre("Grep", `{"pattern":"TODO","path":"/work/app"}`), pb.AgentToolKind_AGENT_TOOL_KIND_GREP, "/work/app", "TODO"},
		{"glob", readToolPre("Glob", `{"pattern":"**/*.go"}`), pb.AgentToolKind_AGENT_TOOL_KIND_GLOB, "", "**/*.go"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var rec recorder
			var out strings.Builder
			if err := RunPre(testConfig(), strings.NewReader(tc.in), &out, rec.send); err != nil {
				t.Fatal(err)
			}
			if strings.TrimSpace(out.String()) != "" {
				t.Errorf("an observed tool must get no decision, got %q", out.String())
			}
			if len(rec.events) != 1 {
				t.Fatalf("events = %v, want one START", rec.events)
			}
			e := rec.events[0]
			if e.GetKind() != pb.AgentCommandEventKind_AGENT_COMMAND_EVENT_KIND_START || e.GetToolUseId() != "toolu_r" {
				t.Errorf("start event = %v", e)
			}
			if e.GetTool() != tc.tool || e.GetTarget() != tc.target || e.GetPattern() != tc.pattern {
				t.Errorf("tool=%v target=%q pattern=%q, want %v %q %q", e.GetTool(), e.GetTarget(), e.GetPattern(), tc.tool, tc.target, tc.pattern)
			}
		})
	}
}

// A failed send does not refuse a read: the decision is unchanged, so the
// read proceeds as it would without the hook.
func TestRunPre_ReadToolSendFailureDoesNotDeny(t *testing.T) {
	rec := recorder{err: errors.New("sink down")}
	var out strings.Builder
	if err := RunPre(testConfig(), strings.NewReader(readToolPre("Read", `{"file_path":"/x"}`)), &out, rec.send); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out.String()) != "" {
		t.Errorf("a read must not be denied by a failed record, got %q", out.String())
	}
}

// The END pairs with the START by tool use id, carries the tool kind and
// target, has no exit code (no shell ran), and never carries the content.
func TestRunPost_ReadToolEndEvent(t *testing.T) {
	var rec recorder
	if err := RunPost(testConfig(), strings.NewReader(readToolPost("Grep", `{"pattern":"TODO","path":"/work"}`)), rec.send); err != nil {
		t.Fatal(err)
	}
	if len(rec.events) != 1 {
		t.Fatalf("events = %v, want one END", rec.events)
	}
	e := rec.events[0]
	if e.GetKind() != pb.AgentCommandEventKind_AGENT_COMMAND_EVENT_KIND_END || e.GetToolUseId() != "toolu_r" {
		t.Errorf("end event = %v", e)
	}
	if e.GetTool() != pb.AgentToolKind_AGENT_TOOL_KIND_GREP || e.GetTarget() != "/work" || e.GetPattern() != "TODO" {
		t.Errorf("end event tool fields = %v", e)
	}
	if e.ExitCode != nil {
		t.Errorf("a non-shell tool has no exit code, got %d", e.GetExitCode())
	}
	if e.GetOutcome() != pb.AgentCommandOutcome_AGENT_COMMAND_OUTCOME_RAN {
		t.Errorf("outcome = %v, want RAN", e.GetOutcome())
	}
	b, _ := json.Marshal(e)
	if strings.Contains(string(b), "SECRET-OUTPUT") {
		t.Errorf("tool output reached the event: %s", b)
	}
}

// Tools outside the observed set stay untouched, post hook included.
func TestRunPost_UnobservedToolIsIgnored(t *testing.T) {
	var rec recorder
	if err := RunPost(testConfig(), strings.NewReader(readToolPost("Edit", `{"file_path":"/x"}`)), rec.send); err != nil {
		t.Fatal(err)
	}
	if len(rec.events) != 0 {
		t.Errorf("events = %v, want none", rec.events)
	}
}

// The sink redacts a read tool's target and pattern as it does argv, and
// stamps identity itself.
func TestSink_RedactsReadToolTargetAndPattern(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "r1.sock")
	out := filepath.Join(dir, "events", "r1.jsonl")
	cfg := testConfig()
	cfg.Socket = sock
	cfg.EventsPath = out

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, ln, cfg, func() time.Time { return time.Unix(1, 0) }, nil) }()

	const token = "ghp_0123456789abcdefghij0123456789abcdef"
	if err := DialSender(sock)(&pb.AgentCommandEvent{
		Kind:      pb.AgentCommandEventKind_AGENT_COMMAND_EVENT_KIND_START,
		ToolUseId: "toolu_g",
		Tool:      pb.AgentToolKind_AGENT_TOOL_KIND_GREP,
		Target:    "/work/" + token,
		Pattern:   token,
	}); err != nil {
		t.Fatalf("send: %v", err)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("sink did not stop")
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "ghp_0123456789") {
		t.Fatalf("token reached the audit file: %s", data)
	}
	var e pb.AgentCommandEvent
	// The START is the first line; the sink closes it with an END at shutdown.
	first := strings.SplitN(strings.TrimSpace(string(data)), "\n", 2)[0]
	if err := protojson.Unmarshal([]byte(first), &e); err != nil {
		t.Fatal(err)
	}
	if e.GetTool() != pb.AgentToolKind_AGENT_TOOL_KIND_GREP || e.GetRunName() != "r1" {
		t.Errorf("event = %v", &e)
	}
	if e.GetTarget() == "" || e.GetPattern() == "" {
		t.Errorf("redaction removed the fields entirely: target=%q pattern=%q", e.GetTarget(), e.GetPattern())
	}
}
