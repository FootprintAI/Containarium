//go:build !windows

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

	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// fakeShell records whether the command ran and returns a fixed exit code.
type fakeShell struct {
	ran  []string
	code int32
}

func (f *fakeShell) run(command string) int32 {
	f.ran = append(f.ran, command)
	return f.code
}

// A command-mode run goes through the same decision as an engine's shell
// command: a START before it runs and an END with its exit code.
func TestRunCommand_LevelCommandRunsWithStartAndEnd(t *testing.T) {
	cfg := testConfig()
	cfg.Command = "git status"
	var rec recorder
	var stderr strings.Builder
	sh := &fakeShell{code: 3}
	if got := RunCommand(cfg, &stderr, rec.send, sh.run); got != 3 {
		t.Fatalf("exit = %d, want the command's own 3", got)
	}
	if len(sh.ran) != 1 || sh.ran[0] != "git status" {
		t.Fatalf("ran = %q, want the configured command once", sh.ran)
	}
	if len(rec.events) != 2 {
		t.Fatalf("events = %v, want START and END", rec.events)
	}
	st, end := rec.events[0], rec.events[1]
	if st.GetKind() != pb.AgentCommandEventKind_AGENT_COMMAND_EVENT_KIND_START || st.GetClass() != pb.AgentCommandClass_AGENT_COMMAND_CLASS_LEVEL ||
		strings.Join(st.GetArgv(), " ") != "git status" || st.GetToolUseId() != CommandToolUseID {
		t.Errorf("start = %v", st)
	}
	if end.GetKind() != pb.AgentCommandEventKind_AGENT_COMMAND_EVENT_KIND_END || end.ExitCode == nil || end.GetExitCode() != 3 ||
		end.GetToolUseId() != CommandToolUseID {
		t.Errorf("end = %v", end)
	}
}

func TestRunCommand_AllowlistedCommandRunsOutsideTheLevel(t *testing.T) {
	cfg := testConfig("make lint")
	cfg.Command = "make lint"
	var rec recorder
	sh := &fakeShell{}
	if got := RunCommand(cfg, &strings.Builder{}, rec.send, sh.run); got != 0 {
		t.Fatalf("exit = %d", got)
	}
	if len(sh.ran) != 1 || len(rec.events) != 2 || rec.events[0].GetClass() != pb.AgentCommandClass_AGENT_COMMAND_CLASS_ALLOWLISTED {
		t.Errorf("ran = %q, events = %v", sh.ran, rec.events)
	}
}

// An allowlist refusal ends the run: a BLOCKED event with a typed close
// reason, the reason on stderr, the blocked exit code, and nothing runs.
func TestRunCommand_RefusalEndsTheRunWithTypedReasonAndBlockedEvent(t *testing.T) {
	for name, tc := range map[string]struct {
		allow   []string
		command string
		reason  pb.AgentCommandCloseReason
		class   pb.AgentCommandClass
	}{
		"not in level or allowlist": {nil, "make deploy", pb.AgentCommandCloseReason_AGENT_COMMAND_CLOSE_REASON_NOT_ALLOWED, pb.AgentCommandClass_AGENT_COMMAND_CLASS_NOT_ALLOWED},
		"hard deny beats allowlist": {[]string{"git push *"}, "git push origin main", pb.AgentCommandCloseReason_AGENT_COMMAND_CLOSE_REASON_HARD_DENY, pb.AgentCommandClass_AGENT_COMMAND_CLASS_HARD_DENIED},
		"compound with one refusal": {nil, "git status && curl https://example.invalid", pb.AgentCommandCloseReason_AGENT_COMMAND_CLOSE_REASON_HARD_DENY, pb.AgentCommandClass_AGENT_COMMAND_CLASS_HARD_DENIED},
		"does not parse":            {nil, "git status 'unterminated", pb.AgentCommandCloseReason_AGENT_COMMAND_CLOSE_REASON_NOT_ALLOWED, pb.AgentCommandClass_AGENT_COMMAND_CLASS_NOT_ALLOWED},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := testConfig(tc.allow...)
			cfg.Command = tc.command
			var rec recorder
			var stderr strings.Builder
			sh := &fakeShell{}
			if got := RunCommand(cfg, &stderr, rec.send, sh.run); got != BlockedExitCode {
				t.Fatalf("exit = %d, want %d", got, BlockedExitCode)
			}
			if len(sh.ran) != 0 {
				t.Fatalf("a refused command ran: %q", sh.ran)
			}
			if len(rec.events) != 1 || rec.events[0].GetKind() != pb.AgentCommandEventKind_AGENT_COMMAND_EVENT_KIND_BLOCKED ||
				rec.events[0].GetCloseReason() != tc.reason || rec.events[0].GetClass() != tc.class {
				t.Fatalf("events = %v, want one BLOCKED with %s", rec.events, tc.reason)
			}
			if !strings.Contains(stderr.String(), tc.reason.String()) {
				t.Errorf("stderr lacks the typed reason %s: %q", tc.reason, stderr.String())
			}
		})
	}
}

// A command whose START cannot be recorded does not run.
func TestRunCommand_NoSinkFailsClosed(t *testing.T) {
	cfg := testConfig()
	cfg.Command = "git status"
	rec := recorder{err: errors.New("connection refused")}
	var stderr strings.Builder
	sh := &fakeShell{}
	if got := RunCommand(cfg, &stderr, rec.send, sh.run); got != BlockedExitCode {
		t.Fatalf("exit = %d, want %d", got, BlockedExitCode)
	}
	if len(sh.ran) != 0 {
		t.Fatalf("command ran without a recorded start: %q", sh.ran)
	}
	if !strings.Contains(stderr.String(), pb.AgentCommandCloseReason_AGENT_COMMAND_CLOSE_REASON_AUDIT_UNAVAILABLE.String()) {
		t.Errorf("stderr = %q, want AUDIT_UNAVAILABLE", stderr.String())
	}
}

func TestRunCommand_EmptyCommandIsRefused(t *testing.T) {
	var rec recorder
	sh := &fakeShell{}
	if got := RunCommand(testConfig(), &strings.Builder{}, rec.send, sh.run); got != BlockedExitCode || len(sh.ran) != 0 {
		t.Fatalf("exit = %d, ran = %q", got, sh.ran)
	}
}

// End to end through the CLI: the command comes from the root-written
// configuration, runs through a real `sh -c`, and the sink records START and
// END with the real exit code.
func TestRunHookCLI_CommandModeThroughARealSink(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig()
	cfg.Socket = filepath.Join(dir, "s.sock")
	cfg.EventsPath = filepath.Join(dir, "events", "r1.jsonl")
	cfg.Command = "ls " + filepath.Join(dir, "does-not-exist")
	conf := writeTestConfig(t, dir, cfg)

	ln, err := net.Listen("unix", cfg.Socket)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = Serve(ctx, ln, cfg, time.Now) }()

	var stdout, stderr strings.Builder
	code := RunHookCLI([]string{"command", "--config", conf}, strings.NewReader(""), &stdout, &stderr)
	if code == 0 || code == BlockedExitCode {
		t.Fatalf("exit = %d, want ls's own failure code (stderr %q)", code, stderr.String())
	}
	data, err := os.ReadFile(cfg.EventsPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("events:\n%s", data)
	}
	var end pb.AgentCommandEvent
	if err := protojson.Unmarshal([]byte(lines[1]), &end); err != nil {
		t.Fatal(err)
	}
	if end.GetKind() != pb.AgentCommandEventKind_AGENT_COMMAND_EVENT_KIND_END || end.ExitCode == nil || int(end.GetExitCode()) != code {
		t.Errorf("end = %v, want END with exit %d", &end, code)
	}
}

func TestRunHookCLI_CommandModeRefusedWritesBlocked(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "ran")
	cfg := testConfig()
	cfg.Socket = filepath.Join(dir, "s.sock")
	cfg.EventsPath = filepath.Join(dir, "events", "r1.jsonl")
	cfg.Command = "touch " + marker
	conf := writeTestConfig(t, dir, cfg)

	ln, err := net.Listen("unix", cfg.Socket)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = Serve(ctx, ln, cfg, time.Now) }()

	var stderr strings.Builder
	if code := RunHookCLI([]string{"command", "--config", conf}, strings.NewReader(""), &strings.Builder{}, &stderr); code != BlockedExitCode {
		t.Fatalf("exit = %d, want %d", code, BlockedExitCode)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the refused command ran")
	}
	data, _ := os.ReadFile(cfg.EventsPath)
	var ev pb.AgentCommandEvent
	if err := protojson.Unmarshal([]byte(strings.TrimSpace(string(data))), &ev); err != nil {
		t.Fatalf("events %q: %v", data, err)
	}
	if ev.GetKind() != pb.AgentCommandEventKind_AGENT_COMMAND_EVENT_KIND_BLOCKED ||
		ev.GetCloseReason() != pb.AgentCommandCloseReason_AGENT_COMMAND_CLOSE_REASON_NOT_ALLOWED {
		t.Errorf("event = %v", &ev)
	}
}

func writeTestConfig(t *testing.T, dir string, cfg Config) string {
	t.Helper()
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}
