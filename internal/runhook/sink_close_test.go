//go:build !windows

package runhook

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// startSink serves cfg on a fresh socket and returns a sender, the events
// path, and a stop function that cancels the sink and waits for it to return.
func startSink(t *testing.T, exit func() RunExit) (Config, Sender, func() []*pb.AgentCommandEvent) {
	t.Helper()
	dir := t.TempDir()
	cfg := testConfig()
	cfg.Socket = filepath.Join(dir, "r1.sock")
	cfg.EventsPath = filepath.Join(dir, "events", "r1.jsonl")
	ln, err := net.Listen("unix", cfg.Socket)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, ln, cfg, time.Now, exit) }()
	stop := func() []*pb.AgentCommandEvent {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("sink: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("sink did not stop")
		}
		return readEvents(t, cfg.EventsPath)
	}
	return cfg, DialSender(cfg.Socket), stop
}

func readEvents(t *testing.T, path string) []*pb.AgentCommandEvent {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var evs []*pb.AgentCommandEvent
	for _, l := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		e := &pb.AgentCommandEvent{}
		if err := protojson.Unmarshal([]byte(l), e); err != nil {
			t.Fatalf("line %q: %v", l, err)
		}
		evs = append(evs, e)
	}
	return evs
}

// endsFor returns the END events for one tool_use_id.
func endsFor(evs []*pb.AgentCommandEvent, id string) []*pb.AgentCommandEvent {
	var out []*pb.AgentCommandEvent
	for _, e := range evs {
		if e.GetKind() == pb.AgentCommandEventKind_AGENT_COMMAND_EVENT_KIND_END && e.GetToolUseId() == id {
			out = append(out, e)
		}
	}
	return out
}

func toolInput(event, id, cmd, extra string) string {
	return `{"hook_event_name":"` + event + `","tool_name":"Bash","tool_use_id":"` + id +
		`","tool_input":{"command":"` + cmd + `"}` + extra + `}`
}

// The gap the live test found: the pre hook defers a command, the engine then
// refuses it itself (--restricted path confinement), and no post hook fires.
// When the run ends cleanly the sink must close that START with an END that
// says the command did not run, with a typed close reason and no exit code.
// A command that did finish keeps its one END from the post hook.
func TestSink_EngineRefusedCommandGetsAnEndOnCleanRunExit(t *testing.T) {
	cfg, send, stop := startSink(t, func() RunExit { return RunExitClean })

	var out strings.Builder
	if err := RunPre(cfg, strings.NewReader(toolInput("PreToolUse", "toolu_ok", "git status", "")), &out, send); err != nil {
		t.Fatal(err)
	}
	if err := RunPost(cfg, strings.NewReader(toolInput("PostToolUse", "toolu_ok", "git status", `,"tool_response":{"stdout":""}`)), send); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := RunPre(cfg, strings.NewReader(toolInput("PreToolUse", "toolu_refused", "ls /outside", "")), &out, send); err != nil {
		t.Fatal(err)
	}
	if o := decodeOutput(t, out.String()); o.HookSpecificOutput != nil {
		t.Fatalf("precondition: the pre hook must defer, got %+v", o.HookSpecificOutput)
	}
	// No post hook for toolu_refused: the engine refused it.

	evs := stop()
	if ends := endsFor(evs, "toolu_ok"); len(ends) != 1 ||
		ends[0].GetOutcome() != pb.AgentCommandOutcome_AGENT_COMMAND_OUTCOME_RAN || ends[0].GetExitCode() != 0 || ends[0].ExitCode == nil {
		t.Errorf("the command that ran must keep exactly its own END (RAN, exit 0): %v", ends)
	}
	ends := endsFor(evs, "toolu_refused")
	if len(ends) != 1 {
		t.Fatalf("START without an END: got %d ENDs for toolu_refused in\n%v", len(ends), evs)
	}
	e := ends[0]
	if e.GetOutcome() != pb.AgentCommandOutcome_AGENT_COMMAND_OUTCOME_NOT_RUN ||
		e.GetCloseReason() != pb.AgentCommandCloseReason_AGENT_COMMAND_CLOSE_REASON_ENGINE_REFUSED {
		t.Errorf("END = %v, want outcome NOT_RUN and close reason ENGINE_REFUSED", e)
	}
	if e.ExitCode != nil {
		t.Errorf("a command that did not run has no exit code, got %d", e.GetExitCode())
	}
	if strings.Join(e.GetArgv(), " ") != "ls /outside" || e.GetClass() != pb.AgentCommandClass_AGENT_COMMAND_CLASS_LEVEL {
		t.Errorf("END must carry the START's argv and class: %v", e)
	}
	if e.GetRunName() != "r1" || e.GetTime() == nil {
		t.Errorf("END must be stamped like any other event: %v", e)
	}
}

// A run killed or crashed after a START: the sink writes an END with the
// INTERRUPTED reason and an UNKNOWN outcome, never a dangling START and never
// a claim that the command did not run.
func TestSink_InterruptedRunClosesOpenStartsAsInterrupted(t *testing.T) {
	for name, exit := range map[string]func() RunExit{
		"killed":       func() RunExit { return RunExitInterrupted },
		"no exit info": nil,
	} {
		t.Run(name, func(t *testing.T) {
			_, send, stop := startSink(t, exit)
			if err := send(&pb.AgentCommandEvent{Kind: pb.AgentCommandEventKind_AGENT_COMMAND_EVENT_KIND_START,
				ToolUseId: CommandToolUseID, Argv: []string{"make", "test"}, Class: pb.AgentCommandClass_AGENT_COMMAND_CLASS_LEVEL}); err != nil {
				t.Fatal(err)
			}
			evs := stop()
			ends := endsFor(evs, CommandToolUseID)
			if len(ends) != 1 {
				t.Fatalf("got %d ENDs, want 1:\n%v", len(ends), evs)
			}
			if ends[0].GetCloseReason() != pb.AgentCommandCloseReason_AGENT_COMMAND_CLOSE_REASON_INTERRUPTED ||
				ends[0].GetOutcome() != pb.AgentCommandOutcome_AGENT_COMMAND_OUTCOME_UNKNOWN || ends[0].ExitCode != nil {
				t.Errorf("END = %v, want INTERRUPTED / UNKNOWN / no exit code", ends[0])
			}
		})
	}
}

// Every START has exactly one END, and nothing else is added: BLOCKED events
// and STARTs already closed get no extra END.
func TestSink_NoExtraEndsWhenEveryStartIsClosed(t *testing.T) {
	_, send, stop := startSink(t, func() RunExit { return RunExitClean })
	for _, e := range []*pb.AgentCommandEvent{
		{Kind: pb.AgentCommandEventKind_AGENT_COMMAND_EVENT_KIND_START, ToolUseId: "a"},
		{Kind: pb.AgentCommandEventKind_AGENT_COMMAND_EVENT_KIND_END, ToolUseId: "a"},
		{Kind: pb.AgentCommandEventKind_AGENT_COMMAND_EVENT_KIND_BLOCKED, ToolUseId: "b",
			CloseReason: pb.AgentCommandCloseReason_AGENT_COMMAND_CLOSE_REASON_NOT_ALLOWED},
	} {
		if err := send(e); err != nil {
			t.Fatal(err)
		}
	}
	if evs := stop(); len(evs) != 3 {
		t.Errorf("got %d events, want the 3 sent:\n%v", len(evs), evs)
	}
}

// How the sink reads the run's end: clean only for an exit status of 0 in a
// fresh root-owned exit file; anything else is an interruption.
func TestRunExitFromRootExitStatus(t *testing.T) {
	since := time.Now().Add(-time.Minute)
	for _, tc := range []struct {
		name, status string
		alive        bool
		want         RunExit
		ended        bool
	}{
		{"exit 0", "0 1762650000", true, RunExitClean, true},
		{"non-zero", "2 1762650000", true, RunExitInterrupted, true},
		{"timeout", "124 1762650000", true, RunExitInterrupted, true},
		{"killed", "137 1762650000", true, RunExitInterrupted, true},
		{"garbage", "zero", true, RunExitInterrupted, true},
		{"empty", "", true, RunExitInterrupted, true},
		{"process gone, no status", "-", false, RunExitInterrupted, true},
		{"still running", "-", true, RunExitInterrupted, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			exitPath := filepath.Join(t.TempDir(), "r1.exit")
			b := []byte(`{"pid":42,"started_at":"` + time.Now().Format(time.RFC3339Nano) + `"}`)
			if err := os.WriteFile(filepath.Join(dir, "r1.json"), b, 0o600); err != nil {
				t.Fatal(err)
			}
			if tc.status != "-" {
				if err := os.WriteFile(exitPath, []byte(tc.status), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			ended, how := runEnded(exitPath, dir, "r1", since, time.Now(), func(int) bool { return tc.alive })
			if ended != tc.ended || (ended && how != tc.want) {
				t.Errorf("runEnded = %v, %v; want %v, %v", ended, how, tc.ended, tc.want)
			}
		})
	}
}
