package agentbox

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/logframe"
)

// The shape no existing test had, and the reason #1701 shipped: the PARENT
// exits while the child still has output to write.
//
// Every other test keeps the parent alive for the run's duration, so the
// in-process frameWriter looked fine — but in production agent-box exits with
// its SSH connection, and the child died of SIGPIPE writing into a pipe
// nobody was reading. Both capture modes must survive that.
func TestSpawn_SurvivesParentExit(t *testing.T) {
	agentBox := buildAgentBoxForTest(t)

	for _, mode := range []CaptureMode{CaptureCombined, CaptureFramed} {
		t.Run(string(mode), func(t *testing.T) {
			dir := t.TempDir()
			name := "survive-" + string(mode)

			// A REAL separate agent-box process starts the run and then
			// exits — the disconnect. An in-process spawn cannot reproduce
			// this, because the test binary stays alive.
			script := mcpStartScript(name, string(mode),
				"sleep 1; echo LINE1; sleep 1; echo LINE2; exit 5")
			cmd := exec.Command(agentBox)
			cmd.Stdin = strings.NewReader(script)
			cmd.Env = append(os.Environ(), "AGENTBOX_LOG_DIR="+dir, "AGENTBOX_SELF="+agentBox)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("start via agent-box: %v\n%s", err, out)
			}
			// agent-box has now exited. The child should still be running.

			logPath := filepath.Join(dir, name+".log")
			exitPath := filepath.Join(dir, name+".exit")
			deadline := time.Now().Add(20 * time.Second)
			for time.Now().Before(deadline) {
				if _, err := os.Stat(exitPath); err == nil {
					break
				}
				time.Sleep(200 * time.Millisecond)
			}

			raw, err := os.ReadFile(exitPath)
			if err != nil {
				t.Fatalf("no exit sidecar — the run did not survive the parent: %v\n%s", err, summarizeSurvivalFailure(dir, name))
			}
			code := strings.Fields(string(raw))
			if len(code) == 0 || code[0] != "5" {
				// 141 here is SIGPIPE: the #1701 regression.
				t.Fatalf("exit code = %q, want 5 (141 means SIGPIPE — the child was killed by the parent's exit)\n%s", raw, summarizeSurvivalFailure(dir, name))
			}

			logData, err := os.ReadFile(logPath)
			if err != nil {
				t.Fatalf("read log: %v", err)
			}
			got := string(logData)
			if mode == CaptureFramed {
				var d logframe.Demuxer
				frames, derr := d.Write(logData)
				if derr != nil {
					t.Fatalf("demux: %v", derr)
				}
				var b strings.Builder
				for _, f := range frames {
					b.Write(f.Payload)
				}
				got = b.String()
			}
			for _, want := range []string{"LINE1", "LINE2"} {
				if !strings.Contains(got, want) {
					t.Errorf("output missing %q — got %q", want, got)
				}
			}
		})
	}
}

func summarizeSurvivalFailure(dir, name string) string {
	var b strings.Builder
	b.WriteString("-- run debug --\n")
	logPath := filepath.Join(dir, name+".log")
	if data, err := os.ReadFile(logPath); err == nil {
		b.WriteString("log_path: ")
		b.WriteString(logPath)
		b.WriteString("\n")
		if len(data) > 0 {
			b.WriteString("log preview:\n")
			preview := data
			if len(preview) > 4096 {
				preview = preview[:4096]
				b.WriteString("...truncated...\n")
			}
			b.WriteString(string(preview))
			if !strings.HasSuffix(string(preview), "\n") {
				b.WriteString("\n")
			}
		}
	} else {
		b.WriteString("log read error: ")
		b.WriteString(err.Error())
		b.WriteString("\n")
	}

	recordPath := filepath.Join(dir, name+".json")
	if data, err := os.ReadFile(recordPath); err == nil {
		var rec RunRecord
		if err := json.Unmarshal(data, &rec); err == nil {
			b.WriteString(fmt.Sprintf("record pid: %d\n", rec.PID))
			if rec.PID > 0 {
				if err := syscall.Kill(rec.PID, syscall.Signal(0)); err == nil {
					b.WriteString("child pid alive: yes\n")
				} else if err == syscall.ESRCH {
					b.WriteString("child pid alive: no\n")
				} else {
					b.WriteString(fmt.Sprintf("child pid alive: unknown (%v)\n", err))
				}
			}
		} else {
			b.WriteString("record parse error: ")
			b.WriteString(err.Error())
			b.WriteString("\n")
		}
	} else {
		b.WriteString("record read error: ")
		b.WriteString(err.Error())
		b.WriteString("\n")
	}
	b.WriteString("-- end run debug --\n")
	return b.String()
}

func mcpStartScript(name, mode, command string) string {
	esc := strings.ReplaceAll(command, `"`, `\"`)
	return strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"process_start","arguments":{"name":"` +
			name + `","capture_mode":"` + mode + `","command":"` + esc + `"}}}`,
	}, "\n") + "\n"
}

func buildAgentBoxForTest(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "agent-box")
	build := exec.Command("go", "build", "-o", bin, "../../cmd/agent-box")
	if out, err := build.CombinedOutput(); err != nil {
		t.Skipf("cannot build agent-box for this test: %v\n%s", err, out)
	}
	return bin
}
