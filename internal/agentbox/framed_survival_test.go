package agentbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
				t.Fatalf("no exit sidecar — the run did not survive the parent: %v", err)
			}
			code := strings.Fields(string(raw))
			if len(code) == 0 || code[0] != "5" {
				// 141 here is SIGPIPE: the #1701 regression.
				t.Fatalf("exit code = %q, want 5 (141 means SIGPIPE — the child was killed by the parent's exit)", raw)
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
