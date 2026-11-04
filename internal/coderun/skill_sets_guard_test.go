package coderun

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/footprintai/containarium/pkg/core/sdlcskills"
)

// boxShellConn stands in for agent-box over SSH as the box owner: shell_exec
// runs the command with the local sh against home and answers in agent-box's
// own shell_exec framing; process_start is recorded and answered canned.
type boxShellConn struct {
	t      *testing.T
	home   string
	starts int
	// kills records process_kill calls as "<name> force=<bool>".
	kills []string
	// beforeClear runs before a stale-marker clear script, onStart inside
	// process_start: where a test makes a new apply take the marker.
	beforeClear, onStart func()
}

func (c *boxShellConn) Initialize(context.Context, mcp.InitializeRequest) (*mcp.InitializeResult, error) {
	return &mcp.InitializeResult{}, nil
}

func (c *boxShellConn) CallTool(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args, _ := req.Params.Arguments.(map[string]any)
	var reply string
	switch req.Params.Name {
	case "shell_exec":
		command := args["command"].(string)
		if c.beforeClear != nil && strings.Contains(command, "echo removed") {
			c.beforeClear()
		}
		reply = boxShellExecForTest(c.home, command)
	case "process_start":
		c.starts++
		if c.onStart != nil {
			c.onStart()
		}
		reply = "name: r\npid: 42\ncommand: x\nlog_path: /tmp/r.log\nstarted_at: 2026-11-04T00:00:00Z\n"
	case "process_kill":
		c.kills = append(c.kills, fmt.Sprintf("%v force=%v", args["name"], args["force"]))
		reply = fmt.Sprintf("name: %v\npid: 42\nsignal: SIGKILL\nexited: true\nlog_path: /tmp/r.log\n", args["name"])
	default:
		return nil, errors.New("boxShellConn: unexpected tool " + req.Params.Name)
	}
	return &mcp.CallToolResult{Content: []mcp.Content{mcp.TextContent{Type: "text", Text: reply}}}, nil
}

func (c *boxShellConn) Close() error { return nil }

// boxShellExecForTest runs command with sh as if agent-box's shell_exec ran it
// with HOME=home, and returns the reply in shell_exec's framing.
func boxShellExecForTest(home, command string) string {
	cmd := exec.Command("sh", "-c", command)
	cmd.Env = append(os.Environ(), "HOME="+home)
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	code := 0
	if err := cmd.Run(); err != nil {
		code = 1
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		}
	}
	return fmt.Sprintf("exit_code: %d\ntimeout_seconds: 30\n--- stdout ---\n%s\n--- stderr ---\n%s", code, stdout.String(), stderr.String())
}

func markerPath(home string) string {
	return filepath.Join(home, ".claude", "skills", sdlcskills.ApplyMarkerFile)
}

func writeMarker(t *testing.T, home, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(markerPath(home)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(markerPath(home), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func takeMarker(t *testing.T, home string) {
	t.Helper()
	out := boxShellExecForTest(home, sdlcskills.ApplyMarkerWriteScript(0, sdlcskills.ApplyMarkerLease))
	if !strings.HasPrefix(out, "exit_code: 0\n") {
		t.Fatalf("write marker: %s", out)
	}
}

func TestProcessStart_RefusedWhileASkillSetApplyHoldsTheMarker(t *testing.T) {
	home := t.TempDir()
	takeMarker(t, home)
	conn := &boxShellConn{t: t, home: home}
	_, err := sessionWith(conn).ProcessStart(context.Background(), "r", "claude -p hi", "", "")
	if !errors.Is(err, ErrSkillSetsApplyInProgress) {
		t.Fatalf("err = %v, want ErrSkillSetsApplyInProgress", err)
	}
	if !strings.Contains(err.Error(), "ApplyBoxSkillSets") {
		t.Errorf("refusal %q does not name the apply", err)
	}
	if conn.starts != 0 {
		t.Fatalf("process_start was called %d time(s) under a held marker; the run must not launch", conn.starts)
	}
	if _, err := os.Stat(markerPath(home)); err != nil {
		t.Fatalf("a held marker must be left in place: %v", err)
	}
}

func TestProcessStart_StaleMarkerIsClearedAndTheRunStarts(t *testing.T) {
	for _, tc := range []struct{ name, content, why string }{
		{"lease lapsed", fmt.Sprintf(`{"version":1,"started_at":%d,"expires_at":%d}`, time.Now().Add(-time.Hour).Unix(), time.Now().Add(-time.Minute).Unix()), "lease lapsed"},
		{"unreadable", "not json", "cannot be read"},
		{"expiry beyond any lease", fmt.Sprintf(`{"version":1,"started_at":%d,"expires_at":%d}`, time.Now().Unix(), time.Now().Add(24*time.Hour).Unix()), "clock moved back"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			writeMarker(t, home, tc.content)
			conn := &boxShellConn{t: t, home: home}
			started, err := sessionWith(conn).ProcessStart(context.Background(), "r", "claude -p hi", "", "")
			if err != nil {
				t.Fatalf("a stale marker must not refuse the run: %v", err)
			}
			if conn.starts != 1 {
				t.Fatalf("process_start called %d time(s), want 1", conn.starts)
			}
			if !strings.Contains(started.Warning, sdlcskills.ApplyMarkerFile) || !strings.Contains(started.Warning, tc.why) {
				t.Errorf("warning %q does not name the stale marker and why (%q)", started.Warning, tc.why)
			}
			if _, err := os.Stat(markerPath(home)); !os.IsNotExist(err) {
				t.Fatalf("a stale marker must be removed: stat err = %v", err)
			}
		})
	}
}

func TestProcessStart_NoMarkerStartsWithoutWarning(t *testing.T) {
	home := t.TempDir()
	conn := &boxShellConn{t: t, home: home}
	started, err := sessionWith(conn).ProcessStart(context.Background(), "r", "claude -p hi", "", "")
	if err != nil || conn.starts != 1 || started.Warning != "" {
		t.Fatalf("err = %v, starts = %d, warning = %q; want a plain start", err, conn.starts, started.Warning)
	}
}

func TestProcessStart_RefusesWhenTheCheckCannotRun(t *testing.T) {
	conn := &scriptedConn{replies: map[string]string{
		"shell_exec":    "exit_code: 127\ntimeout_seconds: 30\n--- stdout ---\n\n--- stderr ---\nsh: date: not found",
		"process_start": "name: r\npid: 1\n",
	}}
	_, err := sessionWith(conn).ProcessStart(context.Background(), "r", "x", "", "")
	if err == nil {
		t.Fatal("a check that could not run must not let the run start")
	}
	if _, called := conn.call("process_start"); called {
		t.Fatal("process_start was called after a failed check")
	}
}

// A stale marker is replaced by a new apply's between the check and the clear:
// the clear keeps the new one, and the run is refused rather than started under
// it.
func TestProcessStart_RefusedWhenANewApplyTakesTheMarkerDuringAStaleClear(t *testing.T) {
	home := t.TempDir()
	writeMarker(t, home, `{"version":1,"started_at":1,"expires_at":2}`)
	conn := &boxShellConn{t: t, home: home, beforeClear: func() { takeMarker(t, home) }}
	_, err := sessionWith(conn).ProcessStart(context.Background(), "r", "claude -p hi", "", "")
	if !errors.Is(err, ErrSkillSetsApplyInProgress) {
		t.Fatalf("err = %v, want ErrSkillSetsApplyInProgress", err)
	}
	if conn.starts != 0 {
		t.Fatalf("process_start called %d time(s) under the new apply's marker", conn.starts)
	}
	if _, err := os.Stat(markerPath(home)); err != nil {
		t.Fatalf("the new apply's marker must be kept: %v", err)
	}
}

// The residual race: the check passes, then an apply takes the marker before
// the run's record exists (so its run-in-progress check does not see the run).
// agent-box writes the record before process_start returns, so the re-check
// after it sees the marker, and the run is stopped and refused.
func TestProcessStart_StopsARunWhoseApplyStartedDuringTheLaunch(t *testing.T) {
	home := t.TempDir()
	conn := &boxShellConn{t: t, home: home, onStart: func() { takeMarker(t, home) }}
	_, err := sessionWith(conn).ProcessStart(context.Background(), "r", "claude -p hi", "", "")
	if !errors.Is(err, ErrSkillSetsApplyInProgress) {
		t.Fatalf("err = %v, want ErrSkillSetsApplyInProgress", err)
	}
	if !strings.Contains(err.Error(), "stopped") {
		t.Errorf("refusal %q does not say the started run was stopped", err)
	}
	if len(conn.kills) != 1 || conn.kills[0] != "r force=true" {
		t.Fatalf("process_kill calls = %v, want one forced kill of %q", conn.kills, "r")
	}
}

// A start time the box clock is behind, or absurdly far from, is not printed
// as a negative or meaningless "started ... ago".
func TestProcessStart_RefusalAgeIsSane(t *testing.T) {
	now := time.Now().Unix()
	for _, started := range []int64{now + 3600, 1, -5} {
		home := t.TempDir()
		writeMarker(t, home, fmt.Sprintf(`{"version":1,"started_at":%d,"expires_at":%d}`, started, now+300))
		_, err := sessionWith(&boxShellConn{t: t, home: home}).ProcessStart(context.Background(), "r", "x", "", "")
		if !errors.Is(err, ErrSkillSetsApplyInProgress) {
			t.Fatalf("started_at %d: err = %v", started, err)
		}
		if msg := err.Error(); strings.Contains(msg, " ago") {
			t.Errorf("started_at %d: refusal %q states an age it cannot know", started, msg)
		}
	}
}
