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
}

func (c *boxShellConn) Initialize(context.Context, mcp.InitializeRequest) (*mcp.InitializeResult, error) {
	return &mcp.InitializeResult{}, nil
}

func (c *boxShellConn) CallTool(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args, _ := req.Params.Arguments.(map[string]any)
	var reply string
	switch req.Params.Name {
	case "shell_exec":
		reply = boxShellExecForTest(c.home, args["command"].(string))
	case "process_start":
		c.starts++
		reply = "name: r\npid: 42\ncommand: x\nlog_path: /tmp/r.log\nstarted_at: 2026-11-04T00:00:00Z\n"
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
