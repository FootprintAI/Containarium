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
	// shellCalls counts shell_exec calls; from failShellFrom on (1-based, 0
	// never) each one exits 1 with shellStderr as its stderr.
	shellCalls, failShellFrom int
	shellStderr               string
	// killErr, when set, makes process_kill fail with it.
	killErr string
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
		c.shellCalls++
		if c.failShellFrom > 0 && c.shellCalls >= c.failShellFrom {
			reply = "exit_code: 1\ntimeout_seconds: 30\n--- stdout ---\n\n--- stderr ---\n" + c.shellStderr
			break
		}
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
		if c.killErr != "" {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{mcp.TextContent{Type: "text", Text: c.killErr}}}, nil
		}
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

// #3540: a directory, or a symlink to one, at the marker path is a stale
// marker like any other: it is removed and the run starts with a warning,
// and the symlink's target is left alone.
func TestProcessStart_ADirectoryAtTheMarkerPathIsClearedAndTheRunStarts(t *testing.T) {
	for _, tc := range []struct {
		name    string
		symlink bool
	}{{"directory", false}, {"symlink to a directory", true}} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			outside := filepath.Join(home, "outside")
			for _, d := range []string{outside, filepath.Dir(markerPath(home))} {
				if err := os.MkdirAll(d, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if tc.symlink {
				if err := os.Symlink(outside, markerPath(home)); err != nil {
					t.Fatal(err)
				}
			} else if err := os.MkdirAll(filepath.Join(markerPath(home), "sub"), 0o755); err != nil {
				t.Fatal(err)
			}
			conn := &boxShellConn{t: t, home: home}
			started, err := sessionWith(conn).ProcessStart(context.Background(), "r", "claude -p hi", "", "")
			if err != nil {
				t.Fatalf("a directory at the marker path must not refuse the run: %v", err)
			}
			if conn.starts != 1 || !strings.Contains(started.Warning, "cleared a stale skill-set apply marker") {
				t.Fatalf("starts = %d, warning = %q; want one start with the stale-clear warning", conn.starts, started.Warning)
			}
			if _, err := os.Lstat(markerPath(home)); !os.IsNotExist(err) {
				t.Fatalf("the marker path must be cleared: lstat err = %v", err)
			}
			if _, err := os.Stat(outside); err != nil {
				t.Fatalf("a directory outside the marker path must survive: %v", err)
			}
		})
	}
}

// #3540: a stale marker the box user cannot remove refuses the run with what
// is wrong and what to do, not as an apply in progress.
func TestProcessStart_AMarkerThatCannotBeClearedRefusesWithTheRealCause(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes a read-only directory")
	}
	home := t.TempDir()
	writeMarker(t, home, "junk")
	skills := filepath.Dir(markerPath(home))
	if err := os.Chmod(skills, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(skills, 0o755) })
	conn := &boxShellConn{t: t, home: home}
	_, err := sessionWith(conn).ProcessStart(context.Background(), "r", "claude -p hi", "", "")
	if !errors.Is(err, ErrSkillSetsApplyMarkerNotCleared) {
		t.Fatalf("err = %v, want ErrSkillSetsApplyMarkerNotCleared", err)
	}
	if errors.Is(err, ErrSkillSetsApplyInProgress) {
		t.Fatalf("refusal %q reads as an apply in progress; none is", err)
	}
	if msg := err.Error(); !strings.Contains(msg, sdlcskills.ApplyMarkerFile) || !strings.Contains(msg, "remove it by hand") {
		t.Errorf("refusal %q does not name the path and the fix", msg)
	}
	if conn.starts != 0 {
		t.Fatalf("process_start called %d time(s)", conn.starts)
	}
}

// #3540 (a surviving mutation of #3539): a stale marker replaced by another
// stale one on every pass is given up on after three passes, refused as an
// apply in progress that will settle, never looped on.
func TestProcessStart_GivesUpAfterThreeReplacedStaleMarkers(t *testing.T) {
	home := t.TempDir()
	writeMarker(t, home, `{"version":1,"started_at":1,"expires_at":2}`)
	clears := 0
	conn := &boxShellConn{t: t, home: home}
	conn.beforeClear = func() {
		clears++
		// Another stale marker under a new inode, as a rename would leave.
		tmp := markerPath(home) + ".other"
		if err := os.WriteFile(tmp, []byte(fmt.Sprintf(`{"version":1,"started_at":1,"expires_at":%d}`, 2+clears)), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, markerPath(home)); err != nil {
			t.Fatal(err)
		}
	}
	_, err := sessionWith(conn).ProcessStart(context.Background(), "r", "claude -p hi", "", "")
	if !errors.Is(err, ErrSkillSetsApplyInProgress) || !strings.Contains(err.Error(), "kept changing") {
		t.Fatalf("err = %v, want the kept-changing refusal", err)
	}
	if clears != 3 {
		t.Fatalf("clear attempts = %d, want 3", clears)
	}
	if conn.starts != 0 {
		t.Fatalf("process_start called %d time(s)", conn.starts)
	}
}

// #3540 (a surviving mutation of #3539): the check after the start cannot
// run, so the run keeps going and the start says so, in a fixed message that
// does not carry the box's stderr to the caller.
func TestProcessStart_AFailedRecheckKeepsTheRunWithAWarning(t *testing.T) {
	home := t.TempDir()
	// shell_exec #1 is the check before the start, #2 the re-check after it.
	conn := &boxShellConn{t: t, home: home, failShellFrom: 2, shellStderr: "\x1b[31mtenant-controlled text\x1b[0m"}
	started, err := sessionWith(conn).ProcessStart(context.Background(), "r", "claude -p hi", "", "")
	if err != nil {
		t.Fatalf("a re-check that cannot run must not refuse a started run: %v", err)
	}
	if conn.starts != 1 || len(conn.kills) != 0 {
		t.Fatalf("starts = %d, kills = %v; want the run started and not stopped", conn.starts, conn.kills)
	}
	if !strings.Contains(started.Warning, "could not re-check for a skill-set apply after the start") {
		t.Fatalf("warning = %q, want the re-check note", started.Warning)
	}
	if strings.Contains(started.Warning, "tenant-controlled") || strings.Contains(started.Warning, "\x1b") {
		t.Fatalf("warning %q carries the box's stderr", started.Warning)
	}
}

// #3540: when the run that had just started under a new apply's marker cannot
// be stopped, the refusal says so and names the run, so the caller can stop
// it.
func TestProcessStart_AFailedKillIsReportedWithTheRunName(t *testing.T) {
	stubDial(t, nil, errors.New("no reconnect in this test"), nil)
	home := t.TempDir()
	conn := &boxShellConn{t: t, home: home, onStart: func() { takeMarker(t, home) }, killErr: "no such run"}
	_, err := sessionWith(conn).ProcessStart(context.Background(), "r", "claude -p hi", "", "")
	if !errors.Is(err, ErrSkillSetsApplyInProgress) {
		t.Fatalf("err = %v, want ErrSkillSetsApplyInProgress", err)
	}
	if msg := err.Error(); !strings.Contains(msg, `the run "r" had just started and could not be stopped`) {
		t.Fatalf("refusal %q does not say the run could not be stopped", msg)
	}
	if len(conn.kills) == 0 || conn.kills[0] != "r force=true" {
		t.Fatalf("process_kill calls = %v, want a forced kill of %q", conn.kills, "r")
	}
}
