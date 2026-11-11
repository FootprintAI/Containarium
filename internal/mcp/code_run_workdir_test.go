package mcp

import (
	"context"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/client"
	"github.com/footprintai/containarium/internal/coderun"
)

// #3613: code_run takes a workdir, with the rule and the check `code run
// --workdir` uses (coderun.CleanHomeRelPath, coderun.Session.ResolveWorkdir).

// A non-canonical workdir is refused before the tool resolves or connects to
// the box: this test has no API client, so a call that went on would panic.
func TestCodeRunTool_NonCanonicalWorkdirIsRefusedBeforeConnecting(t *testing.T) {
	for _, bad := range []string{"/etc", "..", "../x", ".", "a/", ".containarium", "a\x00b"} {
		_, err := handleCodeRun(nil, map[string]interface{}{"box": "alice", "prompt": "fix the bug", "workdir": bad})
		if err == nil || !strings.HasPrefix(err.Error(), "`workdir` ") {
			t.Errorf("workdir %q: err = %v, want a `workdir` refusal", bad, err)
		}
	}
}

// A workdir that is present but not a string is refused, not read as the home.
func TestCodeRunTool_NonStringWorkdirIsRefused(t *testing.T) {
	for _, bad := range []interface{}{42, true, []interface{}{"a"}, map[string]interface{}{}} {
		_, err := handleCodeRun(nil, map[string]interface{}{"box": "alice", "prompt": "fix the bug", "workdir": bad})
		if err == nil || !strings.Contains(err.Error(), "`workdir` must be a string") {
			t.Errorf("workdir %v: err = %v, want a type refusal", bad, err)
		}
	}
}

// The resolved directory reaches process_start as its cwd, through the shared
// start function.
func TestCodeRunTool_StartsInTheResolvedWorkdir(t *testing.T) {
	orig := startCodeRunFn
	t.Cleanup(func() { startCodeRunFn = orig })
	var got client.CodeRunStart
	startCodeRunFn = func(ctx context.Context, s client.CodeRunStart) (*client.CodeRunStarted, error) {
		got = s
		return orig(ctx, s)
	}

	sess := &fakeMCPRunSession{result: &coderun.ProcessStartResult{Name: "r", PID: 7, LogPath: "/l"}}
	if _, err := mcpStartCodeRun(context.Background(), sess, "r", "claude -p", "/home/alice/project", "combined"); err != nil {
		t.Fatalf("mcpStartCodeRun: %v", err)
	}
	if got.Cwd != "/home/alice/project" || strings.Join(sess.got, "|") != "r|claude -p|/home/alice/project|combined" {
		t.Errorf("start = %+v, ProcessStart got %q", got, sess.got)
	}
}

func TestCodeRunSchema_HasWorkdir(t *testing.T) {
	srv := &Server{}
	srv.registerTools()
	for _, tool := range srv.tools {
		if tool.Name != "code_run" {
			continue
		}
		props, _ := tool.InputSchema["properties"].(map[string]interface{})
		wd, ok := props["workdir"].(map[string]interface{})
		if !ok || wd["type"] != "string" {
			t.Fatalf("code_run workdir property = %v, want a string", props["workdir"])
		}
		for _, req := range tool.InputSchema["required"].([]string) {
			if req == "workdir" {
				t.Error("workdir is required; it is optional (default: the home)")
			}
		}
		return
	}
	t.Fatal("code_run tool not found")
}
