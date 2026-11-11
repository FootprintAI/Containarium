package mcp

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/client"
	"github.com/footprintai/containarium/internal/coderun"
)

// #3610: code_run starts its run through the function `containarium code run`
// starts its own through, not a copy of it.
func TestCodeRunTool_UsesTheCLIFunction(t *testing.T) {
	if reflect.ValueOf(startCodeRunFn).Pointer() != reflect.ValueOf(client.StartCodeRun).Pointer() {
		t.Error("startCodeRunFn is not client.StartCodeRun")
	}
}

type fakeMCPRunSession struct {
	result *coderun.ProcessStartResult
	got    []string
}

func (f *fakeMCPRunSession) ProcessStart(_ context.Context, name, command, cwd, captureMode string) (*coderun.ProcessStartResult, error) {
	f.got = []string{name, command, cwd, captureMode}
	return f.result, nil
}

// The tool hands the shared function its SSH session and no token: it has no
// way to select the daemon-API path.
func TestCodeRunTool_StartsWithoutAToken(t *testing.T) {
	orig := startCodeRunFn
	t.Cleanup(func() { startCodeRunFn = orig })

	sess := &fakeMCPRunSession{result: &coderun.ProcessStartResult{Name: "r", PID: 7, LogPath: "/l"}}
	var got client.CodeRunStart
	calls := 0
	startCodeRunFn = func(ctx context.Context, s client.CodeRunStart) (*client.CodeRunStarted, error) {
		calls++
		got = s
		return orig(ctx, s)
	}

	started, err := mcpStartCodeRun(context.Background(), sess, "r", "claude -p", "framed")
	if err != nil {
		t.Fatalf("mcpStartCodeRun: %v", err)
	}
	if calls != 1 {
		t.Fatalf("the shared function was called %d time(s), want 1", calls)
	}
	if got.RunToken != "" || got.Daemon != nil || got.Request != nil {
		t.Errorf("code_run selected the daemon-API path: %+v", got)
	}
	if got.Session != client.CodeRunSessionStarter(sess) || got.Name != "r" || got.Command != "claude -p" || got.CaptureMode != "framed" {
		t.Errorf("start = %+v", got)
	}
	if started != sess.result || strings.Join(sess.got, "|") != "r|claude -p||framed" {
		t.Errorf("started = %+v, ProcessStart got %q", started, sess.got)
	}
}

// A credential in tool arguments would sit in the model's context and in the
// MCP transcript: code_run takes no token, and no path to one.
func TestCodeRunSchema_HasNoTokenParameter(t *testing.T) {
	srv := &Server{}
	srv.registerTools()
	for _, tool := range srv.tools {
		if tool.Name != "code_run" {
			continue
		}
		props, ok := tool.InputSchema["properties"].(map[string]interface{})
		if !ok || len(props) == 0 {
			t.Fatalf("code_run has no properties: %v", tool.InputSchema)
		}
		for name := range props {
			if strings.Contains(strings.ToLower(name), "token") {
				t.Errorf("code_run has a token parameter: %q", name)
			}
		}
		if _, ok := props["prompt"]; !ok {
			t.Errorf("code_run parameters = %v, want prompt among them", props)
		}
		return
	}
	t.Fatal("code_run tool not found")
}
