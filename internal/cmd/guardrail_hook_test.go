package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/pflag"
	"google.golang.org/grpc"

	"github.com/footprintai/containarium/internal/guardrail"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// referenceEngineServer serves the in-tree reference engine over real gRPC,
// so the hook's --engine path is the one under test.
type referenceEngineServer struct {
	pb.UnimplementedGuardrailEngineServiceServer
}

func (referenceEngineServer) Scan(ctx context.Context, req *pb.GuardrailScanRequest) (*pb.GuardrailScanResponse, error) {
	return guardrail.RulesEngine{}.Scan(ctx, req)
}

// serveEngineOnSocket returns the path of a unix socket with the reference
// engine behind it. The directory is short on purpose: a socket path has a
// small length limit.
func serveEngineOnSocket(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "gh")
	must(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "e.sock")
	lis, err := net.Listen("unix", sock)
	must(t, err)
	srv := grpc.NewServer()
	pb.RegisterGuardrailEngineServiceServer(srv, referenceEngineServer{})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return sock
}

// runHook runs `containarium guardrail hook <args>` with stdin and returns
// what it printed and the exit status it asked for.
func runHook(t *testing.T, stdin string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	guardrailHookCmd.Flags().VisitAll(func(f *pflag.Flag) {
		_ = f.Value.Set(f.DefValue)
		f.Changed = false
	})
	t.Setenv("XDG_STATE_HOME", filepath.Join(t.TempDir(), "xdg"))
	prev := guardrailHookExit
	guardrailHookExit = func(c int) { code = c }
	defer func() { guardrailHookExit = prev }()
	var out, errb bytes.Buffer
	rootCmd.SetIn(strings.NewReader(stdin))
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&errb)
	rootCmd.SetArgs(append([]string{"guardrail", "hook"}, args...))
	defer rootCmd.SetArgs(nil)
	defer rootCmd.SetIn(nil)
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("the hook command reports through its exit status, not a cobra error: %v", err)
	}
	return out.String(), errb.String(), code
}

const hookSynthKey = "AKIAIOSFODNN7EXAMPLE" // the provider's documented example id

const hookBashResult = `{"session_id":"s","hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"cat .env"},` +
	`"tool_response":{"stdout":"AWS=` + hookSynthKey + `","stderr":"","interrupted":false,"isImage":false}}`

type hookStdout struct {
	HookSpecificOutput struct {
		PermissionDecision string `json:"permissionDecision"`
		UpdatedToolOutput  struct {
			Stdout      string `json:"stdout"`
			Interrupted *bool  `json:"interrupted"`
		} `json:"updatedToolOutput"`
	} `json:"hookSpecificOutput"`
}

func decodeHookStdout(t *testing.T, s string) hookStdout {
	t.Helper()
	var out hookStdout
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		t.Fatalf("stdout is not one JSON object: %q: %v", s, err)
	}
	return out
}

func TestGuardrailHook_RedactsThroughAnEngineOnALocalSocket(t *testing.T) {
	sock := serveEngineOnSocket(t)
	for _, addr := range []string{sock, "unix://" + sock, ""} {
		stdout, stderr, code := runHook(t, hookBashResult, "PostToolUse", "--engine", addr)
		if code != 0 {
			t.Fatalf("--engine %q: exit %d: %s", addr, code, stderr)
		}
		got := decodeHookStdout(t, stdout).HookSpecificOutput.UpdatedToolOutput
		if strings.Contains(stdout, hookSynthKey) || !strings.HasPrefix(got.Stdout, "AWS=[[AWS_ACCESS_KEY_ID:") {
			t.Errorf("--engine %q: stdout %q", addr, stdout)
		}
		if got.Interrupted == nil || *got.Interrupted {
			t.Errorf("--engine %q: the result's other fields must come back unchanged: %q", addr, stdout)
		}
	}
}

// Criterion: engine stopped -> PreToolUse denies. A denial is an answer, so
// the exit status is 0.
func TestGuardrailHook_PreToolUseDeniesWhenTheEngineIsStopped(t *testing.T) {
	dead := filepath.Join(t.TempDir(), "none.sock")
	in := `{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}`
	stdout, stderr, code := runHook(t, in, "PreToolUse", "--engine", dead, "--engine-wait", "200ms")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if d := decodeHookStdout(t, stdout).HookSpecificOutput.PermissionDecision; d != "deny" {
		t.Fatalf("want deny, got %q", stdout)
	}
	sock := serveEngineOnSocket(t)
	// With the engine up the call is not denied. (Bash is still rewritten by
	// the failed-command wrapper, #3765, so stdout is not empty.)
	stdout, _, code = runHook(t, in, "PreToolUse", "--engine", sock)
	if code != 0 || decodeHookStdout(t, stdout).HookSpecificOutput.PermissionDecision != "" {
		t.Errorf("with the engine up the call is not denied: exit %d stdout %q", code, stdout)
	}
}

// #3765: --wrap-failed-commands is on by default and rewrites a Bash command
// with the EXIT-trap prefix; =false leaves the call untouched.
func TestGuardrailHook_WrapFailedCommandsFlag(t *testing.T) {
	in := `{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"false"}}`
	stdout, stderr, code := runHook(t, in, "PreToolUse")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var out struct {
		HookSpecificOutput struct {
			UpdatedInput struct {
				Command string `json:"command"`
			} `json:"updatedInput"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("stdout is not one JSON object: %q: %v", stdout, err)
	}
	if cmd := out.HookSpecificOutput.UpdatedInput.Command; !strings.HasPrefix(cmd, "trap ") || !strings.HasSuffix(cmd, "\nfalse") {
		t.Fatalf("by default the command must be wrapped, got %q", cmd)
	}
	if stdout, _, code := runHook(t, in, "PreToolUse", "--wrap-failed-commands=false"); code != 0 || stdout != "" {
		t.Errorf("with the wrapper off the call passes untouched: exit %d stdout %q", code, stdout)
	}
}

// An internal error exits 2 with nothing on stdout. Exit 0 with unusable
// output would let the agent's action go ahead.
func TestGuardrailHook_InternalErrorExitsTwo(t *testing.T) {
	for name, tc := range map[string]struct {
		stdin string
		args  []string
	}{
		"invalid hook input": {`{"tool_name":`, []string{"PreToolUse"}},
		"unknown event":      {`{}`, []string{"NoSuchEvent"}},
		"no event":           {`{}`, nil},
		"remote engine":      {hookBashResult, []string{"PostToolUse", "--engine", "198.51.100.7:9090"}},
		"unknown flag":       {`{}`, []string{"PreToolUse", "--no-such-flag"}},
		"bad flag value":     {`{}`, []string{"PreToolUse", "--engine-wait", "soon"}},
		"prompt, engine down": {`{"session_id":"s","prompt":"hi"}`,
			[]string{"UserPromptSubmit", "--engine", filepath.Join(t.TempDir(), "none.sock"), "--scan-timeout", "200ms"}},
	} {
		stdout, stderr, code := runHook(t, tc.stdin, tc.args...)
		if code != 2 || stdout != "" || stderr == "" {
			t.Errorf("%s: exit %d stdout %q stderr %q; want exit 2, empty stdout and a message", name, code, stdout, stderr)
		}
	}
}

func TestGuardrailHook_StateLivesUnderXDGStateHome(t *testing.T) {
	_, stderr, code := runHook(t, hookBashResult, "PostToolUse")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	key := filepath.Join(os.Getenv("XDG_STATE_HOME"), "containarium-guardrail", "marker.key")
	info, err := os.Stat(key)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("marker key is %v, want 0600", info.Mode().Perm())
	}
}

// A relative --state-dir is made absolute against the hook's own working
// directory, so the state-directory deny compares like with like: an
// absolute path into that directory is refused.
func TestGuardrailHook_RelativeStateDirIsMadeAbsolute(t *testing.T) {
	work := t.TempDir()
	t.Chdir(work)
	target := filepath.Join(work, ".guardrail", "markers.jsonl")
	in := `{"session_id":"s","cwd":"/elsewhere","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":` +
		hookJSONString(target) + `}}`
	stdout, stderr, code := runHook(t, in, "PreToolUse", "--state-dir", ".guardrail")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if d := decodeHookStdout(t, stdout).HookSpecificOutput.PermissionDecision; d != "deny" {
		t.Fatalf("a read of the state directory must be denied: %q", stdout)
	}
}

func hookJSONString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}
