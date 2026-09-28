package coderun

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
)

// scriptedConn answers each tool call from a per-tool canned reply and records
// the arguments it was handed, so a test can assert on what `code run` actually
// asked the box to do.
type scriptedConn struct {
	replies map[string]string
	errs    map[string]error
	calls   []scriptedCall
}

type scriptedCall struct {
	tool string
	args map[string]any
}

func (c *scriptedConn) Initialize(context.Context, mcp.InitializeRequest) (*mcp.InitializeResult, error) {
	return &mcp.InitializeResult{}, nil
}

func (c *scriptedConn) CallTool(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	name := req.Params.Name
	args, _ := req.Params.Arguments.(map[string]any)
	c.calls = append(c.calls, scriptedCall{tool: name, args: args})
	if err, ok := c.errs[name]; ok {
		return nil, err
	}
	reply, ok := c.replies[name]
	if !ok {
		return nil, errors.New("scriptedConn: no reply for " + name)
	}
	return &mcp.CallToolResult{Content: []mcp.Content{mcp.TextContent{Type: "text", Text: reply}}}, nil
}

func (c *scriptedConn) Close() error { return nil }

func (c *scriptedConn) call(tool string) (map[string]any, bool) {
	for _, got := range c.calls {
		if got.tool == tool {
			return got.args, true
		}
	}
	return nil, false
}

// sessionWith builds a Session over conn without any ssh involved.
func sessionWith(conn mcpConn) *Session {
	return &Session{mcp: conn}
}

func TestExpandHome(t *testing.T) {
	tests := []struct{ in, want string }{
		{"$HOME/.pi/gateway.env", "/home/alice/.pi/gateway.env"},
		{"$HOME/.containarium/code.json", "/home/alice/.containarium/code.json"},
		{"$HOME", "/home/alice"},
		{"~/.pi/gateway.env", "/home/alice/.pi/gateway.env"},
		// Already absolute, and not home-rooted: left alone.
		{"/run/containarium/secrets.env", "/run/containarium/secrets.env"},
		// A path that merely CONTAINS $HOME later on is not rewritten — only a
		// prefix is a home reference.
		{"/etc/$HOME/weird", "/etc/$HOME/weird"},
	}
	for _, tc := range tests {
		if got := ExpandHome("/home/alice", tc.in); got != tc.want {
			t.Errorf("ExpandHome(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSessionHomeDir(t *testing.T) {
	conn := &scriptedConn{replies: map[string]string{
		"shell_exec": "exit_code: 0\nstdout_bytes: 12\nstderr_bytes: 0\n--- stdout ---\n/home/alice\n",
	}}
	home, err := sessionWith(conn).HomeDir(context.Background())
	if err != nil {
		t.Fatalf("HomeDir: %v", err)
	}
	if home != "/home/alice" {
		t.Errorf("HomeDir = %q, want /home/alice", home)
	}
	// It must not have leaked anything into a command line beyond reading $HOME.
	args, ok := conn.call("shell_exec")
	if !ok {
		t.Fatal("shell_exec was never called")
	}
	if cmd, _ := args["command"].(string); !strings.Contains(cmd, "$HOME") {
		t.Errorf("shell_exec command = %q, want a $HOME read", cmd)
	}
}

func TestSessionReadFile(t *testing.T) {
	const cfg = "{\n  \"version\": 1,\n  \"engine\": \"pi\"\n}\n"
	conn := &scriptedConn{replies: map[string]string{
		"read_file": "path: /home/alice/.containarium/code.json\nsize: 40\noffset: 0\nbytes_returned: 40\ntruncated: false\n--- content ---\n" + cfg,
	}}
	got, err := sessionWith(conn).ReadFile(context.Background(), "/home/alice/.containarium/code.json")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if got != cfg {
		t.Errorf("ReadFile = %q, want %q", got, cfg)
	}
}

// TestSessionWriteFile_GatewayEnvIs0600AndNeverOnACommandLine is the security
// property of the gateway.env write: the token goes in as an MCP argument with
// mode 0600, never as part of a shell command.
//
// A shell_exec `printf ... > file` would put the token in the box's process
// table for the life of the call — the exact hazard docs/integrations/pi.md
// opens by warning about.
func TestSessionWriteFile_GatewayEnvIs0600AndNeverOnACommandLine(t *testing.T) {
	const token = "gw-token-abc123"
	content := "export CONTAINARIUM_MODEL_GATEWAY_URL=http://10.0.0.1:8866/v1/model/kafeido\n" +
		"export CONTAINARIUM_GATEWAY_TOKEN=" + token + "\n"

	conn := &scriptedConn{replies: map[string]string{
		"write_file": "path: /home/alice/.pi/gateway.env\nbytes_written: 120\nmode: 0600\n",
	}}
	err := sessionWith(conn).WriteFile(context.Background(),
		"/home/alice/.pi/gateway.env", content, GatewayEnvFileMode)
	if err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	args, ok := conn.call("write_file")
	if !ok {
		t.Fatal("write_file was never called")
	}
	if args["mode"] != "0600" {
		t.Errorf("mode = %v, want 0600", args["mode"])
	}
	if args["content"] != content {
		t.Errorf("content was not passed through verbatim")
	}
	// No shell_exec at all on this path: the token must never be an argv element.
	for _, got := range conn.calls {
		if got.tool == "shell_exec" {
			cmd, _ := got.args["command"].(string)
			if strings.Contains(cmd, token) {
				t.Errorf("the token reached a shell command line: %q", cmd)
			}
		}
	}
}

// TestSessionWriteFile_FailedWriteIsNotSilent: agent-box reports tool-level
// failures as TEXT with no transport error, so a wrapper that ignored the reply
// would let a failed credential write look like success — and the run would
// start with no credential, failing later and somewhere else.
func TestSessionWriteFile_FailedWriteIsNotSilent(t *testing.T) {
	conn := &scriptedConn{replies: map[string]string{
		"write_file": "write_file: path \"/home/alice/.pi/gateway.env\" is outside AGENTBOX_ROOT (/workspace)",
	}}
	err := sessionWith(conn).WriteFile(context.Background(),
		"/home/alice/.pi/gateway.env", "export X=1\n", GatewayEnvFileMode)
	if err == nil {
		t.Fatal("a refused write was reported as success")
	}
	if !strings.Contains(err.Error(), "AGENTBOX_ROOT") {
		t.Errorf("error should carry agent-box's own reason, got: %v", err)
	}
}

func TestSessionReadFile_MissingMarkerIsAnError(t *testing.T) {
	conn := &scriptedConn{replies: map[string]string{
		"read_file": "read_file: open /home/alice/.containarium/code.json: no such file or directory",
	}}
	_, err := sessionWith(conn).ReadFile(context.Background(), "/home/alice/.containarium/code.json")
	if err == nil {
		t.Fatal("a failed read was reported as success")
	}
}

// TestSessionReadFile_ClassifiesNotFound is load-bearing well beyond this
// package: `code run` falls back to the pre-#1727 Claude + tenant-secret default
// when a box has no code.json, so "absent" and "could not be read" MUST be
// distinguishable.
//
// Conflating them means a transport blip or a permission error on a pi/gateway
// box silently runs the WRONG engine on the WRONG credential and hides the real
// failure. Only a confirmed ENOENT may read as absent.
func TestSessionReadFile_ClassifiesNotFound(t *testing.T) {
	tests := []struct {
		name       string
		reply      string
		callErr    error
		wantAbsent bool
	}{
		{
			name:       "missing file, from os.Stat",
			reply:      "read_file: stat /home/alice/.containarium/code.json: no such file or directory",
			wantAbsent: true,
		},
		{
			name:       "missing file, from os.Open",
			reply:      "read_file: open /home/alice/.containarium/code.json: no such file or directory",
			wantAbsent: true,
		},
		{
			// Everything below is a FAILURE to read, not an absence.
			name:       "permission denied",
			reply:      "read_file: open /home/alice/.containarium/code.json: permission denied",
			wantAbsent: false,
		},
		{
			name:       "outside the sandbox root",
			reply:      `read_file: path "/home/alice/.containarium/code.json" is outside AGENTBOX_ROOT (/workspace)`,
			wantAbsent: false,
		},
		{
			name:       "it is a directory",
			reply:      "read_file: /home/alice/.containarium/code.json is a directory (use list_directory)",
			wantAbsent: false,
		},
		{
			name:       "transport died",
			callErr:    errors.New("transport closed: EOF"),
			wantAbsent: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conn := &scriptedConn{
				replies: map[string]string{"read_file": tc.reply},
				errs:    map[string]error{},
			}
			if tc.callErr != nil {
				conn.errs["read_file"] = tc.callErr
			}
			_, err := sessionWith(conn).ReadFile(context.Background(), "/home/alice/.containarium/code.json")
			if err == nil {
				t.Fatal("expected an error")
			}
			if got := errors.Is(err, ErrFileNotFound); got != tc.wantAbsent {
				t.Errorf("errors.Is(err, ErrFileNotFound) = %v, want %v (err: %v)", got, tc.wantAbsent, err)
			}
			// Whichever it is, agent-box's own reason must survive for the user.
			if tc.reply != "" && !strings.Contains(err.Error(), "code.json") {
				t.Errorf("error lost the path: %v", err)
			}
		})
	}
}
