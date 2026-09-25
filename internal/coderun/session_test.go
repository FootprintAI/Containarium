package coderun

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
)

// These fixtures are agent-box's own output formats (internal/agentbox's
// handleProcessStart/handleTailLog/handleProcessKill Sprintf bodies) —
// kept in sync by hand since coderun deliberately doesn't import agentbox
// (a CLI-side package pulling in agent-box's exec/syscall internals for a
// string format would be the wrong coupling; the wire contract is text,
// not a shared Go type).

func TestParseKV_ProcessStartBody(t *testing.T) {
	body := "name: my-run\npid: 12345\ncommand: sleep 5\nlog_path: /tmp/agent-box/my-run.log\nstarted_at: 2026-09-02T12:00:00Z\n"
	kv, rest := parseKV(body, "")
	if rest != "" {
		t.Errorf("rest = %q, want empty (no content marker in this body)", rest)
	}
	want := map[string]string{
		"name": "my-run", "pid": "12345", "command": "sleep 5",
		"log_path": "/tmp/agent-box/my-run.log", "started_at": "2026-09-02T12:00:00Z",
	}
	for k, v := range want {
		if kv[k] != v {
			t.Errorf("kv[%q] = %q, want %q", k, kv[k], v)
		}
	}
}

func TestParseKV_TailLogBody_SeparatesHeaderFromContent(t *testing.T) {
	body := "path: /tmp/x.log\nstart_offset: 0\nend_offset: 11\nbytes_returned: 11\ntruncated: false\nfollow_seconds: 10\n--- content ---\nhello: not-a-header\nworld"
	kv, content := parseKV(body, tailLogContentMarker)
	if kv["end_offset"] != "11" {
		t.Errorf(`kv["end_offset"] = %q, want "11"`, kv["end_offset"])
	}
	if kv["truncated"] != "false" {
		t.Errorf(`kv["truncated"] = %q, want "false"`, kv["truncated"])
	}
	// "hello: not-a-header" must NOT be parsed as a kv pair — it's file
	// content that happens to look like one.
	if _, present := kv["hello"]; present {
		t.Error(`content line "hello: not-a-header" was parsed as a header key — content marker split failed`)
	}
	if content != "hello: not-a-header\nworld" {
		t.Errorf("content = %q, want the raw text after the marker verbatim", content)
	}
}

func TestParseKV_TailLogBody_EmptyContent(t *testing.T) {
	body := "path: /tmp/x.log\nstart_offset: 5\nend_offset: 5\nbytes_returned: 0\ntruncated: false\nfollow_seconds: 10\n--- content ---\n"
	kv, content := parseKV(body, tailLogContentMarker)
	if kv["start_offset"] != "5" || kv["end_offset"] != "5" {
		t.Errorf("kv = %+v", kv)
	}
	if content != "" {
		t.Errorf("content = %q, want empty", content)
	}
}

func TestParseKV_ProcessKillBody(t *testing.T) {
	body := "name: kill-me\npid: 999\nsignal: SIGTERM\nexited: true\nlog_path: /tmp/agent-box/kill-me.log\n"
	kv, _ := parseKV(body, "")
	if kv["signal"] != "SIGTERM" {
		t.Errorf(`kv["signal"] = %q, want "SIGTERM"`, kv["signal"])
	}
	if kv["exited"] != "true" {
		t.Errorf(`kv["exited"] = %q, want "true"`, kv["exited"])
	}
	pid, err := strconv.Atoi(kv["pid"])
	if err != nil || pid != 999 {
		t.Errorf("pid = %q (err=%v), want 999", kv["pid"], err)
	}
}

func TestParseKV_MarkerAbsentReturnsWholeBodyAsHead(t *testing.T) {
	body := "name: x\npid: 1\n"
	kv, rest := parseKV(body, tailLogContentMarker) // marker not actually present
	if rest != "" {
		t.Errorf("rest = %q, want empty when the marker never appears", rest)
	}
	if kv["name"] != "x" || kv["pid"] != "1" {
		t.Errorf("kv = %+v", kv)
	}
}

// fakeMCPConn stands in for the ssh-backed MCP client so dial()'s error
// classification can be exercised without a box. Initialize returns initErr;
// everything else is unused by these tests.
type fakeMCPConn struct {
	initErr error
	closed  bool
}

func (f *fakeMCPConn) Initialize(context.Context, mcp.InitializeRequest) (*mcp.InitializeResult, error) {
	return nil, f.initErr
}

func (f *fakeMCPConn) CallTool(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return nil, errors.New("not used")
}

func (f *fakeMCPConn) Close() error { f.closed = true; return nil }

// stubDial swaps the ssh-spawning dialer and the agent-box probe for the
// duration of a test, recording the argv the dialer was handed.
func stubDial(t *testing.T, conn mcpConn, dialErr error, probeErr error) *[]string {
	t.Helper()
	var got []string
	origDial, origProbe := dialMCP, probeAgentBox
	dialMCP = func(args []string) (mcpConn, error) {
		got = append([]string{}, args...)
		return conn, dialErr
	}
	probeAgentBox = func(context.Context, []string) error { return probeErr }
	t.Cleanup(func() { dialMCP, probeAgentBox = origDial, origProbe })
	return &got
}

// TestSessionDial_PathIncludesLocalBin pins the remote command `code run`
// spawns: a user-level install (`containarium code install` writes to
// ~/.local/bin, no root) is only reachable if the remote command puts that
// directory on PATH itself — a non-interactive `ssh host agent-box` does not
// get the box's login-shell PATH.
func TestSessionDial_PathIncludesLocalBin(t *testing.T) {
	got := stubDial(t, &fakeMCPConn{initErr: errors.New("transport closed")}, nil, nil)

	_, _ = Connect(context.Background(), []string{"-p", "22", "alice@example.test"})

	if len(*got) == 0 {
		t.Fatal("dialer was never called")
	}
	remote := (*got)[len(*got)-1]
	for _, want := range []string{`$HOME/.local/bin`, "/usr/local/bin", "exec agent-box", "sh -c"} {
		if !strings.Contains(remote, want) {
			t.Errorf("remote command %q is missing %q", remote, want)
		}
	}
	// The ssh flags the caller passed must still be handed through untouched.
	if (*got)[0] != "-p" || (*got)[2] != "alice@example.test" {
		t.Errorf("ssh args mangled: %v", *got)
	}
}

// TestSessionDial_MissingAgentBoxIsNamedError covers the #2030 AC: "`code
// run` on a box without `agent-box` refuses with a message naming the missing
// helper and `code install`, instead of the raw transport error."
func TestSessionDial_MissingAgentBoxIsNamedError(t *testing.T) {
	conn := &fakeMCPConn{initErr: errors.New("transport error: transport closed")}
	stubDial(t, conn, nil, errors.New("exit status 1"))

	_, err := Connect(context.Background(), []string{"alice@example.test"})
	if err == nil {
		t.Fatal("expected an error when agent-box is absent")
	}
	if !errors.Is(err, ErrAgentBoxMissing) {
		t.Fatalf("error %v does not wrap ErrAgentBoxMissing", err)
	}
	if !conn.closed {
		t.Error("the failed MCP connection was not closed")
	}

	named := AgentBoxMissingError("alice")
	if !errors.Is(named, ErrAgentBoxMissing) {
		t.Error("AgentBoxMissingError must wrap ErrAgentBoxMissing")
	}
	for _, want := range []string{"agent-box", "alice", "containarium code install alice"} {
		if !strings.Contains(named.Error(), want) {
			t.Errorf("named error %q is missing %q", named, want)
		}
	}
}

// TestSessionDial_ProbeSaysPresentKeepsTransportError is the other half: when
// agent-box IS installed, an init failure is a real transport fault and must
// not be mislabelled as a missing helper.
func TestSessionDial_ProbeSaysPresentKeepsTransportError(t *testing.T) {
	stubDial(t, &fakeMCPConn{initErr: errors.New("transport error: transport closed")}, nil, nil)

	_, err := Connect(context.Background(), []string{"alice@example.test"})
	if err == nil {
		t.Fatal("expected an error")
	}
	if errors.Is(err, ErrAgentBoxMissing) {
		t.Errorf("a transport fault on a box that HAS agent-box was reported as missing: %v", err)
	}
	if !strings.Contains(err.Error(), "initialize MCP session") {
		t.Errorf("error lost the underlying cause: %v", err)
	}
}
