package coderun

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
)

// tailLogContentMarker is tail_log's own literal separator between its
// key:value header and raw file content (internal/agentbox/tail_log.go).
const tailLogContentMarker = "--- content ---\n"

// Session is a live MCP connection to one box's agent-box, reached the same
// way any MCP client (Claude Code, Claude Desktop) reaches it: spawn
// `ssh <sshArgs...> -- agent-box` as a subprocess and speak MCP over its
// stdio (docs/K8S-AGENT-BOX-RUNTIME-DESIGN.md). Implements LogReader
// directly, transparently reconnecting once on a transport-level failure
// (a dropped SSH connection) before surfacing an error — StreamOutput's own
// retry loop is the second line of defense for anything that doesn't
// self-heal on one reconnect attempt.
type Session struct {
	sshArgs []string // ssh's own flags/target; "agent-box" is appended as the remote command

	mu  sync.Mutex
	mcp *client.Client
}

// Connect spawns ssh with sshArgs (host/user/identity/port flags — NOT
// including a remote command) plus "agent-box" appended as the remote
// command, and initializes an MCP session over its stdio.
func Connect(ctx context.Context, sshArgs []string) (*Session, error) {
	s := &Session{sshArgs: sshArgs}
	c, err := s.dial(ctx)
	if err != nil {
		return nil, err
	}
	s.mcp = c
	return s, nil
}

func (s *Session) dial(ctx context.Context) (*client.Client, error) {
	args := append(append([]string{}, s.sshArgs...), "agent-box")
	// #nosec G204 -- sshArgs is built by the CLI command from a
	// daemon-resolved target + validated flags, the same construction
	// connectcore.BuildSSHArgs already uses for `connect`/`code install`;
	// "agent-box" is a fixed literal, never caller input.
	c, err := client.NewStdioMCPClient("ssh", nil, args...)
	if err != nil {
		return nil, fmt.Errorf("start agent-box over ssh: %w", err)
	}
	initReq := mcp.InitializeRequest{}
	initReq.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	initReq.Params.ClientInfo = mcp.Implementation{Name: "containarium-code", Version: "1"}
	if _, err := c.Initialize(ctx, initReq); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("initialize MCP session: %w", err)
	}
	return c, nil
}

// Close ends the underlying ssh subprocess and MCP session.
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mcp.Close()
}

// callTool invokes name with args and returns its concatenated text
// content. reconnect=true retries once over a freshly-dialed session on
// any error (transport-level failures — a dead ssh subprocess, a closed
// pipe — look identical to a tool-level error at this layer, so the retry
// is harmless when it wasn't actually a transport failure: a genuine
// application error simply repeats).
func (s *Session) callTool(ctx context.Context, name string, args map[string]any, reconnect bool) (string, error) {
	s.mu.Lock()
	c := s.mcp
	s.mu.Unlock()

	text, err := doCallTool(ctx, c, name, args)
	if err == nil || !reconnect {
		return text, err
	}

	fresh, dialErr := s.dial(ctx)
	if dialErr != nil {
		return "", fmt.Errorf("%v (reconnect also failed: %w)", err, dialErr)
	}
	s.mu.Lock()
	_ = s.mcp.Close()
	s.mcp = fresh
	s.mu.Unlock()

	return doCallTool(ctx, fresh, name, args)
}

func doCallTool(ctx context.Context, c *client.Client, name string, args map[string]any) (string, error) {
	res, err := c.CallTool(ctx, mcp.CallToolRequest{Params: mcp.CallToolParams{Name: name, Arguments: args}})
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	for _, content := range res.Content {
		if tc, ok := content.(mcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	text := sb.String()
	if res.IsError {
		return "", fmt.Errorf("%s", strings.TrimSpace(text))
	}
	return text, nil
}

// parseKV splits agent-box's plain-text "key: value\n" tool-result
// convention into a map. When marker is non-empty and present in body
// (tail_log's "--- content ---\n" separator), only the text before it is
// parsed as key:value pairs; everything after is returned separately as
// raw content, since it is arbitrary file bytes, not more header lines.
func parseKV(body, marker string) (kv map[string]string, rest string) {
	head := body
	if marker != "" {
		if idx := strings.Index(body, marker); idx >= 0 {
			head = body[:idx]
			rest = body[idx+len(marker):]
		}
	}
	kv = make(map[string]string)
	for _, line := range strings.Split(head, "\n") {
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, ": ")
		if !ok {
			continue
		}
		kv[k] = v
	}
	return kv, rest
}

// ProcessStartResult is process_start's response, typed (per CLAUDE.md)
// from agent-box's plain-text body.
type ProcessStartResult struct {
	Name, Command, LogPath string
	PID                    int
	StartedAt              time.Time
}

// ProcessStart spawns command on the box. captureMode is "combined" or
// "framed" ("" defaults to "combined", matching process_start's own
// default) — see internal/agentbox's CaptureMode for what each means.
func (s *Session) ProcessStart(ctx context.Context, name, command, cwd, captureMode string) (*ProcessStartResult, error) {
	args := map[string]any{"command": command}
	if name != "" {
		args["name"] = name
	}
	if cwd != "" {
		args["cwd"] = cwd
	}
	if captureMode != "" {
		args["capture_mode"] = captureMode
	}
	text, err := s.callTool(ctx, "process_start", args, true)
	if err != nil {
		return nil, fmt.Errorf("process_start: %w", err)
	}
	kv, _ := parseKV(text, "")
	pid, _ := strconv.Atoi(kv["pid"])
	startedAt, _ := time.Parse(time.RFC3339, kv["started_at"])
	return &ProcessStartResult{
		Name: kv["name"], Command: kv["command"], LogPath: kv["log_path"],
		PID: pid, StartedAt: startedAt,
	}, nil
}

// Read implements LogReader by calling tail_log. followSeconds bounds how
// long the SERVER blocks polling for new content before returning — most
// of StreamOutput's "streaming" feel comes from this blocking, not from
// polling frequency on the client side.
func (s *Session) Read(ctx context.Context, path string, startOffset int64, follow time.Duration) ([]byte, int64, bool, error) {
	args := map[string]any{
		"path":           path,
		"start_offset":   float64(startOffset),
		"follow_seconds": follow.Seconds(),
	}
	text, err := s.callTool(ctx, "tail_log", args, true)
	if err != nil {
		return nil, startOffset, false, fmt.Errorf("tail_log: %w", err)
	}
	kv, content := parseKV(text, tailLogContentMarker)
	end, _ := strconv.ParseInt(kv["end_offset"], 10, 64)
	truncated := kv["truncated"] == "true"
	return []byte(content), end, truncated, nil
}

// ProcessKillResult is process_kill's response, typed from agent-box's
// plain-text body.
type ProcessKillResult struct {
	Name, Signal, LogPath string
	PID                   int
	Exited                bool
}

// ProcessKill stops name on the box.
func (s *Session) ProcessKill(ctx context.Context, name string, force bool) (*ProcessKillResult, error) {
	text, err := s.callTool(ctx, "process_kill", map[string]any{"name": name, "force": force}, true)
	if err != nil {
		return nil, fmt.Errorf("process_kill: %w", err)
	}
	kv, _ := parseKV(text, "")
	pid, _ := strconv.Atoi(kv["pid"])
	return &ProcessKillResult{
		Name: kv["name"], Signal: kv["signal"], LogPath: kv["log_path"],
		PID: pid, Exited: kv["exited"] == "true",
	}, nil
}

// ProcessList returns process_list's raw text body — a multi-process
// listing agent-box formats for humans, not single-record key:value pairs.
// Callers that need one run's status (containarium code status) grep this
// for the run's own block rather than this package re-parsing agent-box's
// display format into a second, redundant typed shape.
func (s *Session) ProcessList(ctx context.Context) (string, error) {
	text, err := s.callTool(ctx, "process_list", nil, true)
	if err != nil {
		return "", fmt.Errorf("process_list: %w", err)
	}
	return text, nil
}
