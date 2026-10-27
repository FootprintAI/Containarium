//go:build !windows

package agentbox

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/footprintai/containarium/internal/coderun"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// `agent-box approval-mcp` (#2183): the permission-prompt tool behind
// `code run --approvals ask`.
//
// Claude Code starts it as a stdio MCP server (--mcp-config) and calls its one
// tool for every tool call that needs a permission (--permission-prompt-tool).
// The call blocks until a signed answer arrives or the request expires into a
// deny, and every step is journaled to <name>.input.jsonl.
//
// Why answers are signed: the agent runs as the same Unix user as anyone
// answering on the box, so any file an answerer can write, the agent can write
// too. The run's key is held only in this process's memory — read from the
// key file and unlinked before the MCP handshake completes, which Claude Code
// waits for before the agent's first turn — and the process is made
// non-dumpable, so a non-root process the agent starts can neither read the key
// file nor this process's memory. Root on the box (box users have sudo) is out
// of reach of any same-box scheme and is not claimed.

// ApprovalToolName is the tool Claude Code's --permission-prompt-tool names,
// as mcp__<server>__<tool>.
const ApprovalToolName = "approve"

// ApprovalServerName is the MCP server key the run's --mcp-config uses.
const ApprovalServerName = "containarium-approval"

// approvalPollInterval is how often a waiting request looks for its answer.
const approvalPollInterval = 500 * time.Millisecond

// approvalProgressInterval keeps Claude Code's stdio idle timer (30 min by
// default) from firing while a request waits.
const approvalProgressInterval = 30 * time.Second

// approvalProbeOK is what `approval-mcp --probe` prints, so `code run` can
// tell an agent-box that has this mode from an older one before it starts a
// run that would otherwise fail to connect its permission tool.
const approvalProbeOK = "approval-mcp ok"

// approvalPromptMax caps the human-readable prompt journaled per request.
const approvalPromptMax = 500

// approvalServer is one run's approval channel.
type approvalServer struct {
	run     string
	dir     string
	timeout time.Duration
	key     []byte // nil: no key was delivered, nothing can answer

	now          func() time.Time
	pollInterval time.Duration

	mu sync.Mutex // serializes journal appends
}

// RunApprovalCLI is `agent-box approval-mcp --run <name> [--timeout d] [--dir d]`.
func RunApprovalCLI(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("approval-mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	run := fs.String("run", "", "run name whose permission requests this serves (required)")
	timeout := fs.Duration("timeout", coderun.DefaultApprovalTimeout, "how long a request waits before it expires into a deny")
	dir := fs.String("dir", DefaultLogDir, "run log directory")
	probe := fs.Bool("probe", false, "print a readiness line and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *probe {
		fmt.Fprintln(stdout, approvalProbeOK)
		return 0
	}
	if *run == "" || strings.ContainsAny(*run, "/\x00") {
		fmt.Fprintln(stderr, "approval-mcp: --run is required and must be a plain run name")
		return 2
	}
	if *timeout <= 0 {
		fmt.Fprintln(stderr, "approval-mcp: --timeout must be positive")
		return 2
	}

	// Before the key is read, so it never sits in a dumpable process.
	if err := makeNonDumpable(); err != nil {
		log.Printf("[approval-mcp] could not make the process non-dumpable: %v", err)
	}

	s := &approvalServer{run: *run, dir: *dir, timeout: *timeout, now: time.Now, pollInterval: approvalPollInterval}
	s.loadKey()

	mcpServer := server.NewMCPServer(ApprovalServerName, "1", server.WithToolCapabilities(false))
	mcpServer.AddTool(approvalTool(), s.handleApprove)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := server.NewStdioServer(mcpServer).Listen(ctx, stdin, stdout); err != nil && !errors.Is(err, context.Canceled) {
		log.Printf("[approval-mcp] stdio serve error: %v", err)
		return 1
	}
	return 0
}

func approvalTool() mcp.Tool {
	return mcp.NewTool(
		ApprovalToolName,
		mcp.WithDescription("Permission prompt for a containarium code run. Called by Claude Code, not by the agent."),
		mcp.WithString("tool_name", mcp.Description("Tool the agent wants to use.")),
		mcp.WithObject("input", mcp.Description("That tool's input.")),
		mcp.WithString("tool_use_id", mcp.Description("Claude Code's id for the tool call.")),
	)
}

func (s *approvalServer) keyPath() string     { return filepath.Join(s.dir, s.run+".approval-key") }
func (s *approvalServer) journalPath() string { return filepath.Join(s.dir, s.run+".input.jsonl") }
func (s *approvalServer) answerPath(id string) string {
	return filepath.Join(s.dir, s.run+".answers", id)
}

// loadKey reads the run's key and unlinks it. A missing or malformed key is
// journaled, and every request is then denied at once: waiting would only
// delay a deny nobody can override.
func (s *approvalServer) loadKey() {
	path := s.keyPath()
	raw, err := os.ReadFile(path)
	_ = os.Remove(path)
	if err != nil {
		s.journal(coderun.InputEvent{Kind: coderun.KindInputStatus,
			Text: "no approval key was delivered to this run; every permission request is denied"})
		return
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) != coderun.ApprovalKeyBytes {
		s.journal(coderun.InputEvent{Kind: coderun.KindInputStatus,
			Text: "the approval key delivered to this run is malformed; every permission request is denied"})
		return
	}
	s.key = key
}

// journal appends one line. O_APPEND with one write per line keeps lines whole
// for concurrent readers.
func (s *approvalServer) journal(e coderun.InputEvent) {
	if e.T.IsZero() {
		e.T = s.now().UTC()
	}
	line, err := e.MarshalLine()
	if err != nil {
		log.Printf("[approval-mcp] marshal journal line: %v", err)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.OpenFile(s.journalPath(), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		log.Printf("[approval-mcp] open journal: %v", err)
		return
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(line); err != nil {
		log.Printf("[approval-mcp] write journal: %v", err)
	}
}

// promptInput is the permission-prompt tool's arguments, as Claude Code sends
// them (verified on Claude Code 2.1.311: tool_name, input, tool_use_id).
type promptInput struct {
	ToolName  string          `json:"tool_name"`
	Input     json.RawMessage `json:"input"`
	ToolUseID string          `json:"tool_use_id"`
}

// promptDecision is the tool's reply: Claude Code reads the text content as
// this JSON. updatedInput is echoed unchanged on allow.
type promptDecision struct {
	Behavior     string          `json:"behavior"`
	UpdatedInput json.RawMessage `json:"updatedInput,omitempty"`
	Message      string          `json:"message,omitempty"`
}

func (s *approvalServer) handleApprove(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var in promptInput
	raw, err := json.Marshal(req.GetArguments())
	if err == nil {
		err = json.Unmarshal(raw, &in)
	}
	if err != nil {
		return decisionResult(promptDecision{Behavior: "deny", Message: "malformed permission request"}), nil
	}
	if len(in.Input) == 0 {
		in.Input = json.RawMessage("{}")
	}

	id, err := newRequestID()
	if err != nil {
		return decisionResult(promptDecision{Behavior: "deny", Message: "could not open a permission request"}), nil
	}
	now := s.now().UTC()
	s.journal(coderun.InputEvent{
		Kind:        coderun.KindInputRequest,
		T:           now,
		RequestID:   id,
		RequestKind: coderun.RequestKindPermission,
		Tool:        in.ToolName,
		Prompt:      describeToolCall(in.ToolName, in.Input),
		Options:     []coderun.Answer{coderun.AnswerAllow, coderun.AnswerDeny},
		Default:     coderun.AnswerDeny,
		ExpiresAt:   now.Add(s.timeout),
	})

	answer, reason := s.wait(ctx, id, now.Add(s.timeout), progressTokenOf(req))
	s.journal(coderun.InputEvent{Kind: coderun.KindInputResponse, RequestID: id, Answer: answer, Reason: reason})

	if answer == coderun.AnswerAllow {
		return decisionResult(promptDecision{Behavior: "allow", UpdatedInput: in.Input}), nil
	}
	msg := "The user denied this action."
	switch reason {
	case coderun.ReasonExpired:
		msg = "Nobody answered this permission request before it expired, so it was denied."
	case coderun.ReasonNoKey:
		msg = "This run has no way to receive answers to permission requests, so it was denied."
	case coderun.ReasonCancelled:
		msg = "The permission request was cancelled."
	}
	return decisionResult(promptDecision{Behavior: "deny", Message: msg}), nil
}

// wait blocks until a valid answer for id arrives, the deadline passes, or ctx
// ends. A file with a bad signature is journaled once and ignored: it is either
// a mistake or an attempt to approve without the key.
func (s *approvalServer) wait(ctx context.Context, id string, deadline time.Time, progress mcp.ProgressToken) (coderun.Answer, coderun.ResponseReason) {
	if s.key == nil {
		return coderun.AnswerDeny, coderun.ReasonNoKey
	}
	path := s.answerPath(id)
	var rejected string
	tick := time.NewTicker(s.pollInterval)
	defer tick.Stop()
	lastProgress := s.now()
	for {
		if content, err := os.ReadFile(path); err == nil && string(content) != rejected {
			a, verr := coderun.VerifyAnswer(s.key, s.run, id, string(content))
			if verr == nil {
				return a, coderun.ReasonAnswered
			}
			rejected = string(content)
			s.journal(coderun.InputEvent{Kind: coderun.KindInputStatus, RequestID: id,
				Text: "ignored an answer to " + id + ": " + verr.Error()})
		}
		if !s.now().Before(deadline) {
			return coderun.AnswerDeny, coderun.ReasonExpired
		}
		if progress != nil && s.now().Sub(lastProgress) >= approvalProgressInterval {
			lastProgress = s.now()
			if srv := server.ServerFromContext(ctx); srv != nil {
				_ = srv.SendNotificationToClient(ctx, "notifications/progress", map[string]any{
					"progressToken": progress,
					"progress":      int(time.Until(deadline).Seconds()),
					"message":       "waiting for an answer to " + id,
				})
			}
		}
		select {
		case <-ctx.Done():
			return coderun.AnswerDeny, coderun.ReasonCancelled
		case <-tick.C:
		}
	}
}

func progressTokenOf(req mcp.CallToolRequest) mcp.ProgressToken {
	if req.Params.Meta == nil {
		return nil
	}
	return req.Params.Meta.ProgressToken
}

func decisionResult(d promptDecision) *mcp.CallToolResult {
	b, _ := json.Marshal(d)
	return mcp.NewToolResultText(string(b))
}

// newRequestID is unguessable so an answer cannot be prepared before its
// request exists.
func newRequestID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "req-" + hex.EncodeToString(b), nil
}

// describeToolCall is the one-line prompt a human answers: the command for a
// shell call, the path for a file tool, otherwise the input as JSON.
func describeToolCall(tool string, input json.RawMessage) string {
	var fields struct {
		Command  string `json:"command"`
		FilePath string `json:"file_path"`
		URL      string `json:"url"`
	}
	_ = json.Unmarshal(input, &fields)
	detail := string(input)
	switch {
	case fields.Command != "":
		detail = fields.Command
	case fields.FilePath != "":
		detail = fields.FilePath
	case fields.URL != "":
		detail = fields.URL
	}
	p := tool + ": " + detail
	if len(p) > approvalPromptMax {
		p = p[:approvalPromptMax] + "…"
	}
	return p
}
