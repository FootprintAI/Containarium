//go:build !windows

package agentbox

import (
	"context"
	"crypto/ed25519"
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
// too. An answer counts only with an Ed25519 signature that verifies under the
// run's public key, which arrives on this process's command line from `code
// run`. The private key never reaches the box, so there is no secret on it for
// any process to read. Out of scope: a process the agent leaves running can
// change the box's own Claude Code setup (its binaries on PATH, its settings)
// for later runs; no scheme confined to the box can prevent that.

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
	pub     ed25519.PublicKey // nil: no usable key was given, nothing can answer

	now          func() time.Time
	pollInterval time.Duration

	mu sync.Mutex // serializes journal appends
}

// RunApprovalCLI is `agent-box approval-mcp --run <name> --public-key <hex> [--timeout d] [--dir d]`.
func RunApprovalCLI(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("approval-mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	run := fs.String("run", "", "run name whose permission requests this serves (required)")
	timeout := fs.Duration("timeout", coderun.DefaultApprovalTimeout, "how long a request waits before it expires into a deny")
	dir := fs.String("dir", DefaultLogDir, "run log directory")
	publicKey := fs.String("public-key", "", "hex Ed25519 public key answers must be signed for")
	probe := fs.Bool("probe", false, "print a readiness line and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *probe {
		fmt.Fprintln(stdout, approvalProbeOK)
		return 0
	}
	if err := coderun.ValidApprovalRunName(*run); err != nil {
		fmt.Fprintf(stderr, "approval-mcp: --run: %v\n", err)
		return 2
	}
	if *timeout <= 0 {
		fmt.Fprintln(stderr, "approval-mcp: --timeout must be positive")
		return 2
	}

	s := &approvalServer{run: *run, dir: *dir, timeout: *timeout, now: time.Now, pollInterval: approvalPollInterval}
	// The answers directory is this run's own: a previous same-name run's was
	// rotated aside by process_start.
	if err := os.MkdirAll(filepath.Join(s.dir, s.run+".answers"), 0o700); err != nil {
		log.Printf("[approval-mcp] create answers dir: %v", err)
	}
	s.setPublicKey(*publicKey)

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

func (s *approvalServer) journalPath() string { return filepath.Join(s.dir, s.run+".input.jsonl") }
func (s *approvalServer) answerPath(id string) string {
	return filepath.Join(s.dir, s.run+".answers", id)
}

// setPublicKey takes the run's public key. A missing or malformed one is
// journaled, and every request is then denied at once: waiting would only
// delay a deny nobody can override.
func (s *approvalServer) setPublicKey(h string) {
	pub, err := coderun.ParseApprovalPublicKey(h)
	if err != nil {
		s.journal(coderun.InputEvent{Kind: coderun.KindInputStatus,
			Text: "no usable approval public key for this run (" + err.Error() + "); every permission request is denied"})
		return
	}
	s.pub = pub
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
	if s.pub == nil {
		return coderun.AnswerDeny, coderun.ReasonNoKey
	}
	path := s.answerPath(id)
	var rejected string
	tick := time.NewTicker(s.pollInterval)
	defer tick.Stop()
	lastProgress := s.now()
	for {
		// The deadline is checked first, so an answer that lands after expiry
		// is never accepted.
		if !s.now().Before(deadline) {
			return coderun.AnswerDeny, coderun.ReasonExpired
		}
		if content, err := os.ReadFile(path); err == nil && string(content) != rejected {
			a, verr := coderun.VerifyAnswer(s.pub, s.run, id, string(content))
			if verr == nil {
				return a, coderun.ReasonAnswered
			}
			rejected = string(content)
			s.journal(coderun.InputEvent{Kind: coderun.KindInputStatus, RequestID: id,
				Text: "ignored an answer to " + id + ": " + verr.Error()})
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
