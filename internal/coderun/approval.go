package coderun

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Permission approvals for `code run --approvals ask` (#2183).
//
// A Claude run started with --approvals ask hands every tool call that needs a
// permission to `agent-box approval-mcp` (Claude Code's --permission-prompt-tool).
// That process journals an input_request, waits for a signed answer, and
// journals the outcome. Everything here is the shared shape of those files, so
// the box side (internal/agentbox) and the client side (`code status`, the MCP
// code_status tool, and later `code answer`) cannot drift.
//
// Files, all next to the run's log under RunLogDir:
//
//	<name>.input.jsonl   append-only journal of InputEvent lines
//	<name>.answers/<id>  one answer per request: "<allow|deny> <hex mac>\n"
//	<name>.approval-key  the run's answer key; the approval server reads and
//	                     unlinks it at startup, before the agent's first turn

// ApprovalMode is `code run --approvals`.
type ApprovalMode string

const (
	// ApprovalsDeny is today's behaviour: a tool call that needs a permission
	// is refused by the engine and nothing waits.
	ApprovalsDeny ApprovalMode = "deny"
	// ApprovalsAsk pauses the run on such a call until it is answered or
	// expires into a deny.
	ApprovalsAsk ApprovalMode = "ask"
)

// ParseApprovalMode validates a --approvals value.
func ParseApprovalMode(s string) (ApprovalMode, error) {
	switch m := ApprovalMode(strings.TrimSpace(s)); m {
	case ApprovalsDeny, ApprovalsAsk:
		return m, nil
	case "":
		return ApprovalsDeny, nil
	default:
		return "", fmt.Errorf("--approvals must be %q or %q, got %q", ApprovalsDeny, ApprovalsAsk, s)
	}
}

// DefaultApprovalTimeout is how long a request waits before it expires into a
// deny (PRD open question 5: long enough to answer from a phone in a meeting).
const DefaultApprovalTimeout = 30 * time.Minute

// ApprovalKeyBytes is the size of a run's answer key.
const ApprovalKeyBytes = 32

// ApprovalKeyFileMode is the mode the key file is created with.
const ApprovalKeyFileMode = "0600"

// ApprovalJournalPath is the run's input journal.
func ApprovalJournalPath(name string) string { return RunLogDir + "/" + name + ".input.jsonl" }

// ApprovalAnswersDir is where answers to the run's requests are dropped.
func ApprovalAnswersDir(name string) string { return RunLogDir + "/" + name + ".answers" }

// ApprovalKeyPath is where `code run` leaves the run's answer key for the
// approval server to consume.
func ApprovalKeyPath(name string) string { return RunLogDir + "/" + name + ".approval-key" }

// Answer is a decision on one permission request.
type Answer string

const (
	AnswerAllow Answer = "allow"
	AnswerDeny  Answer = "deny"
)

// InputKind is the kind of an InputEvent line.
type InputKind string

const (
	// KindInputRequest opens a request.
	KindInputRequest InputKind = "input_request"
	// KindInputResponse closes one: answered, expired or cancelled.
	KindInputResponse InputKind = "input_response"
	// KindInputStatus is a note about the approval channel itself (no key, a
	// rejected answer, an engine without a hook).
	KindInputStatus InputKind = "status"
)

// RequestKindPermission is the only request kind so far (a free-text question
// is a later phase of the PRD).
const RequestKindPermission = "permission"

// ResponseReason says how a request was closed.
type ResponseReason string

const (
	ReasonAnswered  ResponseReason = "answered"
	ReasonExpired   ResponseReason = "expired"
	ReasonCancelled ResponseReason = "cancelled"
	// ReasonNoKey closes a request at once when the server has no key, so
	// nothing could ever answer it.
	ReasonNoKey ResponseReason = "no_key"
)

// InputEvent is one line of the input journal.
type InputEvent struct {
	Kind      InputKind `json:"kind"`
	T         time.Time `json:"t"`
	RequestID string    `json:"request_id,omitempty"`

	// input_request
	RequestKind string    `json:"request_kind,omitempty"`
	Tool        string    `json:"tool,omitempty"`
	Prompt      string    `json:"prompt,omitempty"`
	Options     []Answer  `json:"options,omitempty"`
	Default     Answer    `json:"default,omitempty"`
	ExpiresAt   time.Time `json:"expires_at,omitzero"`

	// input_response
	Answer Answer         `json:"answer,omitempty"`
	Reason ResponseReason `json:"reason,omitempty"`

	// status
	Text string `json:"text,omitempty"`
}

// MarshalLine renders e as one journal line, newline included.
func (e InputEvent) MarshalLine() ([]byte, error) {
	b, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// ParseInputJournal decodes a journal. A line that does not decode is skipped,
// not fatal: the last line can be torn while the server is writing it.
func ParseInputJournal(data []byte) []InputEvent {
	var out []InputEvent
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var e InputEvent
		if err := json.Unmarshal(line, &e); err != nil {
			continue
		}
		out = append(out, e)
	}
	return out
}

// SignAnswer is the MAC an answer to (run, requestID) must carry. Binding the
// run name and request id means an answer cannot be replayed onto another
// request, and binding the answer means "allow" cannot be minted from "deny".
func SignAnswer(key []byte, run, requestID string, a Answer) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(run + "\n" + requestID + "\n" + string(a)))
	return hex.EncodeToString(m.Sum(nil))
}

// FormatAnswer renders an answer file's content.
func FormatAnswer(key []byte, run, requestID string, a Answer) string {
	return string(a) + " " + SignAnswer(key, run, requestID, a) + "\n"
}

// VerifyAnswer parses an answer file's content and checks its MAC.
func VerifyAnswer(key []byte, run, requestID, content string) (Answer, error) {
	fields := strings.Fields(content)
	if len(fields) != 2 {
		return "", fmt.Errorf("answer is not \"<allow|deny> <mac>\"")
	}
	a := Answer(fields[0])
	if a != AnswerAllow && a != AnswerDeny {
		return "", fmt.Errorf("answer %q is neither %q nor %q", fields[0], AnswerAllow, AnswerDeny)
	}
	want := SignAnswer(key, run, requestID, a)
	if !hmac.Equal([]byte(fields[1]), []byte(want)) {
		return "", fmt.Errorf("answer signature does not match")
	}
	return a, nil
}

// ApprovalSummary is the per-run count of permission requests — the PRD's
// demand instrumentation — plus the requests still open.
type ApprovalSummary struct {
	Requests  int
	Allowed   int
	Denied    int
	Expired   int
	Cancelled int
	Open      []InputEvent
	// Notes are the journal's status lines, in order.
	Notes []string
}

// SummarizeApprovals folds a journal into an ApprovalSummary.
func SummarizeApprovals(events []InputEvent) ApprovalSummary {
	var s ApprovalSummary
	open := map[string]InputEvent{}
	var order []string
	for _, e := range events {
		switch e.Kind {
		case KindInputRequest:
			s.Requests++
			open[e.RequestID] = e
			order = append(order, e.RequestID)
		case KindInputResponse:
			if _, ok := open[e.RequestID]; !ok {
				continue
			}
			delete(open, e.RequestID)
			switch {
			case e.Reason == ReasonExpired:
				s.Expired++
			case e.Reason == ReasonCancelled:
				s.Cancelled++
			case e.Answer == AnswerAllow:
				s.Allowed++
			default:
				s.Denied++
			}
		case KindInputStatus:
			s.Notes = append(s.Notes, e.Text)
		}
	}
	for _, id := range order {
		if e, ok := open[id]; ok {
			s.Open = append(s.Open, e)
		}
	}
	return s
}

// ApprovalStatusLines renders a summary for `code status` and the MCP
// code_status tool. running says whether the run is still alive: an open
// request on a dead run is not waiting on anyone. It returns "" for a run that
// never used approvals.
func ApprovalStatusLines(s ApprovalSummary, running bool, now time.Time) string {
	if s.Requests == 0 && len(s.Notes) == 0 {
		return ""
	}
	var b strings.Builder
	if running && len(s.Open) > 0 {
		b.WriteString("state: waiting_input\n")
		for _, e := range s.Open {
			fmt.Fprintf(&b, "  request %s: %s (expires in %s)\n",
				e.RequestID, e.Prompt, e.ExpiresAt.Sub(now).Round(time.Second))
		}
	}
	fmt.Fprintf(&b, "permission requests: %d (allowed %d, denied %d, expired %d, cancelled %d, open %d)\n",
		s.Requests, s.Allowed, s.Denied, s.Expired, s.Cancelled, len(s.Open))
	for _, n := range s.Notes {
		fmt.Fprintf(&b, "  note: %s\n", n)
	}
	return strings.TrimRight(b.String(), "\n")
}

// ApprovalStatus reads the run's journal off the box and renders
// ApprovalStatusLines — the one function `code status` and the MCP code_status
// tool share. A run that never used approvals has no journal and renders "".
func (s *Session) ApprovalStatus(ctx context.Context, name string, running bool, now time.Time) (string, error) {
	blob, err := s.ReadFile(ctx, ApprovalJournalPath(name))
	if err != nil {
		if errors.Is(err, ErrFileNotFound) {
			return "", nil
		}
		return "", err
	}
	return ApprovalStatusLines(SummarizeApprovals(ParseInputJournal([]byte(blob))), running, now), nil
}
