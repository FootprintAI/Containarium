package coderun

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
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
// Files, both next to the run's log under RunLogDir:
//
//	<name>.input.jsonl   append-only journal of InputEvent lines
//	<name>.answers/<id>  one answer per request: "<allow|deny> <hex signature>\n"
//
// An answer counts only with an Ed25519 signature under the box's approval
// public key, which `code run` gets from the daemon and passes to the approval
// server on its command line. The private key never leaves the daemon
// (AnswerRunInput signs, #2184), so it never reaches the box.
//
// The signature also covers the SHA-256 of the prompt the answering human was
// shown. The journal is writable by the agent, so a shown prompt can be a
// forgery; the approval server verifies against the prompt it holds in
// memory, so an answer made for anything but the real request never counts.

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

// ApprovalJournalPath is the run's input journal.
func ApprovalJournalPath(name string) string { return RunLogDir + "/" + name + ".input.jsonl" }

// ApprovalAnswersDir is where answers to the run's requests are dropped.
func ApprovalAnswersDir(name string) string { return RunLogDir + "/" + name + ".answers" }

// ValidApprovalRunName accepts the run names whose approval files can sit
// next to the run's log as-is: exactly the names agent-box's process name
// sanitizer leaves unchanged, minus "." and "..". Anything else is refused
// before any file on the box is touched.
func ValidApprovalRunName(name string) error {
	if name == "" || name == "." || name == ".." {
		return fmt.Errorf("run name %q cannot be used with --approvals ask", name)
	}
	for _, r := range name {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.'
		if !ok {
			return fmt.Errorf("run name %q cannot be used with --approvals ask: only letters, digits, '-', '_' and '.' are allowed", name)
		}
	}
	return nil
}

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
	// ReasonNoKey closes a request at once when the server has no usable
	// public key, so nothing could ever answer it.
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

// approvalSignContext versions the signed message, so a signature made for
// anything else never verifies as an answer. v2 (#2184) added the prompt
// digest; nothing ever signed v1 answers but tests.
const approvalSignContext = "containarium-approval-v2"

// PromptDigest is the digest an answer binds: SHA-256 of the raw prompt
// string as the request line carries it (not its escaped, printed form).
func PromptDigest(prompt string) []byte {
	d := sha256.Sum256([]byte(prompt))
	return d[:]
}

func answerMessage(run, requestID string, promptDigest []byte, a Answer) []byte {
	return []byte(approvalSignContext + "\n" + run + "\n" + requestID + "\n" + hex.EncodeToString(promptDigest) + "\n" + string(a))
}

// SignAnswer signs an answer to (run, requestID) for the prompt whose digest
// is promptDigest. Binding the run name and request id means an answer cannot
// be replayed onto another request; binding the prompt means it cannot be
// spent on a request whose shown prompt was forged; binding the answer means
// "allow" cannot be made from a "deny".
func SignAnswer(priv ed25519.PrivateKey, run, requestID string, promptDigest []byte, a Answer) string {
	return hex.EncodeToString(ed25519.Sign(priv, answerMessage(run, requestID, promptDigest, a)))
}

// FormatAnswer renders an answer file's content.
func FormatAnswer(priv ed25519.PrivateKey, run, requestID string, promptDigest []byte, a Answer) string {
	return string(a) + " " + SignAnswer(priv, run, requestID, promptDigest, a) + "\n"
}

// VerifyAnswer parses an answer file's content and checks its signature for
// the prompt whose digest is promptDigest.
func VerifyAnswer(pub ed25519.PublicKey, run, requestID string, promptDigest []byte, content string) (Answer, error) {
	if len(promptDigest) != sha256.Size {
		return "", fmt.Errorf("no prompt digest to check the answer against")
	}
	fields := strings.Fields(content)
	if len(fields) != 2 {
		return "", fmt.Errorf("answer is not \"<allow|deny> <signature>\"")
	}
	a := Answer(fields[0])
	if a != AnswerAllow && a != AnswerDeny {
		return "", fmt.Errorf("answer %q is neither %q nor %q", fields[0], AnswerAllow, AnswerDeny)
	}
	sig, err := hex.DecodeString(fields[1])
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, answerMessage(run, requestID, promptDigest, a), sig) {
		return "", fmt.Errorf("answer signature does not verify")
	}
	return a, nil
}

// ParseApprovalPublicKey decodes a hex approval public key: the one the
// approval server is started with, and the one GetRunApprovalKey returns.
func ParseApprovalPublicKey(h string) (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(strings.TrimSpace(h))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("not a hex Ed25519 public key")
	}
	return ed25519.PublicKey(b), nil
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

// PlainText makes journal text safe to print on one terminal line. The prompt
// is the agent's own tool input, and the agent can write the journal itself,
// so a newline, carriage return, escape sequence or bidi override in it could
// otherwise forge or hide the lines a human reads before answering. Each
// control or format character is shown as its escaped form instead.
func PlainText(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			q := strconv.QuoteRune(r)
			b.WriteString(q[1 : len(q)-1])
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
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
				PlainText(e.RequestID), PlainText(e.Prompt), e.ExpiresAt.Sub(now).Round(time.Second))
		}
	}
	fmt.Fprintf(&b, "permission requests: %d (allowed %d, denied %d, expired %d, cancelled %d, open %d)\n",
		s.Requests, s.Allowed, s.Denied, s.Expired, s.Cancelled, len(s.Open))
	for _, n := range s.Notes {
		fmt.Fprintf(&b, "  note: %s\n", PlainText(n))
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
