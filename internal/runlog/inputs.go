package runlog

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/footprintai/containarium/internal/coderun"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Permission requests of a box run (#2184): the client side of ListRunInputs
// and AnswerRunInput, shared by `containarium code pending|answer`, `code
// attach`'s inline answers, and the MCP code_pending/code_answer tools.

// RunInputs is the pair of permission-request RPCs; the gRPC, HTTP and MCP
// clients all satisfy it.
type RunInputs interface {
	ListRunInputs(req *pb.ListRunInputsRequest) (*pb.ListRunInputsResponse, error)
	AnswerRunInput(req *pb.AnswerRunInputRequest) (*pb.AnswerRunInputResponse, error)
}

// RunInputsPath is the REST path for ListRunInputs.
func RunInputsPath(username, run string) string {
	return BoxRunsPath(username) + "/" + url.PathEscape(run) + "/inputs"
}

// RunInputAnswerPath is the REST path for AnswerRunInput.
func RunInputAnswerPath(username, run, requestID string) string {
	return RunInputsPath(username, run) + "/" + url.PathEscape(requestID) + ":answer"
}

// RunApprovalKeyPath is the REST path for GetRunApprovalKey.
func RunApprovalKeyPath(username string) string {
	return BoxRunsPath(username) + ":approval-key"
}

// ParseRunInputAnswer reads an answer word: allow or deny.
func ParseRunInputAnswer(s string) (pb.RunInputAnswer, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "allow":
		return pb.RunInputAnswer_RUN_INPUT_ANSWER_ALLOW, nil
	case "deny":
		return pb.RunInputAnswer_RUN_INPUT_ANSWER_DENY, nil
	}
	return pb.RunInputAnswer_RUN_INPUT_ANSWER_UNSPECIFIED, fmt.Errorf("answer must be allow or deny, got %q", s)
}

func answerWord(a pb.RunInputAnswer) string {
	switch a {
	case pb.RunInputAnswer_RUN_INPUT_ANSWER_ALLOW:
		return "allow"
	case pb.RunInputAnswer_RUN_INPUT_ANSWER_DENY:
		return "deny"
	}
	return "unknown"
}

func closeReasonWord(r pb.RunInputCloseReason) string {
	switch r {
	case pb.RunInputCloseReason_RUN_INPUT_CLOSE_REASON_ANSWERED:
		return "answered"
	case pb.RunInputCloseReason_RUN_INPUT_CLOSE_REASON_EXPIRED:
		return "expired"
	case pb.RunInputCloseReason_RUN_INPUT_CLOSE_REASON_CANCELLED:
		return "cancelled"
	case pb.RunInputCloseReason_RUN_INPUT_CLOSE_REASON_NO_KEY:
		return "no key"
	case pb.RunInputCloseReason_RUN_INPUT_CLOSE_REASON_TOO_LARGE:
		return "input too large"
	}
	return "unknown"
}

// WriteRunInputs renders a run's open requests as the table `code pending`
// prints: id, age, expiry and the one-line prompt (escaped: the prompt is the
// agent's own tool input), then the run's counts. The complete input, which
// an allow permits, is shown by `code answer` before it sends one.
func WriteRunInputs(w io.Writer, run string, resp *pb.ListRunInputsResponse, now time.Time) error {
	if !resp.GetRunning() {
		if _, err := fmt.Fprintf(w, "run %s is not running; nothing is waiting on an answer\n", run); err != nil {
			return err
		}
	} else if len(resp.GetOpen()) == 0 {
		if _, err := fmt.Fprintf(w, "no open permission requests on run %s\n", run); err != nil {
			return err
		}
	} else {
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "REQUEST\tAGE\tEXPIRES IN\tPROMPT")
		for _, in := range resp.GetOpen() {
			expires := "-"
			if in.GetExpiresAt() != nil {
				expires = in.GetExpiresAt().AsTime().Sub(now).Round(time.Second).String()
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", coderun.PlainText(in.GetRequestId()),
				now.Sub(in.GetCreatedAt().AsTime()).Round(time.Second), expires, coderun.PlainText(in.GetPrompt()))
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(w, "permission requests: %d (allowed %d, denied %d, expired %d, cancelled %d, open %d)\n",
		resp.GetRequests(), resp.GetAllowed(), resp.GetDenied(), resp.GetExpired(), resp.GetCancelled(), len(resp.GetOpen()))
	return err
}

// ErrNotAnswered marks an AnswerRunInput call that changed nothing or could
// not be confirmed: the CLI exits non-zero on it.
var ErrNotAnswered = errors.New("not answered")

// AnswerResult is one answer's outcome plus the request it was signed for.
type AnswerResult struct {
	RequestID string
	Answer    pb.RunInputAnswer
	// Shown is the request as the answering party saw it, which the answer
	// was signed for; nil when the request was not open, so nothing could be
	// signed for it and the daemon only reported its state.
	Shown *pb.RunInput
	Resp  *pb.AnswerRunInputResponse
}

// WriteRequest prints an open request the way it must be seen before an
// allow: its one-line prompt, then the tool and its complete input, which are
// what an allow permits and what the answer is signed for (the prompt is only
// a summary, and the agent can write it). All are escaped.
//
// The error is the writer's: a caller must not send an allow for a request
// it could not show.
func WriteRequest(w io.Writer, r *pb.RunInput) error {
	_, err := fmt.Fprintf(w, "request %s: %s\n  an allow permits exactly this:\n  tool:  %s\n  input: %s\n",
		coderun.PlainText(r.GetRequestId()), coderun.PlainText(r.GetPrompt()),
		coderun.PlainText(r.GetTool()), coderun.PlainText(r.GetInput()))
	return err
}

// AnswerShown answers shown, the request as the caller showed it to whoever
// is answering: the signed answer binds the digest of its tool and complete
// input, so the box ignores it unless that is the tool call the box asked.
func AnswerShown(api RunInputs, box, run string, shown *pb.RunInput, a pb.RunInputAnswer) (AnswerResult, error) {
	id := shown.GetRequestId()
	resp, err := api.AnswerRunInput(&pb.AnswerRunInputRequest{
		Username: box, RunName: run, RequestId: id, Answer: a,
		RequestSha256: coderun.RequestDigest(shown.GetTool(), shown.GetInput()),
	})
	if err != nil {
		return AnswerResult{}, fmt.Errorf("answer %s on run %s: %w", id, run, err)
	}
	return AnswerResult{RequestID: id, Answer: a, Shown: shown, Resp: resp}, nil
}

// ErrRequestChanged marks an answer that was not sent because the request is
// no longer the one the answering party saw.
var ErrRequestChanged = errors.New("the request changed")

// OpenRequest returns request id when it is open on run, else nil.
func OpenRequest(api RunInputs, box, run, id string) (*pb.RunInput, error) {
	list, err := api.ListRunInputs(&pb.ListRunInputsRequest{Username: box, RunName: run})
	if err != nil {
		return nil, fmt.Errorf("read the permission requests of run %s: %w", run, err)
	}
	for _, in := range list.GetOpen() {
		if in.GetRequestId() == id {
			return in, nil
		}
	}
	return nil, nil
}

// Answer answers request id for seen, the request as the answering party saw
// it (what `code answer` printed and had confirmed, or the input the MCP
// caller got from code_pending); seen is nil when it was not open. It re-reads
// the request first: if it is open with another tool or input now, nothing is
// sent and the error wraps ErrRequestChanged. A request that is not open is
// closed, expired or unknown: the daemon reports which without writing
// anything.
func Answer(api RunInputs, box, run, id string, seen *pb.RunInput, a pb.RunInputAnswer) (AnswerResult, error) {
	current, err := OpenRequest(api, box, run, id)
	if err != nil {
		return AnswerResult{}, err
	}
	if current != nil && (seen == nil || current.GetTool() != seen.GetTool() || current.GetInput() != seen.GetInput()) {
		var b strings.Builder
		_ = WriteRequest(&b, current) // a strings.Builder does not fail
		return AnswerResult{}, fmt.Errorf("%w; nothing was sent. It is now:\n%s", ErrRequestChanged, strings.TrimRight(b.String(), "\n"))
	}
	if current == nil {
		seen = &pb.RunInput{RequestId: id}
	}
	res, err := AnswerShown(api, box, run, seen, a)
	if err != nil {
		return AnswerResult{}, err
	}
	if current == nil {
		res.Shown = nil
	}
	return res, nil
}

// WriteAnswerResult prints r and returns ErrNotAnswered unless the run
// reported taking the answer (its journal showed a response; the journal is
// the agent's to write, so that is a report, not proof).
func WriteAnswerResult(w io.Writer, r AnswerResult) error {
	id := coderun.PlainText(r.RequestID)
	switch r.Resp.GetOutcome() {
	case pb.RunInputAnswerOutcome_RUN_INPUT_ANSWER_OUTCOME_ANSWERED:
		_, err := fmt.Fprintf(w, "%s %s: %s\n", pastTense(r.Resp.GetClosedAnswer()), id, coderun.PlainText(r.Shown.GetPrompt()))
		return err
	case pb.RunInputAnswerOutcome_RUN_INPUT_ANSWER_OUTCOME_ALREADY_CLOSED:
		fmt.Fprintf(w, "%s was already closed: %s (%s)%s; nothing changed\n", id,
			answerWord(r.Resp.GetClosedAnswer()), closeReasonWord(r.Resp.GetCloseReason()), atTime(r.Resp))
	case pb.RunInputAnswerOutcome_RUN_INPUT_ANSWER_OUTCOME_EXPIRED:
		fmt.Fprintf(w, "%s has expired (it is denied); nothing changed\n", id)
	case pb.RunInputAnswerOutcome_RUN_INPUT_ANSWER_OUTCOME_NOT_CONFIRMED:
		fmt.Fprintf(w, "%s %s was sent for: %s\nbut the run has not reported taking it. It may have been refused because that is not the tool call the run asked; the request stays open until answered or expired.\n",
			answerWord(r.Answer), id, coderun.PlainText(r.Shown.GetPrompt()))
	default:
		fmt.Fprintf(w, "%s: unexpected outcome %v\n", id, r.Resp.GetOutcome())
	}
	return ErrNotAnswered
}

func pastTense(a pb.RunInputAnswer) string {
	if a == pb.RunInputAnswer_RUN_INPUT_ANSWER_ALLOW {
		return "allowed"
	}
	return "denied"
}

func atTime(r *pb.AnswerRunInputResponse) string {
	if r.GetClosedAt() == nil {
		return ""
	}
	return " at " + r.GetClosedAt().AsTime().UTC().Format(time.RFC3339)
}
