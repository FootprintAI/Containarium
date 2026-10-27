package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/footprintai/containarium/internal/agentbox"
	"github.com/footprintai/containarium/internal/coderun"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Permission requests of a box run (#2184): the daemon half of `code pending`,
// `code answer` and `code attach`'s inline answers.
//
// A run started with `code run --approvals ask` asks through `agent-box
// approval-mcp` (#2183), which journals each request to <run>.input.jsonl and
// accepts an answer only with an Ed25519 signature under the box's approval
// public key, made for the tool call it asked. The daemon holds the private key,
// derived per box from its own secret, and signs here for an authorized
// caller; the box never holds a secret.
//
// The journal is written by the box's user, which the agent runs as, so
// everything read from it is advisory: a forged line can make a request look
// closed, show another tool call, or report a response the run never made
// (so ANSWERED is the run's report, not proof), but the box only acts on an
// answer signed for the tool call it holds in memory. Whether an answer counts
// is the box's check, not one made here.

// approvalKeyContext separates this derivation from every other use of the
// daemon secret.
const approvalKeyContext = "containarium-approval-key-v1\n"

// defaultRunInputConfirmWait bounds how long AnswerRunInput waits for the box
// to journal its response. The approval server polls every 500ms.
const defaultRunInputConfirmWait = 3 * time.Second

// maxRunInputJournal caps the journal the daemon reads (#2184 review): the
// file is the agent's to write, and is read whole, so without a cap one box
// could exhaust the daemon's memory. Requests are at most 16 KiB of input
// each, so this holds hundreds.
const maxRunInputJournal = 8 << 20

// maxRunInputEvents caps the journal lines the daemon parses (#2184 review):
// 8 MiB of tiny lines would otherwise decode into millions of events. A run
// journals about two lines per request.
const maxRunInputEvents = 20000

// runInputIDPattern is agent-box's request id: "req-" + 16 hex digits. It
// becomes a path component on the box, so nothing else is accepted.
var runInputIDPattern = regexp.MustCompile(`^req-[0-9a-f]{16}$`)

// SetApprovalKeySecret sets the daemon secret box approval keys are derived
// from (the daemon's JWT secret). Without one the approval RPCs are
// Unavailable.
func (s *ContainerServer) SetApprovalKeySecret(secret []byte) {
	s.approvalSecret = append([]byte(nil), secret...)
}

// approvalKey is username's box approval key: an Ed25519 key whose seed is
// HMAC-SHA256(secret, context || username). Rotating the secret changes every
// key, so requests open at that moment can no longer be answered and expire
// into a deny.
func (s *ContainerServer) approvalKey(username string) (ed25519.PrivateKey, error) {
	if len(s.approvalSecret) == 0 {
		return nil, status.Error(codes.Unavailable, "this daemon has no secret to sign permission answers with")
	}
	m := hmac.New(sha256.New, s.approvalSecret)
	m.Write([]byte(approvalKeyContext + username))
	return ed25519.NewKeyFromSeed(m.Sum(nil)), nil
}

func (s *ContainerServer) journalCap() int64 {
	if s.runInputJournalCap > 0 {
		return s.runInputJournalCap
	}
	return maxRunInputJournal
}

func (s *ContainerServer) confirmWait() time.Duration {
	if s.runInputConfirmWait > 0 {
		return s.runInputConfirmWait
	}
	return defaultRunInputConfirmWait
}

// GetRunApprovalKey returns the box's approval public key.
func (s *ContainerServer) GetRunApprovalKey(ctx context.Context, req *pb.GetRunApprovalKeyRequest) (*pb.GetRunApprovalKeyResponse, error) {
	if err := validateBoxRunOwner(req.GetUsername()); err != nil {
		return nil, err
	}
	if err := s.authorizeBoxRuns(ctx, req.GetUsername()); err != nil {
		return nil, err
	}
	priv, err := s.approvalKey(req.GetUsername())
	if err != nil {
		return nil, err
	}
	return &pb.GetRunApprovalKeyResponse{PublicKey: hex.EncodeToString(priv.Public().(ed25519.PublicKey))}, nil
}

// validateRunInputsRun checks (username, run_name) for the input RPCs: the
// box-run rules, plus the approval run-name rule the journal's path needs.
func validateRunInputsRun(username, name string) error {
	if err := validateBoxRunOwner(username); err != nil {
		return err
	}
	if !validRunPathID(name) || coderun.ValidApprovalRunName(name) != nil {
		return status.Errorf(codes.InvalidArgument, "run_name %q is not a run name that can have permission requests", name)
	}
	return nil
}

// runInputsJournalScript prints "J <base64 journal>", "J -" when the run has
// none, or "J big <size>" for one over max bytes, opening it through the same
// symlink guard as the run reader. The read itself is bounded to max+1
// bytes, so a file that grows after the size check (the agent can append to
// it) still yields at most that much; readRunInputs refuses a read that got
// the extra byte.
func runInputsJournalScript(dir, name string, max int64) string {
	return fmt.Sprintf(`%sif open3 %s; then
  s=$(stat -L -c %%s /proc/$$/fd/3)
  if [ "$s" -gt %d ]; then exec 3<&-; echo "J big $s"; else echo "J $(head -c %d <&3 | base64 | tr -d '\n')"; exec 3<&-; fi
else echo "J -"; fi
`, boxRunOpenFn, shellSingleQuote(dir+"/"+name+".input.jsonl"), max, max+1)
}

// runInputsState is one read of a run: whether it is running, and its journal.
type runInputsState struct {
	running bool
	events  []coderun.InputEvent
}

// readRunInputs reads the run's record and journal. NotFound when there is no
// run by that name.
func (s *ContainerServer) readRunInputs(box, username, name string) (runInputsState, error) {
	exec := s.boxRunExecFn()
	if exec == nil {
		return runInputsState{}, status.Error(codes.Unavailable, "no container backend to read the run on")
	}
	dir := s.boxRunDir()
	out, err := exec(box, boxRunListScript(dir))
	if err != nil {
		return runInputsState{}, status.Errorf(codes.Unavailable, "read run records of %q: %v", username, err)
	}
	views, boot, alive := parseBoxRunViews(out)
	var st runInputsState
	found := false
	for _, v := range views {
		if v.fileName == name {
			found = true
			st.running = agentbox.ResolveOutcome(v.record, boot, func(pid int) bool { return pid > 0 && alive[pid] }) == agentbox.RunOutcomeRunning
		}
	}
	if !found {
		return runInputsState{}, status.Errorf(codes.NotFound, "no run named %q on %q", name, username)
	}
	jout, err := exec(box, runInputsJournalScript(dir, name, s.journalCap()))
	if err != nil {
		return runInputsState{}, status.Errorf(codes.Unavailable, "read the permission requests of run %q: %v", name, err)
	}
	for _, line := range strings.Split(jout, "\n") {
		b64, ok := strings.CutPrefix(strings.TrimSpace(line), "J ")
		if !ok || b64 == "-" {
			continue
		}
		if size, big := strings.CutPrefix(b64, "big "); big {
			return runInputsState{}, status.Errorf(codes.ResourceExhausted,
				"the permission journal of run %q is %s bytes, over the %d-byte limit; it cannot be read", name, size, s.journalCap())
		}
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return runInputsState{}, status.Errorf(codes.Internal, "decode the permission journal of run %q: %v", name, err)
		}
		if int64(len(raw)) > s.journalCap() {
			return runInputsState{}, status.Errorf(codes.ResourceExhausted,
				"the permission journal of run %q grew past the %d-byte limit while it was read; it cannot be read", name, s.journalCap())
		}
		if n := bytes.Count(raw, []byte{'\n'}); n > maxRunInputEvents {
			return runInputsState{}, status.Errorf(codes.ResourceExhausted,
				"the permission journal of run %q has %d lines, over the %d-line limit; it cannot be read", name, n, maxRunInputEvents)
		}
		st.events = coderun.ParseInputJournal(raw)
	}
	return st, nil
}

// runInputRecord is what the journal says about one request: the first
// request line for its id (a later line with the same id is the agent's, not
// the box's: the id is random and unknown before the box writes it) and the
// first response to it.
type runInputRecord struct {
	request  coderun.InputEvent
	response *coderun.InputEvent
}

func findRunInput(events []coderun.InputEvent, id string) (runInputRecord, bool) {
	var rec runInputRecord
	found := false
	for i, e := range events {
		if e.RequestID != id {
			continue
		}
		switch e.Kind {
		case coderun.KindInputRequest:
			if !found {
				rec.request, found = e, true
			}
		case coderun.KindInputResponse:
			if found && rec.response == nil {
				rec.response = &events[i]
			}
		}
	}
	return rec, found
}

func runInputAnswerProto(a coderun.Answer) pb.RunInputAnswer {
	switch a {
	case coderun.AnswerAllow:
		return pb.RunInputAnswer_RUN_INPUT_ANSWER_ALLOW
	case coderun.AnswerDeny:
		return pb.RunInputAnswer_RUN_INPUT_ANSWER_DENY
	}
	return pb.RunInputAnswer_RUN_INPUT_ANSWER_UNSPECIFIED
}

func runInputCloseReasonProto(r coderun.ResponseReason) pb.RunInputCloseReason {
	switch r {
	case coderun.ReasonAnswered:
		return pb.RunInputCloseReason_RUN_INPUT_CLOSE_REASON_ANSWERED
	case coderun.ReasonExpired:
		return pb.RunInputCloseReason_RUN_INPUT_CLOSE_REASON_EXPIRED
	case coderun.ReasonCancelled:
		return pb.RunInputCloseReason_RUN_INPUT_CLOSE_REASON_CANCELLED
	case coderun.ReasonNoKey:
		return pb.RunInputCloseReason_RUN_INPUT_CLOSE_REASON_NO_KEY
	case coderun.ReasonTooLarge:
		return pb.RunInputCloseReason_RUN_INPUT_CLOSE_REASON_TOO_LARGE
	}
	return pb.RunInputCloseReason_RUN_INPUT_CLOSE_REASON_UNSPECIFIED
}

func runInputProto(e coderun.InputEvent) *pb.RunInput {
	kind := pb.RunInputKind_RUN_INPUT_KIND_UNSPECIFIED
	if e.RequestKind == coderun.RequestKindPermission {
		kind = pb.RunInputKind_RUN_INPUT_KIND_PERMISSION
	}
	in := &pb.RunInput{RequestId: e.RequestID, Kind: kind, Tool: e.Tool, Prompt: e.Prompt, Input: e.Input, CreatedAt: timestamppb.New(e.T)}
	if !e.ExpiresAt.IsZero() {
		in.ExpiresAt = timestamppb.New(e.ExpiresAt)
	}
	return in
}

// ListRunInputs lists a box run's open permission requests and its counts.
func (s *ContainerServer) ListRunInputs(ctx context.Context, req *pb.ListRunInputsRequest) (*pb.ListRunInputsResponse, error) {
	if err := validateRunInputsRun(req.GetUsername(), req.GetRunName()); err != nil {
		return nil, err
	}
	if err := s.authorizeBoxRuns(ctx, req.GetUsername()); err != nil {
		return nil, err
	}
	st, err := s.readRunInputs(req.GetUsername()+"-container", req.GetUsername(), req.GetRunName())
	if err != nil {
		return nil, err
	}
	sum := coderun.SummarizeApprovals(st.events)
	resp := &pb.ListRunInputsResponse{
		Running:   st.running,
		Requests:  int32(sum.Requests),  // #nosec G115 -- a count of journal lines
		Allowed:   int32(sum.Allowed),   // #nosec G115 -- a count of journal lines
		Denied:    int32(sum.Denied),    // #nosec G115 -- a count of journal lines
		Expired:   int32(sum.Expired),   // #nosec G115 -- a count of journal lines
		Cancelled: int32(sum.Cancelled), // #nosec G115 -- a count of journal lines
	}
	// An open request on a run that has exited is waiting on nobody, and one
	// past its expiry is denied whatever the journal says yet.
	if st.running {
		now := time.Now()
		for _, e := range sum.Open {
			// Report the box's own request line for the id, not a later
			// one the agent appended.
			if rec, ok := findRunInput(st.events, e.RequestID); ok {
				e = rec.request
			}
			if !e.ExpiresAt.IsZero() && !now.Before(e.ExpiresAt) {
				continue
			}
			resp.Open = append(resp.Open, runInputProto(e))
		}
	}
	return resp, nil
}

// runInputAnswerScript drops content as the request's answer, as the box
// user (so nothing here runs with more rights than the agent already has):
// written to a temp file in the answers directory, then renamed over any
// earlier file (one that never got a response is no answer: it may
// be the agent's, or signed for a tool call the box did not ask). Prints
// "written", or "nodir" when the run has no answers directory.
func runInputAnswerScript(answersDir, id, content string) string {
	q := shellSingleQuote
	return fmt.Sprintf(`a=%s
[ -d "$a" ] && [ ! -L "$a" ] || { echo nodir; exit 0; }
t="$a/.answer.$$"
printf '%%s' %s > "$t" && mv -f "$t" "$a"/%s || { rm -f "$t"; exit 1; }
echo written
`, q(answersDir), q(content), q(id))
}

// AnswerRunInput answers one permission request of a box run.
func (s *ContainerServer) AnswerRunInput(ctx context.Context, req *pb.AnswerRunInputRequest) (*pb.AnswerRunInputResponse, error) {
	username, name, id := req.GetUsername(), req.GetRunName(), req.GetRequestId()
	if err := validateRunInputsRun(username, name); err != nil {
		return nil, err
	}
	if !runInputIDPattern.MatchString(id) {
		return nil, status.Errorf(codes.InvalidArgument, "request_id must match %s", runInputIDPattern.String())
	}
	var answer coderun.Answer
	switch req.GetAnswer() {
	case pb.RunInputAnswer_RUN_INPUT_ANSWER_ALLOW:
		answer = coderun.AnswerAllow
	case pb.RunInputAnswer_RUN_INPUT_ANSWER_DENY:
		answer = coderun.AnswerDeny
	default:
		return nil, status.Error(codes.InvalidArgument, "answer must be ALLOW or DENY")
	}
	if len(req.GetRequestSha256()) != sha256.Size {
		return nil, status.Errorf(codes.InvalidArgument, "request_sha256 must be %d bytes: the SHA-256 of the tool call shown to whoever answered", sha256.Size)
	}
	if err := s.authorizeBoxRuns(ctx, username); err != nil {
		return nil, err
	}
	priv, err := s.approvalKey(username)
	if err != nil {
		return nil, err
	}
	write := s.boxRunStartExecFn()
	if write == nil {
		return nil, status.Error(codes.Unavailable, "no container backend to answer the run on")
	}
	box := username + "-container"

	// Serialized per run: a duplicate answer waits for the first one's
	// response and then reports it, instead of racing it.
	lock := s.boxRunLockFor(boxRunLockKey(box, name))
	lock.Lock()
	defer lock.Unlock()

	st, err := s.readRunInputs(box, username, name)
	if err != nil {
		return nil, err
	}
	rec, ok := findRunInput(st.events, id)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "run %q on %q has no permission request %q", name, username, id)
	}
	if rec.response != nil {
		return closedRunInput(pb.RunInputAnswerOutcome_RUN_INPUT_ANSWER_OUTCOME_ALREADY_CLOSED, *rec.response), nil
	}
	if !rec.request.ExpiresAt.IsZero() && !time.Now().Before(rec.request.ExpiresAt) {
		return &pb.AnswerRunInputResponse{Outcome: pb.RunInputAnswerOutcome_RUN_INPUT_ANSWER_OUTCOME_EXPIRED}, nil
	}
	if !st.running {
		return nil, status.Errorf(codes.FailedPrecondition, "run %q on %q is not running; nothing is waiting on request %q", name, username, id)
	}

	content := coderun.FormatAnswer(priv, name, id, req.GetRequestSha256(), answer)
	out, err := write(box, username, runInputAnswerScript(s.boxRunDir()+"/"+name+".answers", id, content))
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "write the answer to %q on %q: %v", id, username, err)
	}
	if strings.TrimSpace(out) != "written" {
		return nil, status.Errorf(codes.FailedPrecondition, "run %q on %q has no answers directory; it was not started with --approvals ask", name, username)
	}

	deadline := time.Now().Add(s.confirmWait())
	for {
		st, err := s.readRunInputs(box, username, name)
		if err != nil {
			return nil, err
		}
		if rec, ok := findRunInput(st.events, id); ok && rec.response != nil {
			// Closed some other way meanwhile (it expired, the run ended, or
			// an earlier answer the other way was taken first): report that,
			// not this answer.
			outcome := pb.RunInputAnswerOutcome_RUN_INPUT_ANSWER_OUTCOME_ANSWERED
			if rec.response.Reason != coderun.ReasonAnswered || rec.response.Answer != answer {
				outcome = pb.RunInputAnswerOutcome_RUN_INPUT_ANSWER_OUTCOME_ALREADY_CLOSED
			}
			return closedRunInput(outcome, *rec.response), nil
		}
		if !time.Now().Before(deadline) {
			return &pb.AnswerRunInputResponse{Outcome: pb.RunInputAnswerOutcome_RUN_INPUT_ANSWER_OUTCOME_NOT_CONFIRMED}, nil
		}
		select {
		case <-ctx.Done():
			return nil, status.FromContextError(ctx.Err()).Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func closedRunInput(outcome pb.RunInputAnswerOutcome, resp coderun.InputEvent) *pb.AnswerRunInputResponse {
	out := &pb.AnswerRunInputResponse{
		Outcome:      outcome,
		ClosedAnswer: runInputAnswerProto(resp.Answer),
		CloseReason:  runInputCloseReasonProto(resp.Reason),
	}
	if !resp.T.IsZero() {
		out.ClosedAt = timestamppb.New(resp.T)
	}
	return out
}
