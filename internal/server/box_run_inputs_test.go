//go:build !containarium_client

package server

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/coderun"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// inputsRun is a running box run with an approval journal holding one open
// request, the way `agent-box approval-mcp` leaves it.
type inputsRun struct {
	s     *ContainerServer
	owner string
	run   string
	dir   string
	req   coderun.InputEvent
}

func startInputsRun(t *testing.T, expiresIn time.Duration) *inputsRun {
	t.Helper()
	s, owner, run := startLongRun(t, "{{READY}}\nsleep 60")
	s.approvalSecret = []byte("test-jwt-secret")
	s.runInputConfirmWait = 2 * time.Second
	r := &inputsRun{s: s, owner: owner, run: run.GetRunName(), dir: s.boxRunDir()}
	if err := os.MkdirAll(filepath.Join(r.dir, r.run+".answers"), 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	r.req = coderun.InputEvent{
		Kind: coderun.KindInputRequest, T: now, RequestID: "req-0123456789abcdef",
		RequestKind: coderun.RequestKindPermission, Tool: "Bash", Prompt: "Bash: rm -rf ~/repo",
		Options: []coderun.Answer{coderun.AnswerAllow, coderun.AnswerDeny}, Default: coderun.AnswerDeny,
		ExpiresAt: now.Add(expiresIn),
	}
	r.appendJournal(t, r.req)
	return r
}

func (r *inputsRun) journalPath() string { return filepath.Join(r.dir, r.run+".input.jsonl") }
func (r *inputsRun) answerPath(id string) string {
	return filepath.Join(r.dir, r.run+".answers", id)
}

func (r *inputsRun) appendJournal(t *testing.T, e coderun.InputEvent) {
	t.Helper()
	line, err := e.MarshalLine()
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(r.journalPath(), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(line); err != nil {
		t.Fatal(err)
	}
}

// boxApproves plays the box's approval server for r.req: it accepts only an
// answer that verifies under the box's public key for the prompt it asked, and
// journals the response, as internal/agentbox does.
func (r *inputsRun) boxApproves(t *testing.T, pub ed25519.PublicKey) {
	t.Helper()
	go func() {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if b, err := os.ReadFile(r.answerPath(r.req.RequestID)); err == nil {
				if a, err := coderun.VerifyAnswer(pub, r.run, r.req.RequestID, coderun.PromptDigest(r.req.Prompt), string(b)); err == nil {
					line, _ := coderun.InputEvent{Kind: coderun.KindInputResponse, T: time.Now().UTC(), RequestID: r.req.RequestID, Answer: a, Reason: coderun.ReasonAnswered}.MarshalLine()
					f, err := os.OpenFile(r.journalPath(), os.O_WRONLY|os.O_APPEND, 0o600)
					if err == nil {
						_, _ = f.Write(line)
						_ = f.Close()
					}
					return
				}
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
}

func (r *inputsRun) publicKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	resp, err := r.s.GetRunApprovalKey(tenantCtx(r.owner), &pb.GetRunApprovalKeyRequest{Username: r.owner})
	if err != nil {
		t.Fatalf("GetRunApprovalKey: %v", err)
	}
	pub, err := coderun.ParseApprovalPublicKey(resp.GetPublicKey())
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func (r *inputsRun) answer(a pb.RunInputAnswer, prompt string) (*pb.AnswerRunInputResponse, error) {
	return r.s.AnswerRunInput(tenantCtx(r.owner), &pb.AnswerRunInputRequest{
		Username: r.owner, RunName: r.run, RequestId: r.req.RequestID, Answer: a,
		PromptSha256: coderun.PromptDigest(prompt),
	})
}

// The key is per box, stable for one daemon secret, and differs per box and
// per secret.
func TestApprovalKeyIsPerBoxAndPerSecret(t *testing.T) {
	s := &ContainerServer{approvalSecret: []byte("one")}
	a1, err := s.approvalKey("alice")
	if err != nil {
		t.Fatal(err)
	}
	a2, _ := s.approvalKey("alice")
	b, _ := s.approvalKey("bob")
	other, _ := (&ContainerServer{approvalSecret: []byte("two")}).approvalKey("alice")
	if !bytes.Equal(a1, a2) || bytes.Equal(a1, b) || bytes.Equal(a1, other) {
		t.Error("approval key is not a stable per-box, per-secret derivation")
	}
	if _, err := (&ContainerServer{}).approvalKey("alice"); err == nil {
		t.Error("a daemon with no secret produced a key")
	}
}

// answer → the box accepts it and resumes: the outcome is ANSWERED with the
// box's own journaled response.
func TestAnswerRunInput_AnswerResumesTheRun(t *testing.T) {
	r := startInputsRun(t, time.Minute)
	r.boxApproves(t, r.publicKey(t))

	resp, err := r.answer(pb.RunInputAnswer_RUN_INPUT_ANSWER_ALLOW, r.req.Prompt)
	if err != nil {
		t.Fatalf("AnswerRunInput: %v", err)
	}
	if resp.GetOutcome() != pb.RunInputAnswerOutcome_RUN_INPUT_ANSWER_OUTCOME_ANSWERED ||
		resp.GetClosedAnswer() != pb.RunInputAnswer_RUN_INPUT_ANSWER_ALLOW ||
		resp.GetCloseReason() != pb.RunInputCloseReason_RUN_INPUT_CLOSE_REASON_ANSWERED || resp.GetClosedAt() == nil {
		t.Fatalf("response = %v, want ANSWERED allow", resp)
	}
}

// A second answer to a closed request writes nothing and reports how it was
// closed — even an answer the other way.
func TestAnswerRunInput_DuplicateAnswerIsIdempotent(t *testing.T) {
	r := startInputsRun(t, time.Minute)
	r.boxApproves(t, r.publicKey(t))
	if _, err := r.answer(pb.RunInputAnswer_RUN_INPUT_ANSWER_ALLOW, r.req.Prompt); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(r.answerPath(r.req.RequestID))
	if err != nil {
		t.Fatal(err)
	}

	resp, err := r.answer(pb.RunInputAnswer_RUN_INPUT_ANSWER_DENY, r.req.Prompt)
	if err != nil {
		t.Fatalf("second AnswerRunInput: %v", err)
	}
	if resp.GetOutcome() != pb.RunInputAnswerOutcome_RUN_INPUT_ANSWER_OUTCOME_ALREADY_CLOSED ||
		resp.GetClosedAnswer() != pb.RunInputAnswer_RUN_INPUT_ANSWER_ALLOW {
		t.Fatalf("response = %v, want ALREADY_CLOSED allow", resp)
	}
	if again, _ := os.ReadFile(r.answerPath(r.req.RequestID)); !bytes.Equal(again, first) {
		t.Error("a duplicate answer changed the answer file")
	}
}

// An expired request is refused with EXPIRED, and nothing is written.
func TestAnswerRunInput_ExpiredRequestIsRefused(t *testing.T) {
	r := startInputsRun(t, -time.Second)
	resp, err := r.answer(pb.RunInputAnswer_RUN_INPUT_ANSWER_ALLOW, r.req.Prompt)
	if err != nil {
		t.Fatalf("AnswerRunInput: %v", err)
	}
	if resp.GetOutcome() != pb.RunInputAnswerOutcome_RUN_INPUT_ANSWER_OUTCOME_EXPIRED {
		t.Fatalf("outcome = %v, want EXPIRED", resp.GetOutcome())
	}
	if _, err := os.Stat(r.answerPath(r.req.RequestID)); !os.IsNotExist(err) {
		t.Errorf("an answer was written for an expired request (stat err %v)", err)
	}
}

// A request id that is not in this run's journal — say one from another run —
// is NotFound, and nothing is written.
func TestAnswerRunInput_WrongRunIsRefused(t *testing.T) {
	r := startInputsRun(t, time.Minute)
	resp, err := r.s.AnswerRunInput(tenantCtx(r.owner), &pb.AnswerRunInputRequest{
		Username: r.owner, RunName: r.run, RequestId: "req-fedcba9876543210",
		Answer: pb.RunInputAnswer_RUN_INPUT_ANSWER_ALLOW, PromptSha256: coderun.PromptDigest(r.req.Prompt),
	})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("AnswerRunInput(other run's id) = %v, %v; want NotFound", resp, err)
	}
	if _, err := os.Stat(r.answerPath("req-fedcba9876543210")); !os.IsNotExist(err) {
		t.Error("an answer was written for a request this run never asked")
	}
}

// An answer for a prompt other than the one the box asked — what a human
// answers after the agent rewrote the journal line — is written but never
// accepted by the box: NOT_CONFIRMED, never ANSWERED.
func TestAnswerRunInput_SpoofedPromptIsNotConfirmed(t *testing.T) {
	r := startInputsRun(t, time.Minute)
	r.s.runInputConfirmWait = 300 * time.Millisecond
	r.boxApproves(t, r.publicKey(t))

	resp, err := r.answer(pb.RunInputAnswer_RUN_INPUT_ANSWER_ALLOW, "Bash: ls")
	if err != nil {
		t.Fatalf("AnswerRunInput: %v", err)
	}
	if resp.GetOutcome() != pb.RunInputAnswerOutcome_RUN_INPUT_ANSWER_OUTCOME_NOT_CONFIRMED {
		t.Fatalf("outcome = %v, want NOT_CONFIRMED", resp.GetOutcome())
	}
}

func TestAnswerRunInput_ValidatesTheRequest(t *testing.T) {
	s := &ContainerServer{approvalSecret: []byte("x")}
	ctx := tenantCtx("alice")
	good := func() *pb.AnswerRunInputRequest {
		return &pb.AnswerRunInputRequest{Username: "alice", RunName: "code", RequestId: "req-0123456789abcdef",
			Answer: pb.RunInputAnswer_RUN_INPUT_ANSWER_ALLOW, PromptSha256: coderun.PromptDigest("p")}
	}
	cases := map[string]func(*pb.AnswerRunInputRequest){
		"bad request id":   func(r *pb.AnswerRunInputRequest) { r.RequestId = "../x" },
		"no answer":        func(r *pb.AnswerRunInputRequest) { r.Answer = pb.RunInputAnswer_RUN_INPUT_ANSWER_UNSPECIFIED },
		"short digest":     func(r *pb.AnswerRunInputRequest) { r.PromptSha256 = []byte{1, 2, 3} },
		"bad run name":     func(r *pb.AnswerRunInputRequest) { r.RunName = "a b" },
		"bad box username": func(r *pb.AnswerRunInputRequest) { r.Username = "a/b" },
	}
	for name, mutate := range cases {
		req := good()
		mutate(req)
		if _, err := s.AnswerRunInput(ctx, req); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: err = %v, want InvalidArgument", name, err)
		}
	}
}

func TestAnswerRunInput_OtherTenantIsRefused(t *testing.T) {
	s := &ContainerServer{approvalSecret: []byte("x"), boxRunCollaborator: func(string, string) (bool, error) { return false, nil }}
	_, err := s.AnswerRunInput(tenantCtx("mallory"), &pb.AnswerRunInputRequest{Username: "alice", RunName: "code",
		RequestId: "req-0123456789abcdef", Answer: pb.RunInputAnswer_RUN_INPUT_ANSWER_ALLOW, PromptSha256: coderun.PromptDigest("p")})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err = %v, want PermissionDenied", err)
	}
	if _, err := s.GetRunApprovalKey(tenantCtx("mallory"), &pb.GetRunApprovalKeyRequest{Username: "alice"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("GetRunApprovalKey err = %v, want PermissionDenied", err)
	}
}

// ListRunInputs reports the open request with its raw prompt and the per-run
// counts, and nothing open once it is answered.
func TestListRunInputs_ReportsOpenRequestsAndCounts(t *testing.T) {
	r := startInputsRun(t, time.Minute)
	list := func() *pb.ListRunInputsResponse {
		t.Helper()
		resp, err := r.s.ListRunInputs(tenantCtx(r.owner), &pb.ListRunInputsRequest{Username: r.owner, RunName: r.run})
		if err != nil {
			t.Fatalf("ListRunInputs: %v", err)
		}
		return resp
	}
	resp := list()
	if !resp.GetRunning() || resp.GetRequests() != 1 || len(resp.GetOpen()) != 1 {
		t.Fatalf("response = %v, want one open request on a running run", resp)
	}
	o := resp.GetOpen()[0]
	if o.GetRequestId() != r.req.RequestID || o.GetPrompt() != r.req.Prompt || o.GetTool() != "Bash" ||
		o.GetKind() != pb.RunInputKind_RUN_INPUT_KIND_PERMISSION || o.GetExpiresAt().AsTime().Unix() != r.req.ExpiresAt.Unix() {
		t.Errorf("open request = %v", o)
	}

	r.boxApproves(t, r.publicKey(t))
	if _, err := r.answer(pb.RunInputAnswer_RUN_INPUT_ANSWER_DENY, r.req.Prompt); err != nil {
		t.Fatal(err)
	}
	if resp := list(); len(resp.GetOpen()) != 0 || resp.GetDenied() != 1 {
		t.Errorf("after the answer: %v, want nothing open and one denied", resp)
	}
}

func TestListRunInputs_NoRunIsNotFound(t *testing.T) {
	r := startInputsRun(t, time.Minute)
	_, err := r.s.ListRunInputs(tenantCtx(r.owner), &pb.ListRunInputsRequest{Username: r.owner, RunName: "nope"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("err = %v, want NotFound", err)
	}
}
