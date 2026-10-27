package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/footprintai/containarium/internal/coderun"
	"github.com/footprintai/containarium/internal/runlog"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// fakeRunInputs is a daemon with one run's requests.
type fakeRunInputs struct {
	mu   sync.Mutex
	list *pb.ListRunInputsResponse
	// lists, when set, are returned in turn by successive ListRunInputs calls
	// (the last one repeats).
	lists    []*pb.ListRunInputsResponse
	answer   *pb.AnswerRunInputResponse
	answers  []*pb.AnswerRunInputRequest
	onAnswer func() // runs as the answer is sent
}

func (f *fakeRunInputs) ListRunInputs(*pb.ListRunInputsRequest) (*pb.ListRunInputsResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.lists) > 0 {
		l := f.lists[0]
		if len(f.lists) > 1 {
			f.lists = f.lists[1:]
		}
		return l, nil
	}
	return f.list, nil
}

func (f *fakeRunInputs) AnswerRunInput(req *pb.AnswerRunInputRequest) (*pb.AnswerRunInputResponse, error) {
	if f.onAnswer != nil {
		f.onAnswer()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answers = append(f.answers, req)
	return f.answer, nil
}

func (f *fakeRunInputs) GetRunApprovalKey(string) (*pb.GetRunApprovalKeyResponse, error) {
	return nil, errors.New("not used")
}

func (f *fakeRunInputs) Close() error { return nil }

func (f *fakeRunInputs) sent() []*pb.AnswerRunInputRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*pb.AnswerRunInputRequest(nil), f.answers...)
}

// inputFor is the complete Bash input behind a "Bash: <command>" prompt.
func inputFor(prompt string) string {
	b, _ := json.Marshal(map[string]string{"command": strings.TrimPrefix(prompt, "Bash: ")})
	return string(b)
}

// digestOf is the request digest an answer for that prompt's request binds.
func digestOf(prompt string) []byte { return coderun.RequestDigest("Bash", inputFor(prompt)) }

func openRequest(now time.Time, id, prompt string) *pb.RunInput {
	return &pb.RunInput{RequestId: id, Kind: pb.RunInputKind_RUN_INPUT_KIND_PERMISSION, Tool: "Bash", Prompt: prompt, Input: inputFor(prompt),
		CreatedAt: timestamppb.New(now.Add(-90 * time.Second)), ExpiresAt: timestamppb.New(now.Add(10 * time.Minute))}
}

func TestCodePendingListsOpenRequests(t *testing.T) {
	now := time.Now()
	api := &fakeRunInputs{list: &pb.ListRunInputsResponse{Running: true, Requests: 3, Allowed: 1, Expired: 1,
		Open: []*pb.RunInput{openRequest(now, "req-0123456789abcdef", "Bash: git push\x1b[2K")}}}
	var out bytes.Buffer
	if err := codePending(api, "alice", "code", &out, now); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, want := range []string{"REQUEST", "req-0123456789abcdef", "1m30s", "10m0s", `Bash: git push\x1b[2K`,
		"permission requests: 3 (allowed 1, denied 0, expired 1, cancelled 0, open 1)"} {
		if !strings.Contains(got, want) {
			t.Errorf("output lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "\x1b") {
		t.Errorf("a raw escape from the prompt reached the terminal:\n%q", got)
	}
}

func deployRequest(now time.Time) *pb.ListRunInputsResponse {
	return &pb.ListRunInputsResponse{Running: true, Open: []*pb.RunInput{openRequest(now, "req-0123456789abcdef", "Bash: make deploy")}}
}

var answeredAllow = &pb.AnswerRunInputResponse{Outcome: pb.RunInputAnswerOutcome_RUN_INPUT_ANSWER_OUTCOME_ANSWERED,
	ClosedAnswer: pb.RunInputAnswer_RUN_INPUT_ANSWER_ALLOW, CloseReason: pb.RunInputCloseReason_RUN_INPUT_CLOSE_REASON_ANSWERED}

// `code answer` prints the request, complete input included, and has an
// allow confirmed BEFORE anything is sent, and the answer is signed for the
// printed request (#2184 review: it used to be printed only after sending,
// and only as a one-line prompt).
func TestCodeAnswerConfirmsThePrintedPromptBeforeSending(t *testing.T) {
	api := &fakeRunInputs{list: deployRequest(time.Now()), answer: answeredAllow}
	var out bytes.Buffer
	var shownAtSend string
	api.onAnswer = func() { shownAtSend = out.String() }

	err := codeAnswer(api, "alice", "code", "req-0123456789abcdef", pb.RunInputAnswer_RUN_INPUT_ANSWER_ALLOW,
		answerConfirm{tty: true, in: strings.NewReader("y\n")}, &out)
	if err != nil {
		t.Fatalf("codeAnswer: %v", err)
	}
	want := "request req-0123456789abcdef: Bash: make deploy\n  an allow permits exactly this:\n  tool:  Bash\n  input: {\"command\":\"make deploy\"}\nallow? [y/N] "
	if !strings.Contains(shownAtSend, want) {
		t.Errorf("at send time the output was %q, want the prompt, the complete input and the question", shownAtSend)
	}
	sent := api.sent()
	if len(sent) != 1 || !bytes.Equal(sent[0].GetRequestSha256(), digestOf("Bash: make deploy")) ||
		sent[0].GetAnswer() != pb.RunInputAnswer_RUN_INPUT_ANSWER_ALLOW || sent[0].GetRunName() != "code" {
		t.Fatalf("sent %v, want an allow bound to the printed prompt", sent)
	}
	if !strings.Contains(out.String(), "allowed req-0123456789abcdef: Bash: make deploy") {
		t.Errorf("output = %q", out.String())
	}
}

// The raw tool is shown before an allow, not only the prompt: the prompt is
// the agent's to write, and the answer is signed for the tool (#2184 review).
func TestCodeAnswerShowsTheRawToolBeforeAnAllow(t *testing.T) {
	req := &pb.RunInput{RequestId: "req-0123456789abcdef", Tool: "mcp__deploy__delete_environment",
		Prompt: "Inventory lookup: prod", Input: `{"name":"prod"}`}
	api := &fakeRunInputs{list: &pb.ListRunInputsResponse{Running: true, Open: []*pb.RunInput{req}}, answer: answeredAllow}
	var out bytes.Buffer
	var shownAtSend string
	api.onAnswer = func() { shownAtSend = out.String() }
	if err := codeAnswer(api, "alice", "code", req.RequestId, pb.RunInputAnswer_RUN_INPUT_ANSWER_ALLOW,
		answerConfirm{tty: true, in: strings.NewReader("y\n")}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(shownAtSend, "tool:  mcp__deploy__delete_environment") {
		t.Errorf("the tool was not shown before the allow was sent:\n%s", shownAtSend)
	}
	if sent := api.sent(); len(sent) != 1 || !bytes.Equal(sent[0].GetRequestSha256(), coderun.RequestDigest(req.Tool, req.Input)) {
		t.Fatalf("sent %v", sent)
	}
}

func TestCodeAnswerAllowNeedsConfirmation(t *testing.T) {
	cases := map[string]answerConfirm{
		"answered no":           {tty: true, in: strings.NewReader("n\n")},
		"no answer at all":      {tty: true, in: strings.NewReader("")},
		"no terminal, no --yes": {in: strings.NewReader("y\n")},
	}
	for name, c := range cases {
		api := &fakeRunInputs{list: deployRequest(time.Now()), answer: answeredAllow}
		err := codeAnswer(api, "alice", "code", "req-0123456789abcdef", pb.RunInputAnswer_RUN_INPUT_ANSWER_ALLOW, c, &bytes.Buffer{})
		if err == nil {
			t.Errorf("%s: allowed without confirmation", name)
		}
		if len(api.sent()) != 0 {
			t.Errorf("%s: an answer was sent", name)
		}
	}
}

// --yes sends an allow without a terminal; a deny is never asked about.
func TestCodeAnswerYesAndDenyNeedNoQuestion(t *testing.T) {
	for name, c := range map[string]struct {
		a   pb.RunInputAnswer
		yes bool
	}{
		"allow --yes": {pb.RunInputAnswer_RUN_INPUT_ANSWER_ALLOW, true},
		"deny":        {pb.RunInputAnswer_RUN_INPUT_ANSWER_DENY, false},
	} {
		api := &fakeRunInputs{list: deployRequest(time.Now()), answer: answeredAllow}
		var out bytes.Buffer
		if err := codeAnswer(api, "alice", "code", "req-0123456789abcdef", c.a, answerConfirm{yes: c.yes}, &out); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if len(api.sent()) != 1 || strings.Contains(out.String(), "[y/N]") {
			t.Errorf("%s: sent %d answers, output %q", name, len(api.sent()), out.String())
		}
	}
}

// If the prompt changes between printing it and sending, nothing is sent.
func TestCodeAnswerRefusesWhenThePromptChangedAfterPrinting(t *testing.T) {
	now := time.Now()
	api := &fakeRunInputs{lists: []*pb.ListRunInputsResponse{
		{Running: true, Open: []*pb.RunInput{openRequest(now, "req-0123456789abcdef", "Bash: ls")}},
		{Running: true, Open: []*pb.RunInput{openRequest(now, "req-0123456789abcdef", "Bash: rm -rf ~/repo")}},
	}, answer: answeredAllow}
	err := codeAnswer(api, "alice", "code", "req-0123456789abcdef", pb.RunInputAnswer_RUN_INPUT_ANSWER_ALLOW,
		answerConfirm{tty: true, in: strings.NewReader("y\n")}, &bytes.Buffer{})
	if !errors.Is(err, runlog.ErrRequestChanged) {
		t.Fatalf("err = %v, want ErrRequestChanged", err)
	}
	if len(api.sent()) != 0 {
		t.Error("an answer was sent for a prompt the user did not see")
	}
}

// Answering an already-closed or expired request, or one the run did not take,
// prints the outcome and exits non-zero.
func TestCodeAnswerIdempotentCasesExitNonZero(t *testing.T) {
	cases := map[string]struct {
		resp *pb.AnswerRunInputResponse
		want string
	}{
		"already closed": {&pb.AnswerRunInputResponse{Outcome: pb.RunInputAnswerOutcome_RUN_INPUT_ANSWER_OUTCOME_ALREADY_CLOSED,
			ClosedAnswer: pb.RunInputAnswer_RUN_INPUT_ANSWER_DENY, CloseReason: pb.RunInputCloseReason_RUN_INPUT_CLOSE_REASON_ANSWERED,
			ClosedAt: timestamppb.New(time.Date(2026, 10, 27, 8, 0, 0, 0, time.UTC))}, "already closed: deny (answered) at 2026-10-27T08:00:00Z"},
		"expired":       {&pb.AnswerRunInputResponse{Outcome: pb.RunInputAnswerOutcome_RUN_INPUT_ANSWER_OUTCOME_EXPIRED}, "has expired"},
		"not confirmed": {&pb.AnswerRunInputResponse{Outcome: pb.RunInputAnswerOutcome_RUN_INPUT_ANSWER_OUTCOME_NOT_CONFIRMED}, "has not reported taking it"},
	}
	for name, c := range cases {
		api := &fakeRunInputs{list: &pb.ListRunInputsResponse{Running: true}, answer: c.resp}
		var out bytes.Buffer
		err := codeAnswer(api, "alice", "code", "req-0123456789abcdef", pb.RunInputAnswer_RUN_INPUT_ANSWER_ALLOW, answerConfirm{}, &out)
		if !errors.Is(err, runlog.ErrNotAnswered) {
			t.Errorf("%s: err = %v, want ErrNotAnswered", name, err)
		}
		if !strings.Contains(out.String(), c.want) {
			t.Errorf("%s: output = %q, want %q", name, out.String(), c.want)
		}
	}
}

func TestCodeAnswerRejectsAnUnknownAnswerWord(t *testing.T) {
	if err := runCodeAnswer(codeAnswerCmd, []string{"alice", "req-0123456789abcdef", "maybe"}); err == nil {
		t.Fatal("answer \"maybe\" accepted")
	}
}

// In attach, a line "a" answers the oldest open request with the prompt that
// was printed for it; output goes to diag, never stdout.
func TestInlineAnswersAllowTheOldestPrintedRequest(t *testing.T) {
	defer func(d time.Duration) { codeInputPollInterval = d }(codeInputPollInterval)
	codeInputPollInterval = 10 * time.Millisecond
	now := time.Now()
	api := &fakeRunInputs{
		list: &pb.ListRunInputsResponse{Running: true, Open: []*pb.RunInput{
			openRequest(now, "req-0000000000000001", "Bash: first"), openRequest(now, "req-0000000000000002", "Bash: second")}},
		answer: &pb.AnswerRunInputResponse{Outcome: pb.RunInputAnswerOutcome_RUN_INPUT_ANSWER_OUTCOME_ANSWERED,
			ClosedAnswer: pb.RunInputAnswer_RUN_INPUT_ANSWER_ALLOW},
	}
	inR, inW := io.Pipe()
	diag := &syncBuffer{}
	stop := startInlineAnswers(context.Background(), func() (runInputsAPI, error) { return api, nil }, "alice", "code", inR, diag)
	defer stop()

	waitFor(t, func() bool { return strings.Contains(diag.String(), "req-0000000000000002") })
	_, _ = io.WriteString(inW, "a\n")
	waitFor(t, func() bool { return len(api.sent()) == 1 })

	sent := api.sent()[0]
	if sent.GetRequestId() != "req-0000000000000001" || !bytes.Equal(sent.GetRequestSha256(), digestOf("Bash: first")) ||
		sent.GetAnswer() != pb.RunInputAnswer_RUN_INPUT_ANSWER_ALLOW {
		t.Fatalf("sent %v, want an allow for the oldest request bound to its printed prompt", sent)
	}
	waitFor(t, func() bool { return strings.Contains(diag.String(), "allowed req-0000000000000001") })
	if strings.Count(diag.String(), "request req-0000000000000001:") != 1 {
		t.Errorf("a request was printed more than once:\n%s", diag.String())
	}
}

// The answer is bound to the prompt that was printed, not to whatever the
// journal says by the time the user types: if the prompt of a printed request
// changes, it is printed again, and the answer binds the latest printed text
// (#2184 review: the agent can show one prompt and then restore another).
func TestInlineAnswersBindThePrintedPromptWhenTheJournalChanges(t *testing.T) {
	defer func(d time.Duration) { codeInputPollInterval = d }(codeInputPollInterval)
	codeInputPollInterval = time.Hour // refreshes only when the test asks
	now := time.Now()
	api := &fakeRunInputs{
		list:   &pb.ListRunInputsResponse{Running: true, Open: []*pb.RunInput{openRequest(now, "req-0000000000000001", "Bash: ls")}},
		answer: &pb.AnswerRunInputResponse{Outcome: pb.RunInputAnswerOutcome_RUN_INPUT_ANSWER_OUTCOME_NOT_CONFIRMED},
	}
	diag := &syncBuffer{}
	w := &inlineAnswers{api: api, box: "alice", run: "code", diag: diag, shown: map[string]*pb.RunInput{}}
	w.refresh()

	// The journal now shows the real prompt, but nothing printed it yet.
	api.mu.Lock()
	api.list = &pb.ListRunInputsResponse{Running: true, Open: []*pb.RunInput{openRequest(now, "req-0000000000000001", "Bash: rm -rf ~/repo")}}
	api.mu.Unlock()
	w.read(context.Background(), strings.NewReader("a\n"))

	sent := api.sent()
	if len(sent) != 1 || !bytes.Equal(sent[0].GetRequestSha256(), digestOf("Bash: ls")) {
		t.Fatalf("sent %v, want the answer bound to the printed prompt \"Bash: ls\"", sent)
	}
	// The read's own refresh prints the changed prompt, so the next answer
	// binds what is on screen then.
	if !strings.Contains(diag.String(), "Bash: rm -rf ~/repo") {
		t.Errorf("the changed prompt was not printed:\n%s", diag.String())
	}
	w.read(context.Background(), strings.NewReader("a\n"))
	if sent := api.sent(); len(sent) != 2 || !bytes.Equal(sent[1].GetRequestSha256(), digestOf("Bash: rm -rf ~/repo")) {
		t.Fatalf("second answer %v, want it bound to the reprinted prompt", sent)
	}
}

func TestInlineAnswersWithoutADaemonPrintsOneNote(t *testing.T) {
	var diag bytes.Buffer
	stop := startInlineAnswers(context.Background(), func() (runInputsAPI, error) { return nil, errors.New("--server is required") }, "alice", "code", strings.NewReader(""), &diag)
	stop()
	if !strings.Contains(diag.String(), "cannot be answered here") {
		t.Errorf("diag = %q", diag.String())
	}
}

// With --approvals ask, a daemon that cannot give the box's approval key
// stops the run before the box session is resolved.
func TestRunCodeRunAskNeedsTheDaemonKeyFirst(t *testing.T) {
	defer func(a, n, p string, f func() (runInputsAPI, error)) {
		codeRunApprovals, codeName, codeRunPrompt, newRunInputsClient = a, n, p, f
	}(codeRunApprovals, codeName, codeRunPrompt, newRunInputsClient)
	codeRunApprovals, codeName, codeRunPrompt = "ask", "", "p"
	newRunInputsClient = func() (runInputsAPI, error) { return nil, errors.New("--server is required") }

	err := runCodeRun(codeRunCmd, []string{"some-box"})
	if err == nil || !strings.Contains(err.Error(), "--server is required") {
		t.Fatalf("err = %v, want the daemon error", err)
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in 5s")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
