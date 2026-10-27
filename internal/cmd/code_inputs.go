package cmd

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/footprintai/containarium/internal/client"
	"github.com/footprintai/containarium/internal/coderun"
	"github.com/footprintai/containarium/internal/runlog"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// Permission requests of a `code run --approvals ask` run (#2184), answered
// through the daemon API: the daemon holds the box's approval key and signs.

var codePendingCmd = &cobra.Command{
	Use:   "pending <box>",
	Short: "List a run's open permission requests",
	Long: `Lists the open permission requests of a run started with
'code run --approvals ask': request id, age, time left before it expires into
a deny, and the prompt (the tool and its command or path), followed by the
run's request counts. Answer one with 'containarium code answer'.

The list comes from the run's journal on the box, which the agent can write
too, so treat it as advisory: an answer is signed for the prompt it was given,
and the run ignores it unless that is the prompt it actually asked.

Reads through the daemon API (--server).`,
	Args: cobra.ExactArgs(1),
	RunE: runCodePending,
}

var codeAnswerCmd = &cobra.Command{
	Use:   "answer <box> <request_id> allow|deny",
	Short: "Answer one permission request of a run",
	Long: `Answers one open permission request of a run started with
'code run --approvals ask'. The request's prompt is read again and printed
with the result: the answer is signed for exactly that prompt, so the run
acts on it only if that is the prompt it asked. If the journal changed since
you ran 'code pending', what you answer is what this command prints; for an
answer bound to the prompt you are looking at, answer inline in 'code attach'.

Answering a request that is already answered or has expired changes nothing,
prints how it was closed, and exits non-zero; so does an answer the run has
not taken within a few seconds.

Answers through the daemon API (--server).`,
	Args: cobra.ExactArgs(3),
	RunE: runCodeAnswer,
}

func init() {
	codeCmd.AddCommand(codePendingCmd)
	codeCmd.AddCommand(codeAnswerCmd)
	for _, c := range []*cobra.Command{codePendingCmd, codeAnswerCmd} {
		c.Flags().StringVar(&codeName, "name", "", "run name (default: \""+defaultCodeRunName+"\")")
	}
}

// runInputsAPI is what pending/answer/attach and `code run --approvals ask`
// need from a daemon client.
type runInputsAPI interface {
	runlog.RunInputs
	GetRunApprovalKey(username string) (*pb.GetRunApprovalKeyResponse, error)
	Close() error
}

// newRunInputsClient is the daemon client for the permission-request RPCs:
// the same --server/--http choice as `code runs|logs`.
var newRunInputsClient = func() (runInputsAPI, error) {
	if serverAddr == "" {
		return nil, fmt.Errorf("--server is required to read or answer permission requests (they are answered through the daemon)")
	}
	if httpMode {
		return client.NewHTTPClient(serverAddr, authToken)
	}
	return client.NewGRPCClient(serverAddr, certsDir, insecure)
}

func runCodePending(cmd *cobra.Command, args []string) error {
	box := args[0]
	if err := validateBoxName(box); err != nil {
		return err
	}
	c, err := newRunInputsClient()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	return codePending(c, box, codeRunName(), cmd.OutOrStdout(), time.Now())
}

// codePending prints run's open requests through the formatter the MCP
// code_pending tool also uses.
func codePending(api runlog.RunInputs, box, run string, w io.Writer, now time.Time) error {
	resp, err := api.ListRunInputs(&pb.ListRunInputsRequest{Username: box, RunName: run})
	if err != nil {
		return fmt.Errorf("list permission requests of run %s on %s: %w", run, box, err)
	}
	return runlog.WriteRunInputs(w, run, resp, now)
}

func runCodeAnswer(cmd *cobra.Command, args []string) error {
	box, id := args[0], args[1]
	if err := validateBoxName(box); err != nil {
		return err
	}
	a, err := runlog.ParseRunInputAnswer(args[2])
	if err != nil {
		return err
	}
	c, err := newRunInputsClient()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	return codeAnswer(c, box, codeRunName(), id, a, cmd.OutOrStdout())
}

// codeAnswer answers through runlog.Answer, the function the MCP code_answer
// tool also calls. Anything but a fresh answer the run took is an error, so
// the command exits non-zero.
func codeAnswer(api runlog.RunInputs, box, run, id string, a pb.RunInputAnswer, w io.Writer) error {
	res, err := runlog.Answer(api, box, run, id, a)
	if err != nil {
		return err
	}
	if err := runlog.WriteAnswerResult(w, res); err != nil {
		return fmt.Errorf("request %s on run %s: %w", id, run, err)
	}
	return nil
}

// codeInputPollInterval is how often `code attach` looks for new requests.
var codeInputPollInterval = 2 * time.Second

// stdinIsTerminal is a seam: inline answers are offered only to a human at a
// terminal.
var stdinIsTerminal = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) } // #nosec G115 -- a file descriptor

// startInlineAnswers lets a human at a terminal answer the run's permission
// requests while its output streams (#2184): each new open request is printed
// to diag (stdout stays the run's output), and a line "a" or "d" on in
// answers the oldest one printed, bound to the prompt printed for it. It
// needs the daemon (--server); without one, or on a daemon without the RPCs,
// it prints one note and stays off. The returned func stops it.
func startInlineAnswers(ctx context.Context, newClient func() (runInputsAPI, error), box, run string, in io.Reader, diag io.Writer) func() {
	c, err := newClient()
	if err != nil {
		fmt.Fprintf(diag, "note: permission requests cannot be answered here: %v\n", err)
		return func() {}
	}
	ctx, cancel := context.WithCancel(ctx)
	w := &inlineAnswers{api: c, box: box, run: run, diag: diag, shown: map[string]bool{}}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		w.poll(ctx)
	}()
	// The reader blocks on stdin and cannot be interrupted; it ends with the
	// process, and ignores lines once ctx is done.
	go w.read(ctx, in)
	return func() {
		cancel()
		wg.Wait()
		_ = c.Close()
	}
}

type inlineAnswers struct {
	api       runlog.RunInputs
	box, run  string
	diag      io.Writer
	mu        sync.Mutex
	shown     map[string]bool
	open      []*pb.RunInput // oldest first, as last listed
	reportErr bool
}

func (w *inlineAnswers) poll(ctx context.Context) {
	for {
		w.refresh()
		select {
		case <-ctx.Done():
			return
		case <-time.After(codeInputPollInterval):
		}
	}
}

func (w *inlineAnswers) refresh() {
	resp, err := w.api.ListRunInputs(&pb.ListRunInputsRequest{Username: w.box, RunName: w.run})
	w.mu.Lock()
	defer w.mu.Unlock()
	if err != nil {
		if !w.reportErr {
			w.reportErr = true
			fmt.Fprintf(w.diag, "[containarium code] cannot read permission requests: %v\n", err)
		}
		return
	}
	w.open = resp.GetOpen()
	for _, r := range w.open {
		if w.shown[r.GetRequestId()] {
			continue
		}
		w.shown[r.GetRequestId()] = true
		left := ""
		if r.GetExpiresAt() != nil {
			left = fmt.Sprintf(" (expires in %s)", time.Until(r.GetExpiresAt().AsTime()).Round(time.Second))
		}
		fmt.Fprintf(w.diag, "[containarium code] permission request %s: %s%s — type a + Enter to allow, d + Enter to deny\n",
			coderun.PlainText(r.GetRequestId()), coderun.PlainText(r.GetPrompt()), left)
	}
}

// oldest is the oldest open request that has been printed.
func (w *inlineAnswers) oldest() *pb.RunInput {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, r := range w.open {
		if w.shown[r.GetRequestId()] {
			return r
		}
	}
	return nil
}

func (w *inlineAnswers) read(ctx context.Context, in io.Reader) {
	sc := bufio.NewScanner(in)
	for sc.Scan() {
		if ctx.Err() != nil {
			return
		}
		var a pb.RunInputAnswer
		switch strings.ToLower(strings.TrimSpace(sc.Text())) {
		case "a":
			a = pb.RunInputAnswer_RUN_INPUT_ANSWER_ALLOW
		case "d":
			a = pb.RunInputAnswer_RUN_INPUT_ANSWER_DENY
		default:
			continue
		}
		r := w.oldest()
		if r == nil {
			fmt.Fprintln(w.diag, "[containarium code] no open permission request to answer")
			continue
		}
		res, err := runlog.AnswerShown(w.api, w.box, w.run, r.GetRequestId(), r.GetPrompt(), a)
		if err != nil {
			fmt.Fprintf(w.diag, "[containarium code] %v\n", err)
			continue
		}
		var out strings.Builder
		_ = runlog.WriteAnswerResult(&out, res) // ErrNotAnswered: the text says why
		fmt.Fprint(w.diag, "[containarium code] "+out.String())
		w.refresh()
	}
}

// runUsesApprovals reports whether run was started with --approvals ask: its
// approval server creates the answers directory when it starts.
func runUsesApprovals(ctx context.Context, sess approvalSession, run string) bool {
	out, err := sess.ShellExec(ctx, "[ -d "+coderun.ShellQuoteSingle(coderun.ApprovalAnswersDir(run))+" ] && echo yes")
	return err == nil && strings.TrimSpace(out) == "yes"
}
