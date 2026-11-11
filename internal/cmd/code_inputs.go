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
'code run --approvals ask'.

The request is read again and printed before anything is sent: its one-line
prompt and the tool's complete input, which is what an allow permits. The
answer is signed for exactly that tool and input, so the run acts on it only
if that is the tool call it asked. An allow needs confirmation: at a terminal
you are asked "allow? [y/N]" under the printed request. Without a terminal,
pass --yes; the allow is then signed for whatever the request is at that
moment, which you have not seen, so prefer answering at a terminal or inline
in 'code attach'. A deny is sent without asking. If the request changes
between printing and sending, nothing is sent.

Answering a request that is already answered or has expired changes nothing,
prints how it was closed, and exits non-zero; so does an answer the run has
not reported taking within a few seconds. That report comes from the run's
journal, which the agent can write, so it is not proof the tool call ran.

Answers through the daemon API (--server). The token needs the code:answer
scope as well as ssh:write; the wildcard scope and a token with no scopes do
not count. No credential the platform puts on a box carries code:answer, so
keep the token that does off the box: an operator mints it on the daemon host
with 'containarium token generate --secret-file <file> --username <you>
--scopes ssh:write,code:answer' and you pass it with --token or
CONTAINARIUM_TOKEN.
Do not run 'containarium login' inside the box the agent runs in: the
credentials it writes there are readable by the agent.`,
	Args: cobra.ExactArgs(3),
	RunE: runCodeAnswer,
}

var codeAnswerYes bool

func init() {
	codeCmd.AddCommand(codePendingCmd)
	codeCmd.AddCommand(codeAnswerCmd)
	for _, c := range []*cobra.Command{codePendingCmd, codeAnswerCmd} {
		c.Flags().StringVar(&codeName, "name", "", "run name (default: \""+defaultCodeRunName+"\")")
	}
	codeAnswerCmd.Flags().BoolVar(&codeAnswerYes, "yes", false,
		"send an allow without asking (needed without a terminal); the allow is signed for the request current at that moment, unseen")
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
	return codeAnswer(c, box, codeRunName(), id, a, answerConfirm{yes: codeAnswerYes, tty: stdinIsTerminal(), in: cmd.InOrStdin()}, cmd.OutOrStdout())
}

// answerConfirm is how `code answer` gets a human's yes for an allow.
type answerConfirm struct {
	yes bool      // --yes: do not ask
	tty bool      // stdin is a terminal
	in  io.Reader // where the y/N answer is read
}

// codeAnswer prints the request (its prompt and complete input), has an
// allow confirmed, and sends the answer signed for the printed request through
// runlog.Answer, the function the MCP code_answer tool also calls. Anything
// but a fresh answer the run reported taking is an error, so the command
// exits non-zero.
func codeAnswer(api runlog.RunInputs, box, run, id string, a pb.RunInputAnswer, confirm answerConfirm, w io.Writer) error {
	shown, err := runlog.OpenRequest(api, box, run, id)
	if err != nil {
		return err
	}
	if shown != nil {
		if err := runlog.WriteRequest(w, shown); err != nil {
			return fmt.Errorf("could not show request %s, so nothing was sent: %w", id, err)
		}
		if a == pb.RunInputAnswer_RUN_INPUT_ANSWER_ALLOW && !confirm.yes {
			if !confirm.tty {
				return fmt.Errorf("an allow needs confirmation: run 'code answer' at a terminal, or pass --yes to allow whatever the request is when it is sent")
			}
			if _, err := fmt.Fprint(w, "allow? [y/N] "); err != nil {
				return fmt.Errorf("could not ask for confirmation, so nothing was sent: %w", err)
			}
			line, _ := bufio.NewReader(confirm.in).ReadString('\n')
			if s := strings.ToLower(strings.TrimSpace(line)); s != "y" && s != "yes" {
				return fmt.Errorf("not confirmed; nothing was sent")
			}
		}
	}
	res, err := runlog.Answer(api, box, run, id, shown, a)
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
// to diag (stdout stays the run's output), and printed again if its prompt
// changes; a line "a" or "d" on in answers the oldest one printed, bound to
// the request (tool and complete input) as last printed. It
// needs the daemon (--server); without one, or on a daemon without the RPCs,
// it prints one note and stays off. The returned func stops it.
func startInlineAnswers(ctx context.Context, newClient func() (runInputsAPI, error), box, run string, in io.Reader, diag io.Writer) func() {
	c, err := newClient()
	if err != nil {
		fmt.Fprintf(diag, "note: permission requests cannot be answered here: %v\n", err)
		return func() {}
	}
	ctx, cancel := context.WithCancel(ctx)
	w := &inlineAnswers{api: c, box: box, run: run, diag: diag, shown: map[string]*pb.RunInput{}}
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
	api      runlog.RunInputs
	box, run string
	diag     io.Writer
	mu       sync.Mutex
	// shown maps each printed request id to the request as last printed: an
	// answer binds that, never a later journal read the user has not seen.
	shown     map[string]*pb.RunInput
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
		prev, printed := w.shown[r.GetRequestId()]
		if printed && prev.GetTool() == r.GetTool() && prev.GetInput() == r.GetInput() && prev.GetPrompt() == r.GetPrompt() {
			continue
		}
		what := "permission request"
		if printed {
			// The journal is the agent's to write: say so when a request
			// already on screen changes, and bind answers to the new text.
			what = "permission request CHANGED"
		}
		left := ""
		if r.GetExpiresAt() != nil {
			left = fmt.Sprintf(" (expires in %s)", time.Until(r.GetExpiresAt().AsTime()).Round(time.Second))
		}
		var b strings.Builder
		_ = runlog.WriteRequest(&b, r) // a strings.Builder does not fail
		// Only a request that was actually printed can be answered.
		// a / d answers the oldest printed request, which need not be this
		// one: name it, so an allow never lands on a request the user did
		// not mean.
		target := r.GetRequestId()
		if t := w.oldestLocked(); t != nil {
			target = t.GetRequestId()
		}
		if _, err := fmt.Fprintf(w.diag, "[containarium code] %s%s\n%s[containarium code] a + Enter allows, d + Enter denies %s\n",
			what, left, b.String(), coderun.PlainText(target)); err != nil {
			continue
		}
		w.shown[r.GetRequestId()] = r
	}
}

// oldest is the oldest open request that has been printed, as printed.
func (w *inlineAnswers) oldest() *pb.RunInput {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.oldestLocked()
}

func (w *inlineAnswers) oldestLocked() *pb.RunInput {
	for _, r := range w.open {
		if shown, printed := w.shown[r.GetRequestId()]; printed {
			return shown
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
		shown := w.oldest()
		if shown == nil {
			fmt.Fprintln(w.diag, "[containarium code] no open permission request to answer")
			continue
		}
		res, err := runlog.AnswerShown(w.api, w.box, w.run, shown, a)
		if err != nil {
			fmt.Fprintf(w.diag, "[containarium code] %v\n", err)
			continue
		}
		var out strings.Builder
		_ = runlog.WriteAnswerResult(&out, res) // ErrNotAnswered: the text says why
		fmt.Fprint(w.diag, "[containarium code] "+out.String())
		w.refresh()
		if next := w.oldest(); next != nil {
			fmt.Fprintf(w.diag, "[containarium code] a + Enter allows, d + Enter denies %s\n", coderun.PlainText(next.GetRequestId()))
		}
	}
}

// runUsesApprovals reports whether run was started with --approvals ask: its
// approval server creates the answers directory when it starts.
func runUsesApprovals(ctx context.Context, sess approvalSession, run string) bool {
	out, err := sess.ShellExec(ctx, "[ -d "+coderun.ShellQuoteSingle(coderun.ApprovalAnswersDir(run))+" ] && echo yes")
	return err == nil && strings.TrimSpace(out) == "yes"
}
