package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/footprintai/containarium/internal/client"
	"github.com/footprintai/containarium/internal/runlog"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

// `containarium code runs|logs` (#2123) read a box's code runs through the
// daemon API (ListBoxRuns / TailBoxRunLog) instead of SSH: the same reads a
// browser or phone makes. `code attach` keeps its SSH path.

var codeLogsFollow bool

var codeRunsCmd = &cobra.Command{
	Use:   "runs <box>",
	Short: "List a box's code runs through the daemon API",
	Long: `List the code runs on a box (containarium code run): name, outcome
(running, exited, or unknown when the run was killed or the box restarted),
exit code, start and end time, and the log path inside the box.

Reads the box's run records through the daemon API, so it needs no SSH access
of its own — only a token that may connect to the box (its owner or a
collaborator, with the ssh:write scope).

Examples:
  containarium code runs alice --server <host>
  containarium code runs alice --server <host> --http`,
	Args: cobra.ExactArgs(1),
	RunE: runCodeRuns,
}

var codeLogsCmd = &cobra.Command{
	Use:   "logs <box> <run>",
	Short: "Print a box code run's output through the daemon API",
	Long: `Print a code run's output from its log on the box.

--follow keeps reading until the run has exited; a dropped connection loses
nothing, since every read resumes at the byte offset the previous one ended at.
For a run started with stream-json output (a framed log) only stdout is
printed; a note on stderr says when the run's stderr was left out — read it
with ` + "`containarium code attach`" + `.

Examples:
  containarium code logs alice code --server <host>
  containarium code logs alice code --follow --server <host>`,
	Args: cobra.ExactArgs(2),
	RunE: runCodeLogs,
}

func init() {
	codeCmd.AddCommand(codeRunsCmd)
	codeCmd.AddCommand(codeLogsCmd)
	codeLogsCmd.Flags().BoolVarP(&codeLogsFollow, "follow", "f", false, "Keep reading until the run exits")
}

// boxRunsAPI is what code runs/logs need from a daemon client.
type boxRunsAPI interface {
	runlog.BoxLister
	runlog.BoxTailer
	Close() error
}

func newBoxRunsClient() (boxRunsAPI, error) {
	if serverAddr == "" {
		return nil, fmt.Errorf("--server is required")
	}
	if httpMode {
		return client.NewHTTPClient(serverAddr, authToken)
	}
	return client.NewGRPCClient(serverAddr, certsDir, insecure)
}

func runCodeRuns(cmd *cobra.Command, args []string) error {
	if err := validateBoxName(args[0]); err != nil {
		return err
	}
	c, err := newBoxRunsClient()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	return codeRuns(c, args[0], os.Stdout)
}

func runCodeLogs(cmd *cobra.Command, args []string) error {
	if err := validateBoxName(args[0]); err != nil {
		return err
	}
	c, err := newBoxRunsClient()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	return codeLogs(cmd, c, args[0], args[1], codeLogsFollow, os.Stdout, os.Stderr)
}

// codeRuns prints the box's runs through the formatter the MCP code_runs
// tool also uses.
func codeRuns(l runlog.BoxLister, box string, w io.Writer) error {
	runs, err := l.ListBoxRuns(box)
	if err != nil {
		return fmt.Errorf("list code runs on %s: %w", box, err)
	}
	return runlog.WriteBoxRuns(w, box, runs)
}

// codeLogs copies the run's output to w through runlog.CopyBox, the reader
// the MCP code_logs tool's window comes from; diagnostics go to diag.
func codeLogs(cmd *cobra.Command, t runlog.BoxTailer, box, run string, follow bool, w, diag io.Writer) error {
	end, stderrDropped, err := runlog.CopyBox(cmd.Context(), t, &pb.TailBoxRunLogRequest{Username: box, RunName: run}, w, follow)
	if stderrDropped {
		_, _ = fmt.Fprintf(diag, "note: run %q writes a framed log; its stderr was not printed (see `containarium code attach %s --name %s`)\n", run, box, run)
	}
	if err != nil {
		return fmt.Errorf("%w (read up to byte %d)", err, end)
	}
	return nil
}
