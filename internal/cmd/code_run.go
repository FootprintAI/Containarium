package cmd

import (
	"context"
	"fmt"
	"github.com/footprintai/containarium/internal/coderun"
	"strings"

	"github.com/spf13/cobra"
)

var (
	codeRunPrompt        string
	codeRunStreamJSON    bool
	codeAttachStreamJSON bool
	codeStopForce        bool
)

var codeRunCmd = &cobra.Command{
	Use:   "run <box>",
	Short: "Start a coding agent on a box and stream its output as it's produced",
	Long: `Starts claude on <box> with --prompt, detached (it survives this command's
own connection dying — see Killing the local client does not kill the run,
below), and streams its output to your terminal as it's produced: not
buffered to completion, and with no timeout on the run itself.

A mid-run network drop is recovered automatically by resuming at the last
byte offset seen — nothing is re-issued, nothing is lost or duplicated.
Killing this command (Ctrl-C, closing the laptop) does NOT kill the run;
reconnect with 'containarium code attach <box>'.

Requires the box to already have Claude Code installed and credentialed —
see 'containarium code install <box>'.`,
	Args: cobra.ExactArgs(1),
	RunE: runCodeRun,
}

var codeAttachCmd = &cobra.Command{
	Use:   "attach <box>",
	Short: "Reconnect to a running (or just-finished) run and replay its output",
	Long: `Reconnects to the run 'containarium code run' started (or one dispatched
another way with the same --name) and replays everything it has produced
since it started, byte-exact, then keeps streaming until it exits or you
disconnect again.`,
	Args: cobra.ExactArgs(1),
	RunE: runCodeAttach,
}

var codeStatusCmd = &cobra.Command{
	Use:   "status <box>",
	Short: "Report a run's liveness and, once finished, its exit code",
	Long: `Reports whether the run is still alive and, once it has finished
(including a run that finished while you were disconnected), its exit
code — 'unknown' rather than a false "finished" if the box died before
recording one.`,
	Args: cobra.ExactArgs(1),
	RunE: runCodeStatus,
}

var codeStopCmd = &cobra.Command{
	Use:   "stop <box>",
	Short: "Stop a run and leave its log readable",
	Long: `Sends SIGTERM (or SIGKILL with --force) to the run and reaps it. The log
stays on the box, readable via 'containarium code status' or another
'code attach'.`,
	Args: cobra.ExactArgs(1),
	RunE: runCodeStop,
}

func runCodeRun(cmd *cobra.Command, args []string) error {
	box := args[0]
	if strings.TrimSpace(codeRunPrompt) == "" {
		return fmt.Errorf("--prompt is required")
	}
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	diag := cmd.ErrOrStderr()
	name := codeRunName()

	sess, err := resolveCodeSession(ctx, box, diag)
	if err != nil {
		return err
	}
	defer func() { _ = sess.Close() }()

	captureMode := "combined"
	if codeRunStreamJSON {
		captureMode = "framed"
	}
	command := coderun.BuildClaudeRunCommand(codeRunPrompt, codeRunStreamJSON)

	started, err := sess.ProcessStart(ctx, name, command, "", captureMode)
	if err != nil {
		return fmt.Errorf("start run on %q: %w", box, err)
	}
	fmt.Fprintf(diag, "✓ started %q (pid %d) on %s\n", started.Name, started.PID, box)

	return streamAndWait(ctx, sess, started.Name, started.LogPath, cmd.OutOrStdout(), diag, codeRunStreamJSON)
}

func runCodeAttach(cmd *cobra.Command, args []string) error {
	box := args[0]
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	diag := cmd.ErrOrStderr()
	name := codeRunName()

	sess, err := resolveCodeSession(ctx, box, diag)
	if err != nil {
		return err
	}
	defer func() { _ = sess.Close() }()

	listing, err := sess.ProcessList(ctx)
	if err != nil {
		return fmt.Errorf("process_list on %q: %w", box, err)
	}
	line, _ := coderun.RunOutcomeLine(listing, name)
	if line == "" {
		return fmt.Errorf("no run named %q on %q — start one with `containarium code run %s --prompt ...`", name, box, box)
	}
	logPath, err := coderun.LogPathFromListing(listing, name)
	if err != nil {
		return err
	}
	fmt.Fprintf(diag, "✓ attaching to %s\n", line)

	return streamAndWait(ctx, sess, name, logPath, cmd.OutOrStdout(), diag, codeAttachStreamJSON)
}

func runCodeStatus(cmd *cobra.Command, args []string) error {
	box := args[0]
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	diag := cmd.ErrOrStderr()
	name := codeRunName()

	sess, err := resolveCodeSession(ctx, box, diag)
	if err != nil {
		return err
	}
	defer func() { _ = sess.Close() }()

	listing, err := sess.ProcessList(ctx)
	if err != nil {
		return fmt.Errorf("process_list on %q: %w", box, err)
	}
	line, _ := coderun.RunOutcomeLine(listing, name)
	if line == "" {
		return fmt.Errorf("no run named %q on %q", name, box)
	}
	fmt.Fprintln(cmd.OutOrStdout(), line)
	return nil
}

func runCodeStop(cmd *cobra.Command, args []string) error {
	box := args[0]
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	diag := cmd.ErrOrStderr()
	name := codeRunName()

	sess, err := resolveCodeSession(ctx, box, diag)
	if err != nil {
		return err
	}
	defer func() { _ = sess.Close() }()

	res, err := sess.ProcessKill(ctx, name, codeStopForce)
	if err != nil {
		return fmt.Errorf("stop %q on %q: %w", name, box, err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "name: %s\npid: %d\nsignal: %s\nexited: %v\nlog_path: %s\n",
		res.Name, res.PID, res.Signal, res.Exited, res.LogPath)
	return nil
}

// logPathFromListing recovers a run's log_path from process_list's raw
// text. process_list doesn't expose per-name lookup, so `code attach`
// greps its own name's block the same way runOutcomeLine does, then reads
// the "Log path:" line immediately under it.
