package cmd

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/footprintai/containarium/internal/coderun"
	"github.com/footprintai/containarium/internal/coderun/engine"
	"github.com/spf13/cobra"
)

var (
	codeRunPrompt        string
	codeRunStreamJSON    bool
	codeAttachStreamJSON bool
	codeStopForce        bool

	// #1727: --continue maps to the engine's session-resume flag, and
	// --token-ttl bounds the gateway token minted for this one run.
	codeRunContinue bool
	codeRunTokenTTL string

	// #2193: --session resumes one SPECIFIC session id instead of --continue's
	// "most recent" — mutually exclusive with it (validated in runCodeRun).
	codeRunSession string
)

var codeRunCmd = &cobra.Command{
	Use:   "run <box>",
	Short: "Start a coding agent on a box and stream its output as it's produced",
	Long: `Starts the box's coding agent with --prompt, detached (it survives this
command's own connection dying — see Killing the local client does not kill
the run, below), and streams its output to your terminal as it's produced: not
buffered to completion, and with no timeout on the run itself.

Which agent, and where its model credential comes from, is read from
~/.containarium/code.json — written by 'containarium code install'. A box with
no such record runs Claude Code on the box's own environment, which is what
every box installed before that record existed already did.

On a box installed with --credential gateway, each run mints its OWN scoped,
short-lived gateway token (bound to this box, this run, and the recorded model)
and writes it to the engine's gateway.env at 0600 before the run starts. No
provider key is ever stored on the box. --token-ttl bounds that token; the
default is 24h and the server caps it.

--continue resumes the agent's most recent session for the run's working
directory instead of starting a fresh one.

A mid-run network drop is recovered automatically by resuming at the last
byte offset seen — nothing is re-issued, nothing is lost or duplicated.
Killing this command (Ctrl-C, closing the laptop) does NOT kill the run;
reconnect with 'containarium code attach <box>'.

This command's own process exit status reflects the AGENT's exit code once
the run finishes: zero when the agent exited zero, non-zero when it didn't —
so CI and shell scripts can gate on '$?' directly, without separately parsing
'containarium code status'. A run that finishes with no exit code recorded
(the box died mid-run) is not treated as a failure here; check 'code status'
for "unknown" in that case.

Requires the box to already have a coding agent installed and credentialed —
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
disconnect again.

Like 'code run', this command's own process exit status reflects the agent's
exit code once the run finishes: non-zero if the agent exited non-zero.`,
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
	if codeRunSession != "" && codeRunContinue {
		return fmt.Errorf("--session and --continue are mutually exclusive (--session resumes one specific session; --continue resumes whichever the engine considers most recent)")
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

	// #1727: the box's own code.json decides which engine and credential source
	// this run uses. A box installed before #1727 has no record, and
	// prepareCodeRun falls back to the Claude + tenant-secret path it was
	// installed with — so an existing box keeps working untouched.
	command, eng, err := prepareCodeRun(ctx, sess, box, name, diag)
	if err != nil {
		return err
	}

	started, err := sess.ProcessStart(ctx, name, command, "", coderun.CaptureModeFor(codeRunStreamJSON))
	if err != nil {
		return fmt.Errorf("start run on %q: %w", box, err)
	}
	fmt.Fprintf(diag, "✓ started %q (pid %d) on %s\n", started.Name, started.PID, box)

	startSessionDiscovery(ctx, sess, eng, started.LogPath, diag)

	return streamAndWait(ctx, sess, started.Name, started.LogPath, cmd.OutOrStdout(), diag, codeRunStreamJSON)
}

// startSessionDiscovery best-effort backgrounds the lookup of this run's own
// session id on the box (#2193), so a later `code run --session <id>` or
// `code runs`/BoxRun.session_id can name this exact conversation. It is
// launched via ONE non-blocking shell_exec call — the poll loop itself runs
// detached ON THE BOX (engine.SessionDiscoveryBackgroundCommand setsid's it),
// so this never delays streaming the run's own output. A failure here is
// never fatal to the run: it only means `code runs` won't show a session id
// for it, which the AC already allows ("absent for engines that don't expose
// one").
func startSessionDiscovery(ctx context.Context, sess *coderun.Session, eng engine.Engine, logPath string, diag io.Writer) {
	if eng == nil {
		return
	}
	home, err := sess.HomeDir(ctx)
	if err != nil {
		fmt.Fprintf(diag, "note: could not resolve $HOME to look for this run's session id: %v\n", err)
		return
	}
	// process_start was given no --cwd, so the run inherited agent-box's own
	// cwd — which over an interactive SSH login is $HOME. Best-effort: if the
	// box's actual login shell lands somewhere else, discovery simply won't
	// find a match and session_id stays absent, same as any other engine
	// that exposes none.
	cwd := home
	sidecarPath := strings.TrimSuffix(logPath, ".log") + ".session"
	cmd, ok := engine.SessionDiscoveryBackgroundCommand(eng.Name(), home, cwd, sidecarPath)
	if !ok {
		return
	}
	if _, err := sess.ShellExec(ctx, cmd); err != nil {
		fmt.Fprintf(diag, "note: could not start looking for this run's session id (non-fatal): %v\n", err)
	}
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
	line, running := coderun.RunOutcomeLine(listing, name)
	if line == "" {
		return fmt.Errorf("no run named %q on %q", name, box)
	}
	out := cmd.OutOrStdout()
	fmt.Fprintln(out, line)

	// #1727/#2011: report the exit code of a run that finished — including one
	// that finished while the user was disconnected, which is the whole point
	// of the durable run record. `--help` has promised this since #1674 and the
	// header line alone never carried it. coderun.ExitCodeLine is the one place
	// that renders this line, shared with the MCP wrapper (handleCodeStatus in
	// internal/mcp/code_tools.go) so the two surfaces cannot drift.
	if !running {
		fmt.Fprintln(out, coderun.ExitCodeLine(listing, name))
	}
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
