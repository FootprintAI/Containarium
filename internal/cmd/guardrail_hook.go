package cmd

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	grpcinsecure "google.golang.org/grpc/credentials/insecure"

	"github.com/footprintai/containarium/internal/guardrail"
	"github.com/footprintai/containarium/internal/guardrailhook"
)

// `containarium guardrail hook <event>`: the handler a coding agent's hooks
// run (docs/architecture/guardrail.md, "Coding-agent hooks"; #3761). It
// reads the hook event on stdin and answers on stdout. Everything it does is
// local to the machine: no server is contacted and no credential is read.
var guardrailHookCmd = &cobra.Command{
	Use:   "hook <event>",
	Short: "Handle a coding-agent hook event: redact what the agent gives the model",
	Long: `Handle one Claude Code hook event, read as JSON on stdin, and print the
hook's answer as JSON on stdout. Meant to be configured as a command hook
(exec form) for each of the events below, with onFailure "block" and a short
timeout; it is not meant to be run by hand.

  SessionStart        tell the model what [[TYPE:...]] markers are
  PreToolUse          deny the call if the engine is not ready; deny WebFetch;
                      restore personal-data markers in file paths and in the
                      new content of Edit / Write / NotebookEdit; deny a
                      secret marker or an unknown one; prefix a Bash command
                      so a failed one is redacted too (--wrap-failed-commands)
  PostToolUse         replace the tool's result with a redacted copy
  PostToolBatch       rescan what is about to reach the model and record
                      anything still unredacted
  UserPromptSubmit    block a prompt (or a background event) with a finding
  InstructionsLoaded  scan an instruction file and record

Detection is done by a GuardrailEngineService on a local socket (--engine),
or by the in-tree reference rules engine when --engine is empty. The
reference engine is a handful of regular expressions for proving the flow,
not a detector to rely on. Text never leaves the machine: --engine must be
a unix socket or a loopback address.

Markers are [[TYPE:<12 hex>]] under a per-user key created on first use.
The key, the marker map, the hook-firing stamps and a bounded findings
spool are kept 0600 in --state-dir. Personal-data markers can be restored;
secrets are never stored and never restored.

Exit status: 0 with a JSON answer (a denial or a block is an answer), 2 on
any internal error, with nothing on stdout.

Examples:
  containarium guardrail hook PreToolUse < event.json
  containarium guardrail hook PostToolUse --engine /run/guardrail/engine.sock < event.json`,
	Args: cobra.ArbitraryArgs,
	// Replaces the root command's hook, which resolves a server address and
	// reads the platform credentials file. This command talks to no server.
	PersistentPreRunE: func(*cobra.Command, []string) error { return nil },
	Run: func(cmd *cobra.Command, args []string) {
		if code := runGuardrailHook(cmd, args); code != 0 {
			guardrailHookExit(code)
		}
	},
}

// guardrailHookExit is os.Exit, replaceable in tests.
var guardrailHookExit = os.Exit

// guardrailHookFailed is the exit status for every internal error. Never 1
// and never 0: an agent treats 2 as "block", and reads exit 0 with unusable
// output as "go ahead" even when the hook is configured to block on failure.
const guardrailHookFailed = 2

var (
	guardrailHookEngineAddr   string
	guardrailHookStateDir     string
	guardrailHookEngineWait   time.Duration
	guardrailHookScanTimeout  time.Duration
	guardrailHookBatchBudget  time.Duration
	guardrailHookFullScanMax  int
	guardrailHookSpoolMax     int64
	guardrailHookBlockOnBatch bool
	guardrailHookWrapCommands bool
)

func init() {
	guardrailCmd.AddCommand(guardrailHookCmd)
	f := guardrailHookCmd.Flags()
	f.StringVar(&guardrailHookEngineAddr, "engine", "", "GuardrailEngineService on this machine: a unix socket path, unix://<path>, or a loopback host:port. Empty = the in-tree reference rules engine, in-process")
	f.StringVar(&guardrailHookStateDir, "state-dir", "", "Where the marker key, marker map, stamps and findings spool live (default $XDG_STATE_HOME/containarium-guardrail, else ~/.local/state/containarium-guardrail)")
	f.DurationVar(&guardrailHookEngineWait, "engine-wait", guardrailhook.DefaultEngineWait, "How long PreToolUse waits for the engine before it denies the call")
	f.DurationVar(&guardrailHookScanTimeout, "scan-timeout", guardrailhook.DefaultScanTimeout, "Deadline for one engine scan")
	f.DurationVar(&guardrailHookBatchBudget, "batch-budget", guardrailhook.DefaultBatchBudget, "Time PostToolBatch may spend on engine scans, all tool calls together. Calls reached after it get the in-process pattern pass. Keep it below the hook's timeout")
	f.IntVar(&guardrailHookFullScanMax, "full-scan-max-bytes", guardrailhook.DefaultFullScanMaxBytes, "Largest text sent to the engine. A larger one, a prompt included, gets the in-process pattern pass and is recorded as partially scanned")
	// A flag error is an internal error like any other: exit 2, not cobra's 1.
	guardrailHookCmd.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		fmt.Fprintf(cmd.ErrOrStderr(), "containarium guardrail hook: %v\n", err)
		guardrailHookExit(guardrailHookFailed)
		return nil
	})
	f.Int64Var(&guardrailHookSpoolMax, "spool-max-bytes", guardrailhook.DefaultSpoolMaxBytes, "Size bound of the findings spool. Rows that would not fit are dropped")
	f.BoolVar(&guardrailHookWrapCommands, "wrap-failed-commands", true, "Prefix each Bash command with an EXIT trap that reports a non-zero exit status and exits 0, so a failed command's output is redacted like any other result (#3765). The permission prompt shows the prefix. =false leaves commands as they are")
	f.BoolVar(&guardrailHookBlockOnBatch, "block-on-batch-finding", false, "On a PostToolBatch finding, stop the turn and refuse later prompts in that session until /clear or a new session")
}

// runGuardrailHook handles one event and returns the exit status.
func runGuardrailHook(cmd *cobra.Command, args []string) (code int) {
	stderr := cmd.ErrOrStderr()
	fail := func(err any) int {
		fmt.Fprintf(stderr, "containarium guardrail hook: %v\n", err)
		return guardrailHookFailed
	}
	defer func() {
		if r := recover(); r != nil {
			code = fail(r)
		}
	}()
	if len(args) != 1 {
		return fail("want exactly one argument, the hook event name")
	}
	event, err := guardrailhook.ParseEvent(args[0])
	if err != nil {
		return fail(err)
	}
	cfg := guardrailhook.Config{
		StateDir:            guardrailHookStateDir,
		EngineWait:          guardrailHookEngineWait,
		ScanTimeout:         guardrailHookScanTimeout,
		BatchBudget:         guardrailHookBatchBudget,
		FullScanMaxBytes:    guardrailHookFullScanMax,
		SpoolMaxBytes:       guardrailHookSpoolMax,
		BlockOnBatchFinding: guardrailHookBlockOnBatch,
		// The flag is on by default; the handler's zero value means on too.
		DisableCommandWrapper: !guardrailHookWrapCommands,
	}
	if cfg.StateDir == "" {
		if cfg.StateDir, err = guardrailhook.DefaultStateDir(); err != nil {
			return fail(err)
		}
	}
	// Absolute once, here: the handler compares it with absolute paths, and
	// the agent may run each hook from a different directory.
	if cfg.StateDir, err = filepath.Abs(cfg.StateDir); err != nil {
		return fail(fmt.Errorf("--state-dir: %w", err))
	}
	if guardrailHookEngineAddr != "" {
		target, err := localEngineTarget(guardrailHookEngineAddr)
		if err != nil {
			return fail(err)
		}
		// WaitForReady: a scan waits out its own deadline for an engine that
		// is still starting, instead of failing on the first refused connect.
		conn, err := grpc.NewClient(target,
			grpc.WithTransportCredentials(grpcinsecure.NewCredentials()),
			grpc.WithDefaultCallOptions(grpc.WaitForReady(true)))
		if err != nil {
			return fail(fmt.Errorf("engine %s: %w", guardrailHookEngineAddr, err))
		}
		defer func() { _ = conn.Close() }()
		cfg.Engine = guardrail.NewGRPCEngine(conn)
	}
	stdin, err := io.ReadAll(cmd.InOrStdin())
	if err != nil {
		return fail(fmt.Errorf("read hook input: %w", err))
	}
	out, err := guardrailhook.New(cfg).Handle(cmd.Context(), event, stdin)
	if err != nil {
		return fail(err)
	}
	if len(out) == 0 {
		return 0
	}
	// One write, so stdout never holds half an answer.
	if _, err := cmd.OutOrStdout().Write(append(out, '\n')); err != nil {
		return fail(fmt.Errorf("write hook output: %w", err))
	}
	return 0
}

// localEngineTarget turns --engine into a gRPC target and refuses anything
// that is not on this machine: the text being scanned is exactly what must
// not leave it.
func localEngineTarget(addr string) (string, error) {
	switch {
	case strings.HasPrefix(addr, "unix:"):
		return addr, nil
	case strings.HasPrefix(addr, "/"):
		return "unix://" + addr, nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("--engine %q: want a unix socket path or a loopback host:port", addr)
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return "", fmt.Errorf("--engine %q is not on this machine: use a unix socket or a loopback address", addr)
	}
	return addr, nil
}
