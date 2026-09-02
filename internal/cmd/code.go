package cmd

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/coderun"
	"github.com/footprintai/containarium/internal/connectcore"
	"github.com/footprintai/containarium/internal/sshkey"
	"github.com/spf13/cobra"
)

// `containarium code run/attach/status/stop` (#1674) is the resumable
// reader over agent-box's tail_log/process_start/process_kill: it feels
// like running the agent in a pipe, but survives the local client's
// network dying mid-run. See docs/architecture/remote-coding-agent.md,
// Part B, and internal/coderun for the resumable-reader core this command
// wraps. `code install` (#1673, a sibling PR) lands the toolchain these
// commands assume is already on the box.
//
// Box resolution/SSH-key authorization here deliberately mirrors
// connect.go's runConnect: same connectAPI, same obtainConnectKey, same
// connectcore helpers — this is the third caller of that pattern (after
// `connect` and `code install`), which is why obtainConnectKey takes
// explicit params instead of reading connect's own package vars.

// defaultCodeRunName is the process name used when --name is omitted, so
// the common case ("one coding task per box at a time") never requires the
// user to track an arbitrary generated name across run/attach/status/stop.
const defaultCodeRunName = "code"

// codeStreamFollow bounds how long each tail_log call blocks server-side
// polling for new content — most of the "streaming" feel comes from this,
// not from client-side poll frequency. Short enough that the post-exit
// grace period (codeStreamFollow + codeExitPollInterval) stays well under
// what a human notices as a delay before the command returns.
const codeStreamFollow = 3 * time.Second

// codeExitPollInterval is how often run/attach checks process_list for the
// run's own exit, independent of the tail_log streaming loop.
const codeExitPollInterval = 1 * time.Second

var (
	codeSSHServer string
	codeKeyPath   string
	codeIdentity  string
	codeUser      string
	codeHost      string
	codePort      int
	codeName      string
)

var codeCmd = &cobra.Command{
	Use:   "code",
	Short: "Run a coding agent on a box and watch it over a connection that may drop",
}

func init() {
	rootCmd.AddCommand(codeCmd)
	codeCmd.PersistentFlags().StringVar(&codeSSHServer, "ssh-server", "", "server to talk to for box resolution / SSH-key authorization (default: --server / CONTAINARIUM_SERVER, else your logged-in server)")
	codeCmd.PersistentFlags().StringVar(&codeKeyPath, "key", "", "public key to authorize (default: the managed key from `containarium ssh setup`)")
	codeCmd.PersistentFlags().StringVar(&codeIdentity, "identity", "", "private key path to authenticate with (default: derived from --key)")
	codeCmd.PersistentFlags().StringVar(&codeUser, "user", "", "override the SSH username (default: the box's own user)")
	codeCmd.PersistentFlags().StringVar(&codeHost, "host", "", "override the SSH host (default: the box's sentinel host)")
	codeCmd.PersistentFlags().IntVar(&codePort, "port", 0, "override the SSH port")
	codeCmd.PersistentFlags().StringVar(&codeName, "name", "", "process name for this run (default: \""+defaultCodeRunName+"\" — override to run more than one task on the same box concurrently)")

	codeCmd.AddCommand(codeRunCmd)
	codeCmd.AddCommand(codeAttachCmd)
	codeCmd.AddCommand(codeStatusCmd)
	codeCmd.AddCommand(codeStopCmd)

	codeRunCmd.Flags().StringVar(&codeRunPrompt, "prompt", "", "prompt to give the agent (required)")
	codeRunCmd.Flags().BoolVar(&codeRunStreamJSON, "output-format-stream-json", false,
		"capture stdout/stderr separately (framed capture_mode) so a JSON stream on stdout isn't corrupted by diagnostics; without this, both are interleaved as plain text")
	codeAttachCmd.Flags().BoolVar(&codeAttachStreamJSON, "output-format-stream-json", false,
		"demultiplex stdout/stderr — must match the capture_mode the run was actually started with")
	codeStopCmd.Flags().BoolVar(&codeStopForce, "force", false, "SIGKILL instead of SIGTERM")
}

func codeRunName() string {
	if codeName != "" {
		return codeName
	}
	return defaultCodeRunName
}

// resolveCodeSession authorizes the caller's managed SSH key on box (same
// flow as `containarium connect`) and opens an MCP session to its
// agent-box over that SSH path.
func resolveCodeSession(ctx context.Context, box string, diag io.Writer) (*coderun.Session, error) {
	if err := validateBoxName(box); err != nil {
		return nil, err
	}

	sshServer := codeSSHServer
	if sshServer == "" {
		sshServer = serverAddr
	}
	server := pickSSHServer(sshServer)
	api, err := newConnectAPI(server)
	if err != nil {
		return nil, err
	}

	c, err := api.GetContainer(ctx, box)
	if err != nil {
		return nil, err
	}
	if !connectcore.IsRunning(c.State) {
		return nil, fmt.Errorf("box %q is %s, not running — start it first (`containarium start %s`)",
			box, connectcore.PrettyState(c.State), box)
	}
	target, err := connectcore.BuildTarget(c, codeUser, codeHost, codePort)
	if err != nil {
		return nil, err
	}

	pub, privPath, err := obtainConnectKey(codeKeyPath, codeIdentity)
	if err != nil {
		return nil, err
	}
	if err := api.AuthorizeKey(ctx, box, pub); err != nil {
		return nil, fmt.Errorf("authorize key on %q: %w", box, err)
	}
	fp, _ := sshkey.Fingerprint(pub)
	fmt.Fprintf(diag, "✓ %s → %s@%s (authorized %s)\n", box, target.User, target.Host, fp)

	sshArgs := connectcore.BuildSSHArgs(target, privPath, "") // no remote command — Connect appends "agent-box"
	sess, err := coderun.Connect(ctx, sshArgs)
	if err != nil {
		return nil, fmt.Errorf("connect to agent-box on %q: %w", box, err)
	}
	return sess, nil
}

// shellQuoteSingle single-quotes s for a POSIX shell, escaping any embedded
// single quote by closing the quoted string, emitting a backslash-escaped
// single quote, then reopening it. process_start runs its command under
// /bin/sh -c on the box, so an unescaped user-supplied --prompt would be
// shell-interpreted there — this is what stands between "the agent's
// prompt" and arbitrary command injection into that shell.
func shellQuoteSingle(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// buildClaudeRunCommand renders the command process_start actually spawns:
// source whatever secrets delivery `containarium code install` (#1673) set
// up, then invoke claude non-interactively. Sourcing here — not relying on
// a login-shell profile — is self-contained per invocation, matching the
// same reasoning code_install.go's verify script uses.
func buildClaudeRunCommand(prompt string, streamJSON bool) string {
	cmd := "set -a; [ -f /run/containarium/secrets.env ] && . /run/containarium/secrets.env; set +a; " +
		"~/.local/bin/claude -p " + shellQuoteSingle(prompt)
	if streamJSON {
		cmd += " --output-format stream-json"
	}
	return cmd
}

// runOutcomeLine finds name's own line in process_list's raw text
// (handleProcessList's "<icon> <name>  (pid <pid>, <outcome>)" format,
// internal/agentbox/process.go) and reports whether it's still running.
// A name that doesn't appear at all (never started under this name, or its
// record was rotated away by a later same-name run) counts as not-running
// — there is nothing left to wait for either way.
func runOutcomeLine(listing, name string) (line string, running bool) {
	for _, l := range strings.Split(listing, "\n") {
		trimmed := strings.TrimSpace(l)
		fields := strings.Fields(trimmed)
		if len(fields) < 2 || fields[1] != name {
			continue
		}
		return trimmed, strings.Contains(trimmed, ", running)")
	}
	return "", false
}

// streamAndWait streams path's output to stdout (demultiplexed to
// stdout+stderr when streamJSON) until ctx is cancelled or name's run has
// exited, polling process_list independently of the tail_log loop to
// notice the exit. After noticing, it waits one more codeStreamFollow
// cycle so a last in-flight read can flush trailing output before
// stopping — tail_log has no "you've caught up, nothing more is coming"
// signal of its own, so watching liveness is the only way to know when to
// stop asking.
func streamAndWait(ctx context.Context, sess *coderun.Session, name, logPath string, stdout, stderr io.Writer, streamJSON bool) error {
	w := stdout
	if streamJSON {
		w = coderun.NewDemuxWriter(stdout, stderr)
	}

	streamCtx, cancelStream := context.WithCancel(ctx)
	defer cancelStream()

	streamDone := make(chan error, 1)
	go func() {
		_, err := coderun.StreamOutput(streamCtx, sess, w, logPath, 0, codeStreamFollow, func(err error) {
			fmt.Fprintf(stderr, "[containarium code] reconnecting after: %v\n", err)
		})
		streamDone <- err
	}()

	ticker := time.NewTicker(codeExitPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			listing, err := sess.ProcessList(ctx)
			if err != nil {
				continue // transient; the streaming loop's own retry handles reconnection
			}
			if _, running := runOutcomeLine(listing, name); !running {
				select {
				case <-time.After(codeStreamFollow + time.Second):
				case <-ctx.Done():
				}
				cancelStream()
				<-streamDone
				return nil
			}
		}
	}
}
