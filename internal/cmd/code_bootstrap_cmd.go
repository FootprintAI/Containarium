package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/client"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// `containarium code bootstrap <box>` (#3512) re-applies a bootstrap bundle
// to a box that already has its agent installed: the bundle step of `code
// install --bootstrap-url` and nothing else. No engine, agent-box or skills
// reinstall, and ~/.containarium/code.json is left alone.
//
// The URL comes from --url, or from --url-cmd: a command the CLI runs AFTER
// the preflight has confirmed the box, so a one-shot URL is only requested
// once the SSH path and the install target are known to work. The CLI knows
// no control-plane endpoint; the hook is how a control plane (or a
// self-hoster's own bundle server) plugs in.

var (
	codeBootstrapFlagURL       string
	codeBootstrapFlagURLCmd    string
	codeBootstrapFlagViaDaemon bool
	codeBootstrapFlagBoxUser   string
)

var codeBootstrapCmd = &cobra.Command{
	Use:   "bootstrap <box>",
	Short: "Re-apply a bootstrap bundle to a box without re-installing the agent",
	Long: `Fetch a bootstrap bundle (a .tar.gz with an apply.sh at its root), unpack it
into a temp dir on the box and run its apply.sh as the box user, over SSH. This
is the bundle step of ` + "`containarium code install --bootstrap-url`" + ` on its own: it
installs no engine, agent-box or skills and leaves ~/.containarium/code.json
alone. Use it to pick up a new skill set, a rotated credential or a changed MCP
config that a bundle carries.

Where the URL comes from (exactly one):

  --url <url>        the bundle URL itself.
  --url-cmd '<cmd>'  a command that prints the URL on its first stdout line.
                     It runs through your $SHELL (/bin/sh when unset) with
                     your environment plus CONTAINARIUM_BOX=<box>, so one
                     documented command serves every box. A hook that has not
                     exited after 30s is killed and nothing is applied.

Before the URL is used, and before --url-cmd runs, one silent SSH round trip
checks that the box is reachable and accepts your key, that its home is
writable, and that curl and tar are there. If that fails, nothing was requested
or applied. A bundle URL may be one-shot: if the download never reached the
server, the URL was not consumed and a retry is safe; if it reached the server
and then failed (an HTTP error such as 404 or 410, or a broken transfer), the
URL may already be consumed, so if a retry fails request a new one; if the
bundle was fetched but is unreadable or its apply.sh fails, the URL is spent,
so request a new one and re-run. The URL is never printed.

--via-daemon applies the bundle through the daemon (--server) instead of over
SSH: the daemon runs the same script inside the box as the box user (--box-user,
default the box owner) and reports the bundle_revision of the applied bundle's
manifest.json. No SSH client or key is needed, and no preflight probe runs; the
daemon refuses a stopped box before the URL is used. With --url-cmd, the hook
runs on this machine before the call. A daemon too old to support it is
reported as such.

Examples:
  containarium code bootstrap alice --url https://bundles.example.com/team.tar.gz
  containarium code bootstrap alice --url-cmd 'my-bundle-server url "$CONTAINARIUM_BOX"'
  containarium code bootstrap alice --via-daemon --server <host> --url https://bundles.example.com/team.tar.gz`,
	Args: cobra.ExactArgs(1),
	RunE: runCodeBootstrap,
}

func init() {
	codeCmd.AddCommand(codeBootstrapCmd)
	codeBootstrapCmd.Flags().StringVar(&codeBootstrapFlagURL, "url", "",
		"URL of the .tar.gz bundle to apply (mutually exclusive with --url-cmd)")
	codeBootstrapCmd.Flags().StringVar(&codeBootstrapFlagURLCmd, "url-cmd", "",
		"command that prints the bundle URL on its first stdout line; run through $SHELL, after the preflight, with CONTAINARIUM_BOX set (mutually exclusive with --url)")
	codeBootstrapCmd.Flags().BoolVar(&codeBootstrapFlagViaDaemon, "via-daemon", false,
		"apply the bundle through the daemon (--server) instead of over SSH; reports the applied bundle_revision")
	codeBootstrapCmd.Flags().StringVar(&codeBootstrapFlagBoxUser, "box-user", "",
		"with --via-daemon: the OS user in the box to apply the bundle as (default: the box owner)")
}

// runURLCmdFn runs --url-cmd. Test seam.
var runURLCmdFn = runURLCmd

// Limits on the --url-cmd hook. Variables only so tests can shorten them.
var (
	// urlCmdTimeout bounds the whole hook: one that never exits is killed
	// rather than hanging the CLI.
	urlCmdTimeout = 30 * time.Second
	// urlCmdWaitDelay bounds how long the CLI waits, after the hook exits,
	// for a background child it left behind to release stdout/stderr.
	urlCmdWaitDelay = 2 * time.Second
)

// urlCmdMaxOutput caps the bytes of the hook's first stdout line the CLI
// keeps; everything after that line is discarded unread.
const urlCmdMaxOutput = 4096

// firstLineWriter keeps the first line written to it, up to max bytes, and
// discards the rest, so a chatty hook cannot grow the CLI's memory.
type firstLineWriter struct {
	buf      []byte
	max      int
	done     bool
	overflow bool
}

func (w *firstLineWriter) Write(p []byte) (int, error) {
	if w.done {
		return len(p), nil
	}
	chunk := p
	if i := bytes.IndexByte(p, '\n'); i >= 0 {
		chunk, w.done = p[:i], true
	}
	if room := w.max - len(w.buf); len(chunk) > room {
		chunk, w.done, w.overflow = chunk[:room], true, true
	}
	w.buf = append(w.buf, chunk...)
	return len(p), nil
}

// runURLCmd runs command through the user's shell ($SHELL, or /bin/sh when
// unset) with CONTAINARIUM_BOX=box and returns the first line of its stdout.
// The hook's stderr goes to stderr so its own diagnostics reach the user; its
// stdout (the URL) is never echoed, not even in an error.
func runURLCmd(ctx context.Context, command, box string, stderr io.Writer) (string, error) {
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}
	ctx, cancel := context.WithTimeout(ctx, urlCmdTimeout)
	defer cancel()
	// #nosec G204 -- running the user's own --url-cmd through their own shell
	// is exactly what the flag asks for.
	c := exec.CommandContext(ctx, shell, "-c", command)
	c.Env = append(os.Environ(), "CONTAINARIUM_BOX="+box)
	c.Stdin = os.Stdin
	c.Stderr = stderr
	c.WaitDelay = urlCmdWaitDelay
	out := &firstLineWriter{max: urlCmdMaxOutput}
	c.Stdout = out
	err := c.Run()
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return "", fmt.Errorf("--url-cmd did not exit within %s and was killed", urlCmdTimeout)
	case errors.Is(err, exec.ErrWaitDelay):
		// The hook itself exited 0; a background child it started still
		// held stdout or stderr and was cut off. The line is complete.
	case err != nil:
		return "", fmt.Errorf("--url-cmd failed: %w", err)
	}
	if out.overflow {
		return "", fmt.Errorf("--url-cmd's first stdout line is longer than %d bytes", urlCmdMaxOutput)
	}
	line := strings.TrimSpace(string(out.buf))
	if line == "" {
		return "", errors.New("--url-cmd printed no URL on its first stdout line")
	}
	return line, nil
}

func runCodeBootstrap(cmd *cobra.Command, args []string) error {
	box := args[0]
	if err := validateBoxName(box); err != nil {
		return err
	}
	url := strings.TrimSpace(codeBootstrapFlagURL)
	urlCmd := strings.TrimSpace(codeBootstrapFlagURLCmd)
	switch {
	case url != "" && urlCmd != "":
		return errors.New("--url and --url-cmd are mutually exclusive")
	case url == "" && urlCmd == "":
		return errors.New("give the bundle with --url or --url-cmd")
	}

	boxUser := strings.TrimSpace(codeBootstrapFlagBoxUser)
	if boxUser != "" && !codeBootstrapFlagViaDaemon {
		return errors.New("--box-user is only used with --via-daemon; over SSH the bundle runs as the user you connect as")
	}

	diag := cmd.ErrOrStderr()
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	if codeBootstrapFlagViaDaemon {
		if serverAddr == "" {
			return errors.New("--via-daemon needs --server")
		}
		c, err := newBootstrapApplierFn()
		if err != nil {
			return err
		}
		defer func() { _ = c.Close() }()
		if urlCmd != "" {
			if url, err = runURLCmdFn(ctx, urlCmd, box, diag); err != nil {
				return fmt.Errorf("obtain the bootstrap URL for %q: %w; nothing was applied", box, err)
			}
		}
		return codeBootstrapViaDaemon(c, box, url, boxUser, cmd.OutOrStdout())
	}
	target, privPath, err := resolveCodeTargetFn(ctx, box, diag)
	if err != nil {
		return err
	}
	// resolveCodeTarget just authorized the key: armed (#2013).
	kw, err := newKeyWait(codeKeyWait, true, diag)
	if err != nil {
		return err
	}
	if err := bootstrapPreflight(ctx, kw, target, privPath, box); err != nil {
		return err
	}
	if urlCmd != "" {
		if url, err = runURLCmdFn(ctx, urlCmd, box, diag); err != nil {
			return fmt.Errorf("obtain the bootstrap URL for %q: %w; nothing was applied", box, err)
		}
	}
	if err := applyBootstrapBundle(box, url, codeSSHRunner(ctx, kw, target, privPath, diag)); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "✓ bootstrap bundle applied on %s\n", box)
	return nil
}

// bootstrapApplierCloser is a daemon client that can apply a bundle.
type bootstrapApplierCloser interface {
	client.BoxBootstrapApplier
	Close() error
}

// newBootstrapApplierFn dials the daemon named by --server. Test seam.
var newBootstrapApplierFn = func() (bootstrapApplierCloser, error) {
	if httpMode {
		return client.NewHTTPClient(serverAddr, authToken)
	}
	return client.NewGRPCClient(serverAddr, certsDir, insecure)
}

// codeBootstrapViaDaemon applies url to box through the daemon's
// ApplyBoxBootstrap (#3694), as boxUser (empty: the box owner). The URL is
// never printed, and no error built here quotes it.
func codeBootstrapViaDaemon(c client.BoxBootstrapApplier, box, url, boxUser string, w io.Writer) error {
	resp, err := c.ApplyBoxBootstrap(&pb.ApplyBoxBootstrapRequest{Name: box, BootstrapUrl: url, BoxUser: boxUser})
	if isUnimplemented(err) {
		return fmt.Errorf("this daemon does not support applying a bootstrap bundle (ApplyBoxBootstrap); upgrade it, or re-run without --via-daemon to apply it over SSH (the URL was not sent to a handler, so it was not consumed)")
	}
	if err != nil {
		if reason, exit := client.BootstrapFailureOf(err); reason != pb.BoxBootstrapFailure_BOX_BOOTSTRAP_FAILURE_UNSPECIFIED {
			name := strings.TrimPrefix(reason.String(), "BOX_BOOTSTRAP_FAILURE_")
			if exit > 0 {
				return fmt.Errorf("apply bootstrap bundle on %q through the daemon: %s (exit %d): %s", box, name, exit, status.Convert(err).Message())
			}
			return fmt.Errorf("apply bootstrap bundle on %q through the daemon: %s: %s", box, name, status.Convert(err).Message())
		}
		return fmt.Errorf("apply bootstrap bundle on %q through the daemon: %w", box, err)
	}
	if resp.GetManifestFound() {
		_, err = fmt.Fprintf(w, "✓ bootstrap bundle applied on %s (bundle revision %d)\n", box, resp.GetBundleRevision())
	} else {
		_, err = fmt.Fprintf(w, "✓ bootstrap bundle applied on %s (the bundle carries no manifest.json)\n", box)
	}
	return err
}
