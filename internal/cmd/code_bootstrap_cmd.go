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

	"github.com/spf13/cobra"
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
	codeBootstrapFlagURL    string
	codeBootstrapFlagURLCmd string
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
                     It runs through your $SHELL with your environment plus
                     CONTAINARIUM_BOX=<box>, so one documented command serves
                     every box.

Before the URL is used, and before --url-cmd runs, one silent SSH round trip
checks that the box is reachable and accepts your key, that its home is
writable, and that curl and tar are there. If that fails, nothing was requested
or applied. A bundle URL may be one-shot: if the download never reached the
server, the URL was not consumed and a retry is safe; if it reached the server
and then failed (an HTTP error such as 404 or 410, or a broken transfer), the
URL may already be consumed, so if a retry fails request a new one; if the
bundle was fetched but is unreadable or its apply.sh fails, the URL is spent,
so request a new one and re-run. The URL is never printed.

Examples:
  containarium code bootstrap alice --url https://bundles.example.com/team.tar.gz
  containarium code bootstrap alice --url-cmd 'my-bundle-server url "$CONTAINARIUM_BOX"'`,
	Args: cobra.ExactArgs(1),
	RunE: runCodeBootstrap,
}

func init() {
	codeCmd.AddCommand(codeBootstrapCmd)
	codeBootstrapCmd.Flags().StringVar(&codeBootstrapFlagURL, "url", "",
		"URL of the .tar.gz bundle to apply (mutually exclusive with --url-cmd)")
	codeBootstrapCmd.Flags().StringVar(&codeBootstrapFlagURLCmd, "url-cmd", "",
		"command that prints the bundle URL on its first stdout line; run through $SHELL, after the preflight, with CONTAINARIUM_BOX set (mutually exclusive with --url)")
}

// runURLCmdFn runs --url-cmd. Test seam.
var runURLCmdFn = runURLCmd

// runURLCmd runs command through the user's shell with CONTAINARIUM_BOX=box
// and returns the first line of its stdout. The hook's stderr goes to stderr
// so its own diagnostics reach the user; its stdout (the URL) is never echoed.
func runURLCmd(ctx context.Context, command, box string, stderr io.Writer) (string, error) {
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}
	// #nosec G204 -- running the user's own --url-cmd through their own shell
	// is exactly what the flag asks for.
	c := exec.CommandContext(ctx, shell, "-c", command)
	c.Env = append(os.Environ(), "CONTAINARIUM_BOX="+box)
	c.Stdin = os.Stdin
	c.Stderr = stderr
	var stdout bytes.Buffer
	c.Stdout = &stdout
	if err := c.Run(); err != nil {
		return "", fmt.Errorf("--url-cmd failed: %w", err)
	}
	line, _, _ := strings.Cut(stdout.String(), "\n")
	line = strings.TrimSpace(line)
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

	diag := cmd.ErrOrStderr()
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
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
