package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/connectcore"
	"github.com/footprintai/containarium/internal/sshkey"
	"github.com/spf13/cobra"
)

// `containarium connect <box>` turns the token the caller already holds
// into a shell, without the user ever hand-managing an SSH key. It
// resolves the box, authorizes a managed key on the caller's behalf, and
// then either drops into an interactive session (default), runs one
// command and returns its output (--exec, the agent-native path), or just
// prints the ready ssh invocation (--print).
//
// CLI-first per CLAUDE.md: this is the canonical surface; the MCP `connect`
// tool is a thin wrapper over the same connectcore resolve+authorize core.
//
// It is glue over primitives the daemon already serves:
//   - GET  /v1/containers/{box}            → ssh_host, username, state, IP
//   - POST /v1/containers/{box}/ssh-keys   → authorize a key (idempotent)
var (
	connectServer   string
	connectExec     string
	connectPrint    bool
	connectKeyPath  string
	connectIdentity string
	connectUser     string
	connectHost     string
	connectPort     int
	connectSession  string
)

var connectCmd = &cobra.Command{
	Use:   "connect <box>",
	Short: "Open a shell on a box using your token (no SSH-key setup)",
	Long: `Connect to one of your boxes over SSH using the token you're already
logged in with — connect authorizes a managed key for you, so you never
have to set up or copy an SSH key yourself.

Modes:

  containarium connect my-box                       # interactive shell
  containarium connect my-box --exec "make"         # run one command, return its output
  containarium connect my-box --print               # authorize + print the ssh command, don't connect

Stateful sessions (--session) run inside a named tmux session ON THE BOX,
so state (cd, exports, background jobs) persists across calls and you can
attach a terminal to watch:

  containarium connect my-box --session work --exec "cd /app"   # state persists...
  containarium connect my-box --session work --exec "pwd"       # ...to the next call → /app
  containarium connect my-box --session work                    # attach your terminal to it

The SSH target is the box's ssh_host (or its IP if the daemon reports no
ssh_host) and its SSH username. Override either with --host / --user.`,
	Args: cobra.ExactArgs(1),
	RunE: runConnect,
}

func init() {
	connectCmd.Flags().StringVar(&connectServer, "server", "", "server to talk to (default: your logged-in server)")
	connectCmd.Flags().StringVar(&connectExec, "exec", "", "run one command over SSH and return its output (non-interactive)")
	connectCmd.Flags().BoolVar(&connectPrint, "print", false, "authorize the key and print the ready ssh command; do not connect")
	connectCmd.Flags().StringVar(&connectKeyPath, "key", "", "public key to authorize (default: reuse or generate the managed key)")
	connectCmd.Flags().StringVar(&connectIdentity, "identity", "", "private key to authenticate with (default: derived from the public key)")
	connectCmd.Flags().StringVar(&connectUser, "user", "", "override the SSH login user (default: the box's SSH username)")
	connectCmd.Flags().StringVar(&connectHost, "host", "", "override the SSH host (default: the box's ssh_host, else its IP)")
	connectCmd.Flags().IntVar(&connectPort, "port", 22, "SSH port")
	connectCmd.Flags().StringVar(&connectSession, "session", "", "run inside a named tmux session on the box (stateful; persists across calls). With --exec runs the command there; without --exec attaches your terminal.")
	rootCmd.AddCommand(connectCmd)
}

// ---- thin REST client (deliberately not ssh.go's sshHTTPClient: that
// one maps 404→Unimplemented, which would mask "box not found") ---------

type connectAPI struct {
	hc     *http.Client
	server string
	token  string
}

func newConnectAPI(server string) (*connectAPI, error) {
	tok := resolveAuthToken(server)
	if tok == "" {
		return nil, fmt.Errorf("no auth token for %s — run `containarium login` first", server)
	}
	return &connectAPI{
		hc:     &http.Client{Timeout: 30 * time.Second},
		server: server,
		token:  tok,
	}, nil
}

// do sends the request and returns the HTTP status so callers can
// distinguish 404 (box not found) from other failures. out is decoded on
// a 2xx response when non-nil.
func (c *connectAPI) do(ctx context.Context, method, path string, body, out any) (int, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, fmt.Errorf("marshal request: %w", err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.server+path, rdr)
	if err != nil {
		return 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if out != nil && len(rb) > 0 {
			if err := json.Unmarshal(rb, out); err != nil {
				return resp.StatusCode, fmt.Errorf("decode response: %w", err)
			}
		}
		return resp.StatusCode, nil
	}
	return resp.StatusCode, fmt.Errorf("%s %s: status %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(rb)))
}

func (c *connectAPI) GetContainer(ctx context.Context, box string) (*connectcore.Container, error) {
	var out connectcore.GetContainerResponse
	st, err := c.do(ctx, http.MethodGet, "/v1/containers/"+url.PathEscape(box), nil, &out)
	if st == http.StatusNotFound {
		return nil, fmt.Errorf("box %q not found (check the name, or `containarium list`)", box)
	}
	if err != nil {
		return nil, err
	}
	return &out.Container, nil
}

func (c *connectAPI) AuthorizeKey(ctx context.Context, box, pub string) error {
	_, err := c.do(ctx, http.MethodPost,
		"/v1/containers/"+url.PathEscape(box)+"/ssh-keys",
		connectcore.AuthorizeKeyRequest{SshPublicKey: pub}, nil)
	return err
}

// ---- command handler ---------------------------------------------------

// obtainConnectKey returns the public key to authorize and the private
// key path to authenticate with. With a non-empty keyPath it uses that
// supplied public key; otherwise it reuses (or generates once) the managed
// key the `ssh setup` flow already uses, so the user never hand-manages a
// key. The private path defaults to the public path minus ".pub" unless
// identity overrides it.
//
// Parameterized (not reading connect's own connectKeyPath/connectIdentity
// package vars) so other commands needing the same "authorize a managed
// key, connect over SSH" flow — e.g. `code install` (#1673) — can call it
// with their own flag values instead of colliding with connect's.
func obtainConnectKey(keyPath, identity string) (pub, privPath string, err error) {
	var pubPath string
	if keyPath != "" {
		pub, err = sshkey.ReadPublicKey(keyPath)
		if err != nil {
			return "", "", err
		}
		pubPath = keyPath
	} else {
		pubPath, pub, _, err = sshkey.LocateOrGenerate(sshkey.LocateOpts{})
		if err != nil {
			return "", "", fmt.Errorf("locate or generate managed key: %w", err)
		}
	}
	privPath = identity
	if privPath == "" {
		privPath = strings.TrimSuffix(pubPath, ".pub")
	}
	return pub, privPath, nil
}

func runConnect(cmd *cobra.Command, args []string) error {
	box := args[0]
	if err := validateBoxName(box); err != nil {
		return err
	}
	// Diagnostics go to stderr so --exec keeps stdout clean for command
	// output (an agent parsing --exec output gets only the command's bytes).
	diag := cmd.ErrOrStderr()

	server := pickSSHServer(connectServer)
	api, err := newConnectAPI(server)
	if err != nil {
		return err
	}
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	c, err := api.GetContainer(ctx, box)
	if err != nil {
		return err
	}
	if !connectcore.IsRunning(c.State) {
		return fmt.Errorf("box %q is %s, not running — start it first (`containarium start %s`)",
			box, connectcore.PrettyState(c.State), box)
	}
	target, err := connectcore.BuildTarget(c, connectUser, connectHost, connectPort)
	if err != nil {
		return err
	}

	pub, privPath, err := obtainConnectKey(connectKeyPath, connectIdentity)
	if err != nil {
		return err
	}
	if err := api.AuthorizeKey(ctx, box, pub); err != nil {
		return fmt.Errorf("authorize key on %q: %w", box, err)
	}
	fp, _ := sshkey.Fingerprint(pub)
	fmt.Fprintf(diag, "✓ %s → %s@%s (authorized %s)\n", box, target.User, target.Host, fp)

	// Tier 2 — stateful tmux session on the box.
	if connectSession != "" {
		if err := connectcore.ValidateSessionName(connectSession); err != nil {
			return err
		}
		if connectExec != "" {
			return runSessionExec(diag, cmd.OutOrStdout(), target, privPath, connectSession, connectExec)
		}
		// No --exec: attach the user's terminal to the session (create if absent).
		return runSSH(connectcore.BuildAttachArgs(target, privPath, connectSession))
	}

	sshArgs := connectcore.BuildSSHArgs(target, privPath, connectExec)
	if connectPrint {
		// The ready invocation is the deliverable here → stdout.
		fmt.Fprintf(cmd.OutOrStdout(), "ssh %s\n", strings.Join(sshArgs, " "))
		return nil
	}
	return runSSH(sshArgs)
}

// runSessionExec runs one command inside a named tmux session on the box
// and prints its captured output. The remote exit code is propagated
// (os.Exit) so CI / scripts see failures, matching plain --exec.
func runSessionExec(diag, out io.Writer, target connectcore.Target, identity, session, command string) error {
	marker, err := connectcore.NewMarker()
	if err != nil {
		return err
	}
	sshBin, err := exec.LookPath("ssh")
	if err != nil {
		return fmt.Errorf("ssh not found in PATH: %w", err)
	}
	// Box-side poll caps at the timeout; give the ssh process a little more
	// before we abandon it.
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	args := connectcore.BuildSessionExecArgs(target, identity, session, marker, connectcore.EncodeCommand(command), 60)
	// #nosec G204 -- sshBin is the resolved `ssh` binary; args are built from
	// a validated box name + daemon-resolved target + user flags. Running ssh
	// is precisely this command's job.
	c := exec.CommandContext(ctx, sshBin, args...)
	c.Stdin = strings.NewReader(connectcore.SessionExecScript())
	var stdout bytes.Buffer
	c.Stdout = &stdout
	c.Stderr = diag // ssh's own diagnostics (host-key, connection) to stderr
	runErr := c.Run()
	if runErr != nil {
		var ee *exec.ExitError
		if !errors.As(runErr, &ee) {
			return fmt.Errorf("session exec: %w", runErr)
		}
		// Non-zero ssh exit (e.g. orchestration exit 127) still has framed
		// output we can parse below; fall through.
	}

	cmdOut, code, perr := connectcore.ParseSessionResult(stdout.String(), marker)
	if perr != nil {
		return perr
	}
	if cmdOut != "" {
		fmt.Fprint(out, cmdOut)
		if !strings.HasSuffix(cmdOut, "\n") {
			fmt.Fprintln(out)
		}
	}
	if code != 0 {
		os.Exit(code)
	}
	return nil
}

// runSSH execs the local ssh client, inheriting the terminal. For an
// interactive session stdin is the user's TTY (ssh allocates a PTY); for
// --exec it's a one-shot command whose stdout/stderr stream through. The
// remote exit code is propagated verbatim so CI / agents see failures.
func runSSH(args []string) error {
	sshBin, err := exec.LookPath("ssh")
	if err != nil {
		return fmt.Errorf("ssh not found in PATH: %w", err)
	}
	// #nosec G204 -- sshBin is the resolved `ssh` binary; args are built from
	// a validated box name + daemon-resolved target + user flags. Running ssh
	// is precisely this command's job.
	c := exec.Command(sshBin, args...)
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	if err := c.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			os.Exit(ee.ExitCode())
		}
		return fmt.Errorf("ssh: %w", err)
	}
	return nil
}
