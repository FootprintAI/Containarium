package cmd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/client"
	"github.com/footprintai/containarium/internal/coderun"
	"github.com/footprintai/containarium/internal/connectcore"
	"github.com/footprintai/containarium/internal/sshkey"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

// `containarium code` (#1673, #1674) is the box-side coding-agent surface:
// `install` lands the toolchain on a box you already use (PRD Story 2,
// docs/product/remote-coding-agent.md); `run`/`attach`/`status`/`stop` are
// the resumable reader over agent-box's tail_log/process_start/process_kill
// (PRD Story 3, Part B of the design doc) — it feels like running the agent
// in a pipe, but survives the local client's network dying mid-run. See
// internal/coderun for the resumable-reader core `run`/`attach` wrap.
//
// Box resolution/SSH-key authorization is shared by all five subcommands
// and deliberately mirrors connect.go's runConnect: same connectAPI, same
// obtainConnectKey, same connectcore helpers — this package is the second
// caller of that pattern (after `connect`), which is why obtainConnectKey
// takes explicit params instead of reading connect's own package vars.

// claudeOAuthTokenSecretName is the tenant-secret name `code install` checks
// for before installing. Minted once on a trusted machine with `claude
// setup-token`, then delivered via `containarium secrets set`. This package
// only ever reads its metadata (name, delivery mode, version) via
// ListSecrets — never its plaintext value — so the token is never a CLI
// parameter here and never appears in this command's output.
const claudeOAuthTokenSecretName = "CLAUDE_CODE_OAUTH_TOKEN" // #nosec G101 -- secret NAME, not a credential value

// claudeInstallScript is Claude Code's own native installer. It writes to
// ~/.local/bin/claude — user-level, no root — which is exactly why `code
// install` doesn't need a daemon-side privileged exec path.
const claudeInstallScript = "curl -fsSL https://claude.ai/install.sh | bash"

// defaultCodeRunName is the process name used when --name is omitted, so
// the common case ("one coding task per box at a time") never requires the
// user to track an arbitrary generated name across run/attach/status/stop.
const defaultCodeRunName = coderun.DefaultRunName

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
	Short: "Run and manage a coding agent on a box",
}

var codeInstallCmd = &cobra.Command{
	Use:   "install <box>",
	Short: "Install the Claude Code CLI onto an existing, already-provisioned box",
	Long: `Installs Claude Code onto a box you already use, over the existing SSH
path — no new box type, no daemon-side privileged exec.

The box must already hold its Claude Code credential as a tenant secret
named CLAUDE_CODE_OAUTH_TOKEN, delivered as "compose" or "file" — NOT the
default "env". env-delivered secrets are stamped on the LXC's
container-start environment, which an SSH shell session (where claude
actually runs) never inherits; see docs/integrations/pi.md for the same
finding against a different agent. Mint the token once on a trusted
machine, then set it before running this command:

  claude setup-token
  containarium secrets set <box> CLAUDE_CODE_OAUTH_TOKEN <token> --delivery compose
  containarium code install <box>

The token itself is never a parameter to this command and never appears in
its output — only the secret's presence and delivery mode are checked.

After installing, this command verifies the install by running a single
non-interactive prompt (no TTY, no login flow) and asserts
ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN are unset on the box — both
outrank CLAUDE_CODE_OAUTH_TOKEN in Claude Code's auth precedence and would
silently win over it.`,
	Args: cobra.ExactArgs(1),
	RunE: runCodeInstall,
}

// codeRunCmd, codeAttachCmd, codeStatusCmd, codeStopCmd and their RunE
// handlers are defined in code_run.go (the resumable-reader core, #1674) —
// declared there rather than here since they're wired into codeCmd below
// alongside codeInstallCmd (#1673).
func init() {
	rootCmd.AddCommand(codeCmd)
	codeCmd.PersistentFlags().StringVar(&codeSSHServer, "ssh-server", "", "server to talk to for box resolution / SSH-key authorization (default: --server / CONTAINARIUM_SERVER, else your logged-in server) — deliberately NOT named --server: that flag already means \"the daemon secrets are read from\", and this can legitimately differ (e.g. a cloud-fronted login server vs. a direct daemon address)")
	codeCmd.PersistentFlags().StringVar(&codeKeyPath, "key", "", "public key to authorize (default: the managed key from `containarium ssh setup`)")
	codeCmd.PersistentFlags().StringVar(&codeIdentity, "identity", "", "private key path to authenticate with (default: derived from --key)")
	codeCmd.PersistentFlags().StringVar(&codeUser, "user", "", "override the SSH username (default: the box's own user)")
	codeCmd.PersistentFlags().StringVar(&codeHost, "host", "", "override the SSH host (default: the box's sentinel host)")
	codeCmd.PersistentFlags().IntVar(&codePort, "port", 0, "override the SSH port")

	codeCmd.AddCommand(codeInstallCmd)
	codeCmd.AddCommand(codeRunCmd)
	codeCmd.AddCommand(codeAttachCmd)
	codeCmd.AddCommand(codeStatusCmd)
	codeCmd.AddCommand(codeStopCmd)

	// --name applies to run/attach/status/stop (which task on the box) —
	// not install, which has no notion of a named run.
	for _, c := range []*cobra.Command{codeRunCmd, codeAttachCmd, codeStatusCmd, codeStopCmd} {
		c.Flags().StringVar(&codeName, "name", "", "process name for this run (default: \""+defaultCodeRunName+"\" — override to run more than one task on the same box concurrently)")
	}

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

// resolveCodeTarget authorizes the caller's managed SSH key on box (same
// flow as `containarium connect`) and returns the resolved SSH target plus
// the private key path to authenticate with. Shared by every code
// subcommand; run/attach/status/stop layer an MCP session on top
// (resolveCodeSession), `install` execs a plain script directly.
func resolveCodeTarget(ctx context.Context, box string, diag io.Writer) (connectcore.Target, string, error) {
	if err := validateBoxName(box); err != nil {
		return connectcore.Target{}, "", err
	}

	sshServer := codeSSHServer
	if sshServer == "" {
		sshServer = serverAddr
	}
	server := pickSSHServer(sshServer)
	api, err := newConnectAPI(server)
	if err != nil {
		return connectcore.Target{}, "", err
	}

	c, err := api.GetContainer(ctx, box)
	if err != nil {
		return connectcore.Target{}, "", err
	}
	if !connectcore.IsRunning(c.State) {
		return connectcore.Target{}, "", fmt.Errorf("box %q is %s, not running — start it first (`containarium start %s`)",
			box, connectcore.PrettyState(c.State), box)
	}
	target, err := connectcore.BuildTarget(c, codeUser, codeHost, codePort)
	if err != nil {
		return connectcore.Target{}, "", err
	}

	pub, privPath, err := obtainConnectKey(codeKeyPath, codeIdentity)
	if err != nil {
		return connectcore.Target{}, "", err
	}
	if err := api.AuthorizeKey(ctx, box, pub); err != nil {
		return connectcore.Target{}, "", fmt.Errorf("authorize key on %q: %w", box, err)
	}
	fp, _ := sshkey.Fingerprint(pub)
	fmt.Fprintf(diag, "✓ %s → %s@%s (authorized %s)\n", box, target.User, target.Host, fp)

	return target, privPath, nil
}

// resolveCodeSession resolves box (resolveCodeTarget) and opens an MCP
// session to its agent-box over that SSH path — the transport
// run/attach/status/stop need. `install` doesn't call this: it execs a
// plain shell script over SSH directly, no MCP involved.
func resolveCodeSession(ctx context.Context, box string, diag io.Writer) (*coderun.Session, error) {
	target, privPath, err := resolveCodeTarget(ctx, box, diag)
	if err != nil {
		return nil, err
	}
	sshArgs := connectcore.BuildSSHArgs(target, privPath, "") // no remote command — Connect appends "agent-box"
	sess, err := coderun.Connect(ctx, sshArgs)
	if err != nil {
		return nil, fmt.Errorf("connect to agent-box on %q: %w", box, err)
	}
	return sess, nil
}

// buildClaudeRunCommand renders the command process_start actually spawns:
// source whatever secrets delivery `containarium code install` set up, then
// invoke claude non-interactively. Sourcing here — not relying on a
// login-shell profile — is self-contained per invocation, matching the same
// reasoning claudeVerifyScript uses.
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
			if _, running := coderun.RunOutcomeLine(listing, name); !running {
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

// findSecret returns the metadata for name, if present in secrets.
func findSecret(secrets []*pb.SecretMetadata, name string) (*pb.SecretMetadata, bool) {
	for _, s := range secrets {
		if s.Name == name {
			return s, true
		}
	}
	return nil, false
}

// checkClaudeCredential implements the #1673 AC "installing with no
// credential set fails naming the `secrets set` command, rather than
// hanging on a login prompt" — extended to the delivery-mode footgun found
// in docs/integrations/pi.md: the default "env" delivery would still fail,
// just later and far more confusingly (a hang on claude's own login
// prompt, not a named error here), so it's rejected with the same
// up-front clarity as a missing secret.
func checkClaudeCredential(secrets []*pb.SecretMetadata, box string) error {
	secret, found := findSecret(secrets, claudeOAuthTokenSecretName)
	if !found {
		return fmt.Errorf(
			"no %s secret set for %q — mint one with `claude setup-token` on a trusted machine, then run:\n  containarium secrets set %s %s <token> --delivery compose",
			claudeOAuthTokenSecretName, box, box, claudeOAuthTokenSecretName)
	}
	switch secret.DeliveryMode {
	case pb.SecretDelivery_SECRET_DELIVERY_COMPOSE, pb.SecretDelivery_SECRET_DELIVERY_FILE:
		return nil
	default:
		return fmt.Errorf(
			"%s for %q is delivered as %q — claude runs in an SSH shell session, which does not inherit the LXC's container-start environment (see docs/integrations/pi.md). Re-set it with:\n  containarium secrets set %s %s <token> --delivery compose\n  containarium secrets refresh %s",
			claudeOAuthTokenSecretName, box, secret.DeliveryMode, box, claudeOAuthTokenSecretName, box)
	}
}

// claudeVerifyScript sources whatever secrets delivery the box actually
// has (compose's shared dotenv, or a file-delivery secret converted to an
// env var), asserts ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN are unset,
// then runs one non-interactive prompt. No -t/-tt anywhere on the ssh side
// of this path (buildClaudeSSHArgs never adds one), so no TTY is ever
// allocated for this exec.
func claudeVerifyScript() string {
	return `set -e
if [ -f /run/containarium/secrets.env ]; then set -a; . /run/containarium/secrets.env; set +a; fi
if [ -z "$` + claudeOAuthTokenSecretName + `" ] && [ -f /run/secrets/` + claudeOAuthTokenSecretName + ` ]; then
  export ` + claudeOAuthTokenSecretName + `="$(cat /run/secrets/` + claudeOAuthTokenSecretName + `)"
fi
if [ -n "$ANTHROPIC_API_KEY" ] || [ -n "$ANTHROPIC_AUTH_TOKEN" ]; then
  echo "ANTHROPIC_API_KEY/ANTHROPIC_AUTH_TOKEN must be unset on this box (they outrank CLAUDE_CODE_OAUTH_TOKEN in Claude Code's auth precedence)" >&2
  exit 3
fi
~/.local/bin/claude -p "print the current working directory"`
}

// buildClaudeSSHArgs wraps connectcore.BuildSSHArgs for this command's
// call sites — a single seam so a future need to add flags common to both
// the install and verify exec (e.g. a timeout) touches one place.
func buildClaudeSSHArgs(target connectcore.Target, identity, execCmd string) []string {
	return connectcore.BuildSSHArgs(target, identity, execCmd)
}

func runCodeInstall(cmd *cobra.Command, args []string) error {
	box := args[0]
	if err := validateBoxName(box); err != nil {
		return err
	}
	diag := cmd.ErrOrStderr()
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	// Secrets are a direct daemon RPC (serverAddr/authToken, the same
	// target every other daemon-talking command uses — secrets.go's
	// ListSecrets/RefreshSecrets follow this exact pattern) — NOT the
	// cloud-login-aware --ssh-server box resolution below; those are
	// genuinely different targets in this codebase.
	if serverAddr == "" {
		return fmt.Errorf("--server is required (daemon owns the secrets store)")
	}
	secrets, err := listSecretsFor(box)
	if err != nil {
		return fmt.Errorf("check %s: %w", claudeOAuthTokenSecretName, err)
	}
	if err := checkClaudeCredential(secrets, box); err != nil {
		return err
	}
	if _, _, err := refreshSecretsFor(box); err != nil {
		return fmt.Errorf("refresh secrets on %q: %w", box, err)
	}

	target, privPath, err := resolveCodeTarget(ctx, box, diag)
	if err != nil {
		return err
	}

	if _, err := runSSHCaptured(diag, buildClaudeSSHArgs(target, privPath, claudeInstallScript)); err != nil {
		return fmt.Errorf("install claude on %q: %w", box, err)
	}
	fmt.Fprintf(diag, "✓ claude installed on %s\n", box)

	out, err := runSSHCaptured(diag, buildClaudeSSHArgs(target, privPath, claudeVerifyScript()))
	if err != nil {
		return fmt.Errorf("verify claude on %q: %w (output: %s)", box, err, strings.TrimSpace(out))
	}
	if strings.TrimSpace(out) == "" {
		return fmt.Errorf("claude -p returned an empty response on %q", box)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "✓ claude verified on %s: %s\n", box, strings.TrimSpace(out))
	return nil
}

// listSecretsFor and refreshSecretsFor mirror runSecretsList/
// runSecretsRefresh's dual-transport (httpMode) dispatch exactly, factored
// out so runCodeInstall reads as the install flow rather than repeating
// the http-vs-grpc branch inline.
func listSecretsFor(username string) ([]*pb.SecretMetadata, error) {
	if httpMode {
		h, err := client.NewHTTPClient(serverAddr, authToken)
		if err != nil {
			return nil, err
		}
		defer func() { _ = h.Close() }()
		return h.ListSecrets(username)
	}
	g, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return nil, err
	}
	defer func() { _ = g.Close() }()
	return g.ListSecrets(username)
}

func refreshSecretsFor(username string) (string, int32, error) {
	if httpMode {
		h, err := client.NewHTTPClient(serverAddr, authToken)
		if err != nil {
			return "", 0, err
		}
		defer func() { _ = h.Close() }()
		return h.RefreshSecrets(username)
	}
	g, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = g.Close() }()
	return g.RefreshSecrets(username)
}

// runSSHCaptured runs args non-interactively via the local ssh client and
// returns its captured stdout. ssh's own diagnostics (connection,
// host-key) go to diag, not the returned string, so a caller parsing the
// result gets only the remote command's own bytes — same convention as
// `connect --exec`.
func runSSHCaptured(diag io.Writer, args []string) (string, error) {
	sshBin, err := exec.LookPath("ssh")
	if err != nil {
		return "", fmt.Errorf("ssh not found in PATH: %w", err)
	}
	// #nosec G204 -- sshBin is the resolved `ssh` binary; args are built
	// from a validated box name, a daemon-resolved target, and a
	// package-controlled script (claudeInstallScript / claudeVerifyScript)
	// — no caller-supplied command reaches this path.
	c := exec.Command(sshBin, args...)
	var stdout bytes.Buffer
	c.Stdout = &stdout
	c.Stderr = diag
	if err := c.Run(); err != nil {
		return stdout.String(), fmt.Errorf("ssh: %w", err)
	}
	return stdout.String(), nil
}
