package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/coderun"
	"github.com/footprintai/containarium/internal/connectcore"
	"github.com/footprintai/containarium/internal/sshkey"
	"github.com/footprintai/containarium/pkg/version"
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

// `code install` carries NO credential (#2030). Claude Code's terms
// (https://code.claude.com/docs/en/legal-and-compliance, "Authentication and
// credential use") forbid a platform collecting, storing, or intermediating a
// Claude.ai credential or session token: sign-in must complete through
// Anthropic's own flow. The permitted lane for hosting Claude Code in a
// sandbox is the unmodified binary with each end user bringing their own
// credential — so this command installs a toolchain and stops there. It
// neither reads, lists, nor names a Claude.ai token.

// claudeInstallScript is Claude Code's own native installer, run verbatim. It
// writes to ~/.local/bin/claude — user-level, no root — which is exactly why
// `code install` doesn't need a daemon-side privileged exec path.
const claudeInstallScript = "curl -fsSL https://claude.ai/install.sh | bash"

// agentBoxRepo is where the agent-box / mcp-server release assets live. Same
// assets scripts/install-agent-runtime.sh pulls for the agent-runtime recipe
// — `code install` lands them on an ordinary box so code run/attach/status/
// stop work there too, instead of only on a recipe box.
const agentBoxRepo = "FootprintAI/Containarium"

// agentBoxAssetArch is the only Linux build the release publishes
// (Makefile's build-agent-box-all). Boxes are Linux; darwin assets exist for
// laptops, not for this path.
const agentBoxAssetArch = "linux-amd64"

// codeInstallStateFile carries one bit from the install step to the verify
// step: whether ~/.claude/.credentials.json already existed. A user who
// signed in through Anthropic's flow legitimately has one, so the assertion
// that has to hold is "the install did not create it", not "there is none".
const codeInstallStateFile = "$HOME/.cache/containarium/code-install-state"

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

	// `code install` only (#2030).
	codeBootstrapURL      string
	codeRelease           string
	codeClaudeCodeVersion string
)

// Test seams. Production never reassigns these; they exist so the install
// flow can be driven end to end without a box, a daemon, or an ssh binary.
var (
	sshExec             = runSSHCaptured
	resolveCodeTargetFn = resolveCodeTarget
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

This command installs a toolchain and nothing else. It carries no credential:
Claude Code's terms require sign-in to complete through Anthropic's own flow
(https://code.claude.com/docs/en/legal-and-compliance), so you bring your own
afterwards, one of two ways:

  interactive — SSH in and run claude, then complete the device-code sign-in
  (the documented path for SSH sessions and containers):

    containarium connect <box>
    claude

  headless — place your own ANTHROPIC_API_KEY (or a Bedrock / Vertex / Foundry
  credential) in the "env" block of ~/.claude/settings.json on the box. Both
  interactive claude and agent-box-launched runs read it.

It also lands the agent-box helper on ~/.local/bin, so containarium code
run/attach/status/stop work on this box.

After installing it prints the binary version, asserts the install created no
~/.claude/.credentials.json, and reports which credential SOURCE the box has —
names only, never a value.`,
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

	codeInstallCmd.Flags().StringVar(&codeBootstrapURL, "bootstrap-url", "",
		"URL of a .tar.gz bundle to apply after the toolchain lands — unpacked into a temp dir on the box and its apply.sh run as the box user (skipped when empty)")
	codeInstallCmd.Flags().StringVar(&codeRelease, "release", "",
		"release tag to pull the agent-box / mcp-server assets from, v-prefixed (default: this CLI's own version)")
	codeInstallCmd.Flags().StringVar(&codeClaudeCodeVersion, "claude-code-version", "",
		"pin the Claude Code version the installer fetches (default: whatever the installer considers current)")

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
		if errors.Is(err, coderun.ErrAgentBoxMissing) {
			return nil, coderun.AgentBoxMissingError(box)
		}
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

// defaultAgentBoxRelease is the release the agent-box / mcp-server assets are
// pulled from when --release is omitted: this CLI's own version, v-prefixed.
// pkg/version carries a bare semver while release TAGS carry the v (see
// docs/RELEASE-PROCESS.md), so the prefix is added here rather than assumed.
func defaultAgentBoxRelease() string {
	v := version.Version
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	return v
}

func codeInstallRelease() (string, error) {
	r := strings.TrimSpace(codeRelease)
	if r == "" {
		return defaultAgentBoxRelease(), nil
	}
	if !releaseTagPattern.MatchString(r) {
		return "", fmt.Errorf("--release %q is not a release tag (expected something like v0.89.0)", r)
	}
	return r, nil
}

// claudeInstallScriptFor runs Anthropic's own installer, unmodified. The only
// addition is the one bit the verify step needs: whether a credentials file
// existed BEFORE the install, so "the install created one" can be told apart
// from "the user signed in earlier", which is the supported path.
//
// claudeCodeVersion, when set, is passed to the installer as its argument —
// the installer's own documented way to pin a version. The command line
// itself is unchanged.
func claudeInstallScriptFor(claudeCodeVersion string) string {
	installer := claudeInstallScript
	if v := strings.TrimSpace(claudeCodeVersion); v != "" {
		installer += " -s " + coderun.ShellQuoteSingle(v)
	}
	return `set -e
mkdir -p "$(dirname "` + codeInstallStateFile + `")"
if [ -f "$HOME/.claude/.credentials.json" ]; then
  echo present > "` + codeInstallStateFile + `"
else
  echo absent > "` + codeInstallStateFile + `"
fi
` + installer
}

// agentBoxInstallScript lands agent-box (and, best-effort, mcp-server) in
// ~/.local/bin. User-level, so this stays a plain SSH exec with no privilege
// escalation — the same reason Claude Code's own installer is usable here.
//
// mcp-server is best-effort on purpose, matching
// scripts/install-agent-runtime.sh: a release missing that asset must not
// take down code run/attach/status/stop, which only need agent-box. Both are
// downloaded to a temp file and moved into place, so a failed or truncated
// fetch never leaves a broken binary on PATH.
func agentBoxInstallScript(release string) string {
	base := "https://github.com/" + agentBoxRepo + "/releases/download/" + release
	return `set -e
mkdir -p "$HOME/.local/bin"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl -fsSL "` + base + `/agent-box-` + agentBoxAssetArch + `" -o "$tmp/agent-box" </dev/null
chmod +x "$tmp/agent-box"
mv "$tmp/agent-box" "$HOME/.local/bin/agent-box"
if curl -fsSL "` + base + `/mcp-server-` + agentBoxAssetArch + `" -o "$tmp/mcp-server" </dev/null; then
  chmod +x "$tmp/mcp-server"
  mv "$tmp/mcp-server" "$HOME/.local/bin/mcp-server"
else
  echo "WARNING: no mcp-server-` + agentBoxAssetArch + ` in that release; runs bound to a tracker connection will have no tracker tools" >&2
fi
echo "agent-box installed at $HOME/.local/bin/agent-box"`
}

// releaseTagPattern is what may be interpolated into the asset URL above.
// The tag is a flag value and lands inside a double-quoted shell string, so
// it is validated rather than quoted — a charset with no $, backtick, quote,
// or backslash cannot be anything but a path segment there.
var releaseTagPattern = regexp.MustCompile(`^v?[0-9A-Za-z][0-9A-Za-z._-]*$`)

// bootstrapScript fetches url, unpacks it into a throwaway directory, and
// runs its apply.sh as the box user — the seam a team uses to drop in skills,
// an MCP config, or dotfiles without this command growing a flag per item.
// No sudo anywhere: a bootstrap bundle is the user's own content and gets the
// user's own privileges.
func bootstrapScript(url string) string {
	return `set -e
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl -fsSL ` + coderun.ShellQuoteSingle(url) + ` | tar -xz -C "$tmp"
if [ ! -f "$tmp/apply.sh" ]; then
  echo "bootstrap bundle has no apply.sh at its root" >&2
  exit 4
fi
chmod +x "$tmp/apply.sh"
cd "$tmp" && ./apply.sh`
}

// claudeVerifyScript replaces #1673's non-interactive prompt, which could not
// run without a credential this command no longer supplies.
//
// It does three things: prints the installed binary's version, asserts the
// install created no ~/.claude/.credentials.json (a platform must never mint
// or store a Claude.ai credential), and reports which credential SOURCE the
// box has. That last part is deliberately NAMES ONLY — every branch tests for
// presence and echoes a literal, because expanding any of these would put a
// live credential into the CLI's output and the user's scrollback.
func claudeVerifyScript() string {
	return `set -e
"$HOME/.local/bin/claude" --version
creds="$HOME/.claude/.credentials.json"
before=absent
if [ -f "` + codeInstallStateFile + `" ]; then
  before="$(cat "` + codeInstallStateFile + `")"
  rm -f "` + codeInstallStateFile + `"
fi
if [ "$before" = absent ] && [ -f "$creds" ]; then
  echo "the install created $creds — containarium never mints or stores a Claude.ai credential" >&2
  exit 3
fi
echo "credential sources present:"
found=0
if [ -f "$creds" ]; then
  echo "  - $creds (signed in through Anthropic's own flow)"
  found=1
fi
settings="$HOME/.claude/settings.json"
for key in ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN; do
  if [ -f "$settings" ] && grep -q "\"$key\"" "$settings"; then
    echo "  - $key in the env block of $settings"
    found=1
  fi
done
providers="$(env | sed -n 's/^\(CLAUDE_CODE_USE_[A-Z0-9_]*\)=.*/\1/p')"
if [ -n "$providers" ]; then
  for p in $providers; do echo "  - $p (3P inference provider)"; done
  found=1
fi
if [ "$found" = 0 ]; then
  echo "  (none yet — sign in on the box, or place your own key in $settings)"
fi`
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
	release, err := codeInstallRelease()
	if err != nil {
		return err
	}
	diag := cmd.ErrOrStderr()
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	// No secrets RPC and no --server: this command reaches the box over SSH
	// and installs binaries. There is no credential for it to fetch (#2030).
	target, privPath, err := resolveCodeTargetFn(ctx, box, diag)
	if err != nil {
		return err
	}
	run := func(script string) (string, error) {
		return sshExec(diag, buildClaudeSSHArgs(target, privPath, script))
	}

	if _, err := run(claudeInstallScriptFor(codeClaudeCodeVersion)); err != nil {
		return fmt.Errorf("install claude on %q: %w", box, err)
	}
	fmt.Fprintf(diag, "✓ claude installed on %s\n", box)

	if _, err := run(agentBoxInstallScript(release)); err != nil {
		return fmt.Errorf("install agent-box (%s) on %q: %w", release, box, err)
	}
	fmt.Fprintf(diag, "✓ agent-box installed on %s (from %s)\n", box, release)

	if url := strings.TrimSpace(codeBootstrapURL); url != "" {
		if _, err := run(bootstrapScript(url)); err != nil {
			return fmt.Errorf("apply bootstrap bundle on %q: %w", box, err)
		}
		fmt.Fprintf(diag, "✓ bootstrap bundle applied on %s\n", box)
	}

	out, err := run(claudeVerifyScript())
	if err != nil {
		return fmt.Errorf("verify claude on %q: %w (output: %s)", box, err, strings.TrimSpace(out))
	}
	if strings.TrimSpace(out) == "" {
		return fmt.Errorf("claude --version produced no output on %q", box)
	}
	stdout := cmd.OutOrStdout()
	fmt.Fprintf(stdout, "✓ claude verified on %s:\n%s\n", box, strings.TrimSpace(out))
	fmt.Fprint(stdout, codeSignInHelp(box))
	return nil
}

// codeSignInHelp is what replaces the credential this command used to require.
// Both paths complete through Anthropic's own flow or the user's own key; the
// platform is not in the middle of either.
func codeSignInHelp(box string) string {
	return fmt.Sprintf(`
Claude Code is installed but not signed in. Pick one:

  interactive — sign in inside the box (device code, no credential stored here):
      containarium connect %s
      claude

  headless — place your own key in the "env" block of ~/.claude/settings.json
  on the box (ANTHROPIC_API_KEY, or a Bedrock / Vertex / Foundry credential):
      {"env": {"ANTHROPIC_API_KEY": "<your key>"}}

Then: containarium code run %s --prompt "..."
`, box, box)
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
