package cmd

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/credentials"
	"github.com/spf13/cobra"
)

// Sub-task A3 of umbrella-issue #100: client-side device-flow
// consumer that pairs with the cloud's CLISessionService.
// See prd/cloud/cli-login-and-multi-env-ssh.md §"Design — `containarium login`".
//
// The CLI POSTs /v1/cli/sessions, opens the verification URL in a
// browser, polls /v1/cli/sessions/{id}/status until approved, then
// persists the token to ~/.containarium/credentials.json via the
// credentials store. The login command itself is unauthenticated —
// the user_code + browser-side approval ARE the credential. We
// intentionally use raw net/http here rather than the existing
// internal/client/http.go wrapper, which expects an
// already-authenticated bearer token (see Stop conditions in the
// task brief).

const (
	defaultLoginServer = "https://cloud.containarium.dev"
	loginPollInterval  = 5 * time.Second
	loginMaxWait       = 10 * time.Minute
	loginHTTPTimeout   = 30 * time.Second
)

// Per-command flags. Top-level `--server` and `--token` are reused
// from root.go; these are login/logout/whoami specifics.
var (
	loginServer      string // explicit override for login/logout/whoami
	loginDeviceName  string
	loginNoBrowser   bool
	logoutAll        bool
	configTokenSrv   string
	whoamiServerFlag string

	// Sub-task A7 (umbrella-issue #100): post-login SSH-key
	// auto-registration. Default behaviour is "prompt the user with
	// Y default"; --with-ssh-setup forces the prompt-and-go path
	// non-interactively (assume yes), and --no-ssh-setup skips it
	// entirely. The two flags are mutually exclusive — cobra
	// enforces.
	loginWithSSHSetup bool
	loginNoSSHSetup   bool
)

// loginPromptReader is the io.Reader the prompt loop drains for the
// y/N answer. Tests swap it for a strings.Reader; production reads
// from stdin. Kept package-private so nothing else accidentally
// drives the login prompt.
var loginPromptReader io.Reader = os.Stdin

// pollIntervalOverride lets tests dial the polling interval down to
// milliseconds so the device-flow happy-path runs fast. Defaults to
// the production constant.
var pollIntervalOverride = loginPollInterval

// maxWaitOverride lets tests shrink the overall approval window so the
// timeout path (and its #456 collision guidance) is exercisable in
// milliseconds. Defaults to the production constant.
var maxWaitOverride = loginMaxWait

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate against a Containarium server via browser device flow",
	Long: `Open the browser to approve a CLI session, then persist the resulting
token to ~/.containarium/credentials.json (0600).

The token is automatically picked up by subsequent CLI commands when
neither --token nor CONTAINARIUM_TOKEN is set. See ` + "`containarium --help`" + `
for the precedence order.

The login flow is the standard OAuth-style device flow:

  1. CLI POSTs /v1/cli/sessions to the cloud; cloud returns
     {session_id, user_code, verification_url}.
  2. CLI opens verification_url in your default browser (or prints
     it if --no-browser is set / the OS launcher fails).
  3. You approve the session in the browser.
  4. CLI polls /v1/cli/sessions/{id}/status every 5s (max 10min)
     until status == approved, then writes credentials.json.

Multi-server: you can be logged into the hosted cloud AND a
self-hosted instance simultaneously. The first server you log into
becomes the default; --server picks a non-default one.`,
	Example: `  # Log in to the hosted cloud
  containarium login

  # Log in to a self-hosted instance
  containarium login --server=https://containarium.internal.example.com

  # Headless mode (don't try to open a browser)
  containarium login --no-browser`,
	RunE: runLogin,
}

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Remove stored credentials for a server",
	Long: `Delete the token + identity stored in ~/.containarium/credentials.json
for a given server. Does NOT call the cloud — the token on the
server side remains until it expires or is explicitly revoked via
` + "`containarium token revoke`" + `.

If neither --server nor --all is given, logs out of the default
server.`,
	Example: `  # Log out of the default server
  containarium logout

  # Log out of a specific server
  containarium logout --server=https://cloud.containarium.dev

  # Wipe credentials for every server
  containarium logout --all`,
	RunE: runLogout,
}

var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Print the active server and identity",
	Long: `Show the credentials store's view of "who am I" — which server is the
default, what email + org are associated with it, and when the
token was issued / expires.

Exit code is non-zero when no credentials are stored for the
selected server (useful in shell scripts: ` + "`containarium whoami || containarium login`" + `).`,
	RunE: runWhoami,
}

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Read CLI configuration (credentials, defaults)",
	Long:  `Inspect the local CLI state stored under ~/.containarium/. See subcommands.`,
}

var configGetTokenCmd = &cobra.Command{
	Use:   "get-token",
	Short: "Print the stored token for a server (script-friendly)",
	Long: `Emit the bearer token stored in ~/.containarium/credentials.json
for the given (or default) server, on stdout. No trailing newline,
so it composes with shell pipes:

  export TOKEN=$(containarium config get-token)
  curl -H "Authorization: Bearer $TOKEN" ...

Exit code is non-zero if no token is stored.`,
	RunE: runConfigGetToken,
}

func init() {
	loginCmd.Flags().StringVar(&loginServer, "server", "", "server to log in to (default: "+defaultLoginServer+")")
	loginCmd.Flags().StringVar(&loginDeviceName, "device-name", "", "human label for this session (default: <user>@<host>-<rand>, auto-disambiguated per login); an explicit name is used verbatim")
	loginCmd.Flags().BoolVar(&loginNoBrowser, "no-browser", false, "don't try to open a browser; print the URL instead")
	loginCmd.Flags().BoolVar(&loginWithSSHSetup, "with-ssh-setup", false, "after login, register this machine's SSH public key non-interactively (skips the y/N prompt)")
	loginCmd.Flags().BoolVar(&loginNoSSHSetup, "no-ssh-setup", false, "after login, skip the SSH-key registration prompt entirely")
	loginCmd.MarkFlagsMutuallyExclusive("with-ssh-setup", "no-ssh-setup")

	logoutCmd.Flags().StringVar(&loginServer, "server", "", "server to log out of (default: default_server)")
	logoutCmd.Flags().BoolVar(&logoutAll, "all", false, "wipe credentials for all servers")

	whoamiCmd.Flags().StringVar(&whoamiServerFlag, "server", "", "server to query (default: default_server)")

	configGetTokenCmd.Flags().StringVar(&configTokenSrv, "server", "", "server to read the token for (default: default_server)")

	configCmd.AddCommand(configGetTokenCmd)

	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(logoutCmd)
	rootCmd.AddCommand(whoamiCmd)
	rootCmd.AddCommand(configCmd)
}

// Wire-format DTOs for the device-flow endpoints. The cloud's
// CLISessionService is the source of truth; these structs mirror
// its JSON shape per the PRD.
//
// Per CLAUDE.md, we use typed structs at the HTTP boundary rather
// than map[string]interface{} — even though the JSON-RPC at the
// edge of MCP gets a pass, ordinary REST calls do not.

type createSessionReq struct {
	DeviceName string `json:"device_name"`
}

// JSON tags are lowerCamelCase: the cloud's CLISessionService is served
// through grpc-gateway, whose protojson marshaler emits proto field names
// in camelCase (sessionId, verificationUrl, …), NOT the snake_case proto
// names. An earlier version used snake_case and silently decoded every
// field to its zero value (→ "incomplete session"). Names mirror the
// cloud CLISessionService's grpc-gateway JSON.
type createSessionResp struct {
	SessionID       string `json:"sessionId"`
	UserCode        string `json:"userCode"`
	VerificationURL string `json:"verificationUrl"`
	// Proto field expires_in_seconds → expiresInSeconds on the wire.
	ExpiresIn int `json:"expiresInSeconds"`
}

type sessionStatusResp struct {
	// Status is a CLISessionStatus proto enum; grpc-gateway emits it as the
	// enum NAME ("CLI_SESSION_STATUS_APPROVED"), so it is normalized to the
	// short form (pending|approved|denied|expired) in fetchSessionStatus.
	Status string `json:"status"`
	Token  string `json:"token,omitempty"`
	// UserEmail / OrgID are NOT in the cloud's GetCLISessionStatusResponse
	// (it carries only status/token/expires_at/approved_at), so they stay
	// empty here — identity is carried by the token itself. Retained so the
	// credentials write + whoami display compile; tags are harmless.
	UserEmail string `json:"userEmail,omitempty"`
	OrgID     string `json:"orgId,omitempty"`
	// ExpiresAt is RFC3339; absent or empty means non-expiring.
	ExpiresAt string `json:"expiresAt,omitempty"`
}

// emailFromToken best-effort extracts a human identity from a JWT access
// token WITHOUT verifying its signature — display only. The cloud's
// CLI-session-status response doesn't carry the user email (identity lives in
// the token itself, see sessionStatusResp), so we read it from the token's
// claims to label the login ("Logged in as …") and persist it for `whoami`.
// Returns "" for anything that isn't a decodable JWT, so the caller falls back
// gracefully (previously every login showed "unknown user", #634 follow-up).
func emailFromToken(tok string) string {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return "" // not a JWT (e.g. an opaque token) — nothing to decode
	}
	// JWT segments are unpadded base64url; tolerate accidental padding too.
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return ""
	}
	var claims struct {
		Email             string `json:"email"`
		PreferredUsername string `json:"preferred_username"`
		Sub               string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	switch {
	case claims.Email != "":
		return claims.Email
	case claims.PreferredUsername != "":
		return claims.PreferredUsername
	default:
		return claims.Sub
	}
}

// loginHTTPClient is the unauthenticated HTTP client used by the
// device-flow handshake. Kept private so nothing else accidentally
// uses it.
func loginHTTPClient() *http.Client {
	return &http.Client{Timeout: loginHTTPTimeout}
}

// isCloudServer reports whether srv is the managed cloud rather than a
// self-hosted OSS daemon. The two have different box-access models — cloud
// authenticates with the API token (`containarium connect`), self-hosted with
// the user's SSH key — so the post-login flow branches on it. Detection keys off
// the cloud apex host (defaultLoginServer), normalized so an explicit --server
// pointing at the cloud is recognized too.
func isCloudServer(srv string) bool {
	return credentials.NormalizeServer(srv) == credentials.NormalizeServer(defaultLoginServer)
}

// pickLoginServer resolves the effective server URL for login:
// the explicit flag wins, otherwise the constant default. We do
// NOT consult $CONTAINARIUM_SERVER here — that env var is for the
// daemon/gRPC server, which is a different surface (the cloud
// auth endpoint).
func pickLoginServer(explicit string) string {
	if explicit != "" {
		return strings.TrimRight(explicit, "/")
	}
	return defaultLoginServer
}

// deviceName returns the label for the CLI session / minted credential.
//
// An explicit --device-name is returned verbatim: the user owns that
// name and may want a stable label (accepting that a re-login under the
// same name can collide with a still-live token on the server — see
// the timeout guidance in runLogin and #456).
//
// The DEFAULT name — "<user>@<host>" — additionally gets a short random
// suffix. The CLI polls an unauthenticated status endpoint and can't see
// the server's credential list, so it can't detect a name collision
// before the browser approve; when the default name is already taken the
// approve is refused server-side and the CLI polls to timeout with no
// actionable signal (#456). Appending a per-login suffix sidesteps that
// entirely: repeat logins from the same host mint distinct names and
// "just work". The cost is one extra (revocable) token per login,
// prunable in the cloud's API-tokens UI — a far better failure mode than
// a silent 10-minute strand.
//
// The default is also conformed to the cloud's device_name charset
// (#634): "<user>@<host>" carries '@', which is outside the allowed set
// [-_.() a-zA-Z0-9], so an unsanitized default 400s on every login. An
// explicit override is NOT sanitized — the user owns that string.
func deviceName(override string) string {
	if override != "" {
		return override
	}
	return defaultDeviceName(defaultDeviceBase(), shortDeviceSuffix())
}

// allowedDeviceNameLen is the cloud's device_name cap (1-64 chars).
const allowedDeviceNameLen = 64

// defaultDeviceName joins the base + random suffix and conforms the result
// to the cloud's device_name validation: 1-64 chars of [-_.() a-zA-Z0-9]
// (#634). Disallowed runes in the base are mapped to '-'; the base is then
// clamped so "<base>-<suffix>" fits the cap, keeping the suffix intact (it's
// what guarantees the per-login uniqueness from #456).
func defaultDeviceName(base, suffix string) string {
	clean := sanitizeDeviceLabel(base)
	if max := allowedDeviceNameLen - len(suffix) - 1; max < 1 {
		clean = "" // suffix alone already fills the budget
	} else if len(clean) > max {
		clean = clean[:max] // safe: sanitizeDeviceLabel emits ASCII only
	}
	clean = strings.Trim(clean, "- ")
	if clean == "" {
		return suffix
	}
	return clean + "-" + suffix
}

// sanitizeDeviceLabel maps a label to the cloud's allowed device_name
// charset [-_.() a-zA-Z0-9], replacing any other rune (e.g. '@' in
// <user>@<host>, or '\' in a Windows DOMAIN\user) with '-'. Output is
// ASCII-only, so byte-slicing it for the length clamp is safe.
func sanitizeDeviceLabel(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '_', r == '.', r == '(', r == ')', r == ' ':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return b.String()
}

// defaultDeviceBase builds the stable "<user>@<host>" portion of the
// default device name, with graceful fallbacks when either is missing.
func defaultDeviceBase() string {
	var who, host string
	if u, err := user.Current(); err == nil {
		who = u.Username
	}
	host, _ = os.Hostname()
	switch {
	case who != "" && host != "":
		return fmt.Sprintf("%s@%s", who, host)
	case host != "":
		return host
	case who != "":
		return who
	}
	return "containarium-cli"
}

// shortDeviceSuffix returns a short, unique-enough token (6 hex chars)
// used to disambiguate repeat logins from one host. Falls back to a
// nanosecond-derived value if the system RNG is unavailable — that still
// varies per call, preserving the no-collision property.
func shortDeviceSuffix() string {
	var b [3]byte
	if _, err := rand.Read(b[:]); err == nil {
		return hex.EncodeToString(b[:])
	}
	return strconv.FormatInt(time.Now().UnixNano()&0xffffff, 16)
}

// openBrowser fires-and-forgets the platform-native URL opener. We
// intentionally don't block on the child process — the user may
// not return for minutes, and the polling loop is what actually
// drives login. Returns the error from exec.Start so callers can
// fall back to printing the URL.
//
// Cross-platform handling per the task brief: linux→xdg-open,
// darwin→open, windows→cmd /c start. Unknown OSes get an error
// and we print the URL.
func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		// #nosec G204 -- url comes from the cloud's session
		// response; the user already trusts that endpoint.
		cmd = exec.Command("xdg-open", url)
	case "darwin":
		// #nosec G204
		cmd = exec.Command("open", url)
	case "windows":
		// "start" is a cmd builtin, hence the cmd /c wrapper.
		// "" placeholder is start's window-title argument; without
		// it URLs containing & get truncated.
		// #nosec G204
		cmd = exec.Command("cmd", "/c", "start", "", url)
	default:
		return fmt.Errorf("unsupported OS for auto-launch: %s", runtime.GOOS)
	}
	return cmd.Start()
}

func runLogin(cmd *cobra.Command, args []string) error {
	srv := pickLoginServer(loginServer)
	out := cmd.OutOrStdout()
	hc := loginHTTPClient()
	ctx, cancel := context.WithTimeout(context.Background(), maxWaitOverride+loginHTTPTimeout)
	defer cancel()

	// 1. Open a session. Compute the device name once so the value sent
	//    to the server matches what we surface in any later message (the
	//    default name carries a random suffix — see deviceName).
	dev := deviceName(loginDeviceName)
	sess, err := createSession(ctx, hc, srv, dev)
	if err != nil {
		return fmt.Errorf("open CLI session: %w", err)
	}

	fmt.Fprintf(out, "Opening browser to %s\n", sess.VerificationURL)
	fmt.Fprintf(out, "If your browser doesn't open, visit that URL and enter code: %s\n", sess.UserCode)
	if !loginNoBrowser {
		if err := openBrowser(sess.VerificationURL); err != nil {
			// Fall back gracefully — the user already has the URL.
			fmt.Fprintf(out, "(could not auto-launch browser: %v — please open the URL manually)\n", err)
		}
	}
	fmt.Fprintf(out, "(polls every %s, max %s)\n", loginPollInterval, loginMaxWait)

	// 2. Poll status until terminal.
	status, err := pollSession(ctx, out, hc, srv, sess.SessionID, pollIntervalOverride, maxWaitOverride)
	if err != nil {
		// A timeout most often means the browser approval never landed.
		// The single most common reason it silently fails: the token
		// the approval mints is named after --device-name, and a token
		// with that name already exists in the org, so the server
		// refuses the approve and the session just sits pending until it
		// expires (#456). The CLI can't see that approve-side error
		// (it's unauthenticated and only polls status), so spell out the
		// remedy instead of leaving the user staring at a bare timeout.
		if errors.Is(err, errPollTimeout) {
			base := strings.TrimRight(srv, "/")
			fmt.Fprintf(out, "\nApproval didn't complete in time.\n")
			if loginDeviceName != "" {
				// Only explicit --device-name can still collide; the
				// default name is auto-disambiguated (see deviceName).
				fmt.Fprintf(out, "The device name %q may already be in use —\n", dev)
				fmt.Fprintf(out, "revoke the old token at %s/settings/api-tokens, or rerun with a different --device-name (or omit it to auto-disambiguate).\n", base)
			} else {
				fmt.Fprintf(out, "Revoke any stale tokens at %s/settings/api-tokens and try again.\n", base)
			}
		}
		return err
	}

	// 3. Persist credentials. The status response doesn't carry the user
	//    email (identity lives in the token), so recover it from the token's
	//    JWT claims for the banner + `whoami`; falls back to "" if the token
	//    isn't a decodable JWT.
	email := status.UserEmail
	if email == "" {
		email = emailFromToken(status.Token)
	}
	creds := credentials.ServerCreds{
		Token:     status.Token,
		UserEmail: email,
		OrgID:     status.OrgID,
		IssuedAt:  time.Now().UTC(),
	}
	if status.ExpiresAt != "" {
		if t, err := time.Parse(time.RFC3339, status.ExpiresAt); err == nil {
			creds.ExpiresAt = &t
		}
	}

	path, err := credentials.DefaultPath()
	if err != nil {
		return err
	}
	cf, err := credentials.Load(path)
	if err != nil {
		return err
	}
	cf.Set(srv, creds)
	if cf.DefaultServer == "" {
		cf.DefaultServer = credentials.NormalizeServer(srv)
	}
	if err := credentials.Save(path, cf); err != nil {
		return fmt.Errorf("save credentials: %w", err)
	}

	who := email
	if who == "" {
		who = "unknown user"
	}
	fmt.Fprintf(out, "✓ Logged in as %s\n", who)
	fmt.Fprintf(out, "✓ API token saved to %s\n", path)
	// K2 of cloud#147 — surface the rotation path so the operator
	// knows where to find the token they just got handed. The cloud
	// minted this token during the cli-session approve flow; it's
	// org-scoped and long-lived (no expiry) until explicit revoke.
	fmt.Fprintf(out, "  → View / rotate at %s/settings/api-tokens\n",
		strings.TrimRight(srv, "/"))

	// Sub-task A7: optionally register this machine's SSH key for
	// access to boxes created under this account. Done as a tail of
	// login so a fresh user gets a working `ssh <box>` after a single
	// command. Errors are surfaced but non-fatal — the login itself
	// succeeded, and the user can re-run `containarium ssh setup`
	// later.
	maybeRunPostLoginSSHSetup(out, srv)
	return nil
}

// maybeRunPostLoginSSHSetup implements the A7 contract:
//
//	--no-ssh-setup        skip silently
//	--with-ssh-setup      run setup non-interactively (assume yes)
//	neither (default)     prompt "Register this machine's SSH key
//	                      as 'X' for SSH access to your boxes? [Y/n]"
//	                      — empty answer = yes, anything else parsed
//
// In non-TTY environments (CI, pipes) we treat an empty/EOF answer
// as "no" because hitting people with a key-registration in CI
// without an explicit opt-in is hostile. Use --with-ssh-setup to
// force-on in CI.
func maybeRunPostLoginSSHSetup(out io.Writer, srv string) {
	if loginNoSSHSetup {
		return
	}

	// Two access models:
	//   - Cloud: the API token you just minted IS the credential.
	//     `containarium connect <box>` turns it into a shell with a managed key
	//     — there's no personal SSH key to register. So we skip key registration
	//     and point at connect.
	//   - Self-hosted (OSS): boxes are reached over plain `ssh` with the user's
	//     own key, so the registration flow below applies.
	// --with-ssh-setup forces the key flow even against the cloud, for users who
	// still want plain `ssh user@host`.
	if isCloudServer(srv) && !loginWithSSHSetup {
		fmt.Fprintf(out, "\nOpen a shell on a box:  containarium connect <box>\n")
		return
	}

	name := defaultLocalKeyName()
	if loginDeviceName != "" {
		// Re-use the login --device-name when the user gave one;
		// otherwise the SSH-keys table on the cloud has a different
		// label than the "Active sessions" table, which is confusing.
		name = loginDeviceName
	}

	// Prompt-or-skip decision.
	yes := loginWithSSHSetup
	if !yes {
		isTTY := isStdinTTY()
		prompt := fmt.Sprintf("\nRegister this machine's SSH key as %q for SSH access to your boxes? [Y/n] ", name)
		fmt.Fprint(out, prompt)
		ans, ok := readYesNo(loginPromptReader)
		switch {
		case !ok && isTTY:
			fmt.Fprintln(out, "(no answer; skipping. Run `containarium ssh setup` later.)")
			return
		case !ok:
			// Non-TTY + no answer = silent no.
			return
		case ans:
			yes = true
		default:
			fmt.Fprintln(out, "(skipped. Run `containarium ssh setup` later.)")
			return
		}
	}

	if !yes {
		return
	}

	// Drive the same code path `containarium ssh setup` uses, with
	// the post-login defaults wired in. Errors surface as warnings
	// because the login itself already succeeded — we don't want to
	// roll that back.
	oldName, oldServer := sshSetupName, sshSetupServer
	sshSetupName = name
	sshSetupServer = srv
	defer func() {
		sshSetupName = oldName
		sshSetupServer = oldServer
	}()

	// Build a tiny cobra context so the handler's cmd.OutOrStdout()
	// flows to the same writer login is using.
	tmp := &cobra.Command{}
	tmp.SetOut(out)
	if err := runSSHSetup(tmp, nil); err != nil {
		fmt.Fprintf(out, "⚠ SSH key setup skipped: %v\n", err)
		fmt.Fprintln(out, "  You can re-run it later with `containarium ssh setup`.")
	}
}

// readYesNo reads a single line from r and returns (yes, true) for
// y/Y/yes/empty (because the prompt's default is Y), (no, true) for
// n/N/no, and (_, false) for EOF.
func readYesNo(r io.Reader) (bool, bool) {
	if r == nil {
		return false, false
	}
	br := bufio.NewReader(r)
	line, err := br.ReadString('\n')
	if err != nil && line == "" {
		return false, false
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "", "y", "yes":
		return true, true
	case "n", "no":
		return false, true
	default:
		// Unrecognised answer = treat as "no" but ok=true so the
		// caller knows we got *some* input.
		return false, true
	}
}

// isStdinTTY is a best-effort "are we attached to a terminal?"
// check. We don't pull in golang.org/x/term to keep the dependency
// footprint tight — Stat() on stdin and checking the file mode is
// good enough for the "should I treat empty-prompt as silent skip?"
// decision below.
func isStdinTTY() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// defaultLocalKeyName is defined in ssh.go (same package); this
// comment is just a pointer for the next reader so they don't grep
// for a missing helper.

// createSession POSTs /v1/cli/sessions and decodes the response.
func createSession(ctx context.Context, hc *http.Client, server, device string) (*createSessionResp, error) {
	body, err := json.Marshal(createSessionReq{DeviceName: device})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server+"/v1/cli/sessions", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	var out createSessionResp
	if err := json.Unmarshal(rb, &out); err != nil {
		return nil, fmt.Errorf("decode session response: %w", err)
	}
	if out.SessionID == "" || out.VerificationURL == "" {
		return nil, fmt.Errorf("server returned incomplete session: %+v", out)
	}
	return &out, nil
}

// pollSession GETs /v1/cli/sessions/{id}/status every interval and
// returns the final non-pending status. It rides out transient errors
// (network blips, 5xx, 408/429) until the maxWait deadline rather than
// aborting on the first one — a momentary DNS or connectivity hiccup
// must not kill a multi-minute login while the user is mid-approval in
// the browser (#455). Terminal conditions stop immediately: a gone
// session (404), a non-retryable HTTP error, denied/expired status, or
// a cancelled context. Progress notices for transient retries go to
// out (nil-safe).
func pollSession(ctx context.Context, out io.Writer, hc *http.Client, server, sessionID string, interval, maxWait time.Duration) (*sessionStatusResp, error) {
	deadline := time.Now().Add(maxWait)
	url := fmt.Sprintf("%s/v1/cli/sessions/%s/status", server, sessionID)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var consecutiveTransient int
	for {
		st, err := fetchSessionStatus(ctx, hc, url)
		if err != nil {
			// Terminal: the session is gone — stop, consistent with the
			// "expired" status branch below.
			if errors.Is(err, errSessionGone) {
				return nil, fmt.Errorf("login session expired before approval")
			}
			// Terminal: a non-retryable HTTP error (bad request, auth,
			// etc.). Retrying won't change the answer.
			var he httpStatusError
			if errors.As(err, &he) && !he.retryable() {
				return nil, fmt.Errorf("poll session status: %w", err)
			}
			// Transient: network error, 5xx, or 408/429. Keep polling
			// until the deadline, but bail if they pile up consecutively
			// (server down for good) so we fail faster than maxWait.
			consecutiveTransient++
			if consecutiveTransient >= maxConsecutivePollFailures {
				return nil, fmt.Errorf("poll session status: %d consecutive failures, last: %w", consecutiveTransient, err)
			}
			if time.Now().After(deadline) {
				return nil, fmt.Errorf("%w (after %s); last error: %v", errPollTimeout, maxWait, err)
			}
			if out != nil {
				fmt.Fprintf(out, "  (transient error polling status, retrying: %v)\n", err)
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-ticker.C:
			}
			continue
		}
		consecutiveTransient = 0

		switch st.Status {
		case "approved":
			if st.Token == "" {
				return nil, fmt.Errorf("server reported approved but no token in response")
			}
			return st, nil
		case "denied":
			return nil, fmt.Errorf("login denied in browser")
		case "expired":
			return nil, fmt.Errorf("login session expired before approval")
		case "pending", "":
			// continue
		default:
			return nil, fmt.Errorf("unknown session status %q", st.Status)
		}

		if time.Now().After(deadline) {
			return nil, fmt.Errorf("%w (after %s)", errPollTimeout, maxWait)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func fetchSessionStatus(ctx context.Context, hc *http.Client, url string) (*sessionStatusResp, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		// Terminal: the session row is gone (expired / swept / unknown
		// id). Re-polling can't bring it back.
		return nil, errSessionGone
	}
	if resp.StatusCode >= 400 {
		// Carry the code so pollSession can decide retry-vs-give-up by
		// class (5xx / 408 / 429 are transient; other 4xx aren't).
		return nil, httpStatusError{code: resp.StatusCode, body: strings.TrimSpace(string(rb))}
	}
	var out sessionStatusResp
	if err := json.Unmarshal(rb, &out); err != nil {
		return nil, fmt.Errorf("decode status response: %w", err)
	}
	out.Status = normalizeSessionStatus(out.Status)
	return &out, nil
}

// errSessionGone is the terminal "this session no longer exists" signal
// — a 404 from the status endpoint (expired, swept, or unknown id).
// pollSession stops on it rather than retrying.
var errSessionGone = errors.New("session not found (id may have expired)")

// errPollTimeout marks the "ran out the maxWait window without an
// approval" case so runLogin can attach actionable guidance (the most
// common real cause is a device-name collision — see #456) without
// string-matching the error text.
var errPollTimeout = errors.New("timed out waiting for approval")

// httpStatusError carries a non-2xx status from the status endpoint so
// pollSession can classify it. A bare fmt.Errorf would force the loop
// to string-match the code, which is exactly the brittleness #455 is
// about.
type httpStatusError struct {
	code int
	body string
}

func (e httpStatusError) Error() string {
	if e.body != "" {
		return fmt.Sprintf("status %d: %s", e.code, e.body)
	}
	return fmt.Sprintf("status %d", e.code)
}

// retryable reports whether re-polling could plausibly succeed: a
// transient server fault (5xx) or a back-pressure signal (408, 429).
// Any other 4xx is a client/contract problem that won't self-heal.
func (e httpStatusError) retryable() bool {
	return e.code >= 500 ||
		e.code == http.StatusRequestTimeout ||
		e.code == http.StatusTooManyRequests
}

// maxConsecutivePollFailures bounds how many back-to-back transient
// poll failures we ride out before giving up. The maxWait deadline is
// the real ceiling; this just fails faster when the server is
// unreachable for good instead of silently retrying the whole window.
// ~10 failures at the 5s default poll interval ≈ under a minute of
// solid errors before we bail.
const maxConsecutivePollFailures = 10

// normalizeSessionStatus folds the cloud's CLISessionStatus proto-enum wire
// form ("CLI_SESSION_STATUS_APPROVED") down to the short lowercase token the
// poll loop switches on ("approved"). Tolerant of the short form too, so it
// is a no-op if the wire ever emits the shorter shape. Empty stays empty
// (treated as "pending" by the caller).
func normalizeSessionStatus(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.TrimPrefix(s, "cli_session_status_")
}

func runLogout(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	path, err := credentials.DefaultPath()
	if err != nil {
		return err
	}
	cf, err := credentials.Load(path)
	if err != nil {
		return err
	}

	if logoutAll {
		if len(cf.Servers) == 0 {
			fmt.Fprintln(out, "No stored credentials.")
			return nil
		}
		cf.Servers = map[string]credentials.ServerCreds{}
		cf.DefaultServer = ""
		if err := credentials.Save(path, cf); err != nil {
			return fmt.Errorf("save credentials: %w", err)
		}
		fmt.Fprintln(out, "Removed credentials for all servers.")
		return nil
	}

	srv := loginServer
	if srv == "" {
		srv = cf.DefaultServer
	}
	if srv == "" {
		return fmt.Errorf("no server specified and no default server in credentials file")
	}
	if !cf.Remove(srv) {
		return fmt.Errorf("no stored credentials for %s", srv)
	}
	if err := credentials.Save(path, cf); err != nil {
		return fmt.Errorf("save credentials: %w", err)
	}
	fmt.Fprintf(out, "Removed credentials for %s\n", srv)
	return nil
}

// errNoSession is returned by whoami / config get-token when the
// credentials file has no matching entry. We use a sentinel so
// callers can map it to a clean exit code without an extra string
// match.
var errNoSession = errors.New("no stored credentials")

func runWhoami(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	path, err := credentials.DefaultPath()
	if err != nil {
		return err
	}
	cf, err := credentials.Load(path)
	if err != nil {
		return err
	}
	srv := whoamiServerFlag
	if srv == "" {
		srv = cf.DefaultServer
	}
	creds, ok := cf.Get(srv)
	if !ok {
		return fmt.Errorf("%w (run `containarium login` to authenticate)", errNoSession)
	}
	fmt.Fprintf(out, "Server:      %s\n", srv)
	fmt.Fprintf(out, "User email:  %s\n", orDash(creds.UserEmail))
	fmt.Fprintf(out, "Org ID:      %s\n", orDash(creds.OrgID))
	if !creds.IssuedAt.IsZero() {
		fmt.Fprintf(out, "Issued at:   %s\n", creds.IssuedAt.Format(time.RFC3339))
	}
	if creds.ExpiresAt != nil {
		fmt.Fprintf(out, "Expires at:  %s\n", creds.ExpiresAt.Format(time.RFC3339))
	} else {
		fmt.Fprintln(out, "Expires at:  never")
	}
	return nil
}

func runConfigGetToken(cmd *cobra.Command, args []string) error {
	path, err := credentials.DefaultPath()
	if err != nil {
		return err
	}
	cf, err := credentials.Load(path)
	if err != nil {
		return err
	}
	srv := configTokenSrv
	creds, ok := cf.Get(srv)
	if !ok || creds.Token == "" {
		return errNoSession
	}
	// No trailing newline — composes with shell pipes per docstring.
	fmt.Fprint(cmd.OutOrStdout(), creds.Token)
	return nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// resolveAuthToken implements the precedence chain documented in
// `containarium --help`:
//
//  1. --token flag (explicit)
//  2. CONTAINARIUM_TOKEN env var
//  3. ~/.containarium/credentials.json (server matching --server,
//     else default_server)
//
// Step 1 + 2 are already collapsed into the `authToken` variable by
// the time cobra invokes a subcommand (root.go sets the flag
// default from the env var). This function only fills in step 3
// when authToken is empty. Server matching is best-effort: if no
// match exists we leave authToken empty and let downstream commands
// fail with their usual "401" error.
func resolveAuthToken(server string) string {
	if authToken != "" {
		return authToken
	}
	path, err := credentials.DefaultPath()
	if err != nil {
		return ""
	}
	cf, err := credentials.Load(path)
	if err != nil {
		return ""
	}
	creds, ok := cf.Get(server)
	if !ok {
		return ""
	}
	return creds.Token
}
