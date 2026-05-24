package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"runtime"
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
)

// pollIntervalOverride lets tests dial the polling interval down to
// milliseconds so the device-flow happy-path runs fast. Defaults to
// the production constant.
var pollIntervalOverride = loginPollInterval

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
	loginCmd.Flags().StringVar(&loginDeviceName, "device-name", "", "human label for this session (default: <user>-<host>)")
	loginCmd.Flags().BoolVar(&loginNoBrowser, "no-browser", false, "don't try to open a browser; print the URL instead")

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

type createSessionResp struct {
	SessionID       string `json:"session_id"`
	UserCode        string `json:"user_code"`
	VerificationURL string `json:"verification_url"`
	ExpiresIn       int    `json:"expires_in"`
}

type sessionStatusResp struct {
	Status    string `json:"status"` // pending | approved | denied | expired
	Token     string `json:"token,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
	OrgID     string `json:"org_id,omitempty"`
	// ExpiresAt is RFC3339; absent or empty means non-expiring.
	ExpiresAt string `json:"expires_at,omitempty"`
}

// loginHTTPClient is the unauthenticated HTTP client used by the
// device-flow handshake. Kept private so nothing else accidentally
// uses it.
func loginHTTPClient() *http.Client {
	return &http.Client{Timeout: loginHTTPTimeout}
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

// deviceName returns a stable, human-readable label for the
// session. PRD example: "alice-laptop (alice)". We default to
// "<user>@<host>" which is close enough — exact format matters
// only for the cloud's "Active sessions" UI.
func deviceName(override string) string {
	if override != "" {
		return override
	}
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
	ctx, cancel := context.WithTimeout(context.Background(), loginMaxWait+loginHTTPTimeout)
	defer cancel()

	// 1. Open a session.
	sess, err := createSession(ctx, hc, srv, deviceName(loginDeviceName))
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
	status, err := pollSession(ctx, hc, srv, sess.SessionID, pollIntervalOverride, loginMaxWait)
	if err != nil {
		return err
	}

	// 3. Persist credentials.
	creds := credentials.ServerCreds{
		Token:     status.Token,
		UserEmail: status.UserEmail,
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

	who := status.UserEmail
	if who == "" {
		who = "unknown user"
	}
	fmt.Fprintf(out, "✓ Logged in as %s\n", who)
	fmt.Fprintf(out, "  Token saved to %s\n", path)
	return nil
}

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
// returns the final non-pending status (or an error if the deadline
// elapses or the server reports denied/expired).
func pollSession(ctx context.Context, hc *http.Client, server, sessionID string, interval, maxWait time.Duration) (*sessionStatusResp, error) {
	deadline := time.Now().Add(maxWait)
	url := fmt.Sprintf("%s/v1/cli/sessions/%s/status", server, sessionID)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		st, err := fetchSessionStatus(ctx, hc, url)
		if err != nil {
			return nil, fmt.Errorf("poll session status: %w", err)
		}
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
			return nil, fmt.Errorf("timed out waiting for approval (after %s)", maxWait)
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
		return nil, fmt.Errorf("session not found (id may have expired)")
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	var out sessionStatusResp
	if err := json.Unmarshal(rb, &out); err != nil {
		return nil, fmt.Errorf("decode status response: %w", err)
	}
	return &out, nil
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
