package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/user"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/footprintai/containarium/internal/credentials"
	"github.com/footprintai/containarium/internal/sshkey"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Sub-tasks A5 + A6 of umbrella-issue #100: per-machine SSH key
// registration with the cloud's UserService.
//
// See prd/cloud/cli-login-and-multi-env-ssh.md §"Design —
// Multi-environment SSH" for the contract:
//
//   containarium ssh setup [--name=<friendly>] [--key=<path>]
//       reads/generates local key, POSTs UserService.AddSSHKey
//   containarium ssh list
//       GETs UserService.ListSSHKeys, prints a table
//   containarium ssh remove <name>
//       DELETEs UserService.RemoveSSHKey by name
//   containarium ssh propagate
//       POSTs UserService.PropagateSSHKeysToBoxes (cloud-side RPC
//       not yet implemented; the CLI handles Unimplemented
//       gracefully, matching the pattern from PR #297 / `containarium
//       ttl`).
//
// Strong typing per CLAUDE.md: the on-wire shape is sshkey.SSHKey,
// not map[string]any. The HTTP shim around UserService is small enough
// that we inline it here rather than refactor internal/client/http.go
// — those wrappers expect already-authenticated gRPC plumbing pointed
// at the daemon, whereas the SSH-keys endpoints live on the cloud
// (the same surface login.go talks to).

// Per-command flags.
var (
	sshSetupName       string
	sshSetupKeyPath    string
	sshSetupGenerate   bool
	sshSetupForce      bool
	sshSetupServer     string
	sshListServer      string
	sshRemoveServer    string
	sshPropagateServer string
	sshPropagateBoxes  []string
)

var sshCmd = &cobra.Command{
	Use:   "ssh",
	Short: "Manage per-machine SSH keys registered with your account",
	Long: `Register, list, and remove the SSH public key(s) the cloud knows about
for your user. Once a key is registered with ` + "`containarium ssh setup`" + `,
it gets installed in the authorized_keys file of every box you create
(or, with ` + "`containarium ssh propagate`" + `, every box you already own).

The key registration lives on the cloud's UserService, NOT on a single
daemon — so it follows you across self-hosted instances. This is the
"one laptop, many boxes" half of the multi-environment SSH design.

Typical first-run, post-login flow:

  containarium login                  # populates ~/.containarium/credentials.json
  containarium ssh setup              # uploads ~/.ssh/id_ed25519.pub (or generates one)
  containarium create alice ...       # the key is auto-installed in alice's authorized_keys
  ssh alice                           # works

To register the same machine's key without re-running setup on every
fresh box, run ` + "`containarium ssh propagate`" + ` once.`,
}

var sshSetupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Register this machine's SSH public key with the cloud",
	Long: `Locate (or generate) the local SSH keypair, then upload the public
half to the cloud via UserService.AddSSHKey. The private key stays
on your laptop.

Behavior:

  - With no flags, looks for ~/.ssh/id_ed25519.pub (then id_rsa.pub).
    If neither exists, generates a fresh ed25519 key at
    ~/.ssh/containarium_ed25519{,.pub} and uploads the public half.

  - --key=<path> uses an explicit public-key file (overrides the
    search).

  - --name=<label> sets the friendly name shown by ` + "`containarium ssh list`" + `.
    Defaults to "<user>@<host>".

  - --generate forces generation of a new keypair even if one
    already exists in ~/.ssh.

  - --force allows --generate to overwrite an existing
    containarium-prefixed key.

Requires ` + "`containarium login`" + ` first (the upload is
authenticated with the credentials-file token).`,
	Example: `  # Default: find ~/.ssh/id_ed25519.pub and register as alice@laptop
  containarium ssh setup

  # Custom label
  containarium ssh setup --name=alice-mbp

  # Explicit key file
  containarium ssh setup --key=~/.ssh/work_ed25519.pub

  # Generate a fresh containarium-only key
  containarium ssh setup --generate`,
	RunE: runSSHSetup,
}

var sshListCmd = &cobra.Command{
	Use:   "list",
	Short: "List SSH keys registered with your account",
	Long: `Print the keys the cloud knows about for your user, one per row,
showing the friendly name, the SHA256 fingerprint, and when each
key was registered.

Pipes-friendly: passes through stdout as a tab-aligned table; the
key column is the fingerprint, not the full public-key blob.`,
	RunE: runSSHList,
}

var sshRemoveCmd = &cobra.Command{
	Use:   "remove <name>",
	Short: "Remove a registered SSH key by friendly name",
	Long: `Delete the SSH key with the given name from the cloud's record.
Future boxes you create will not include this key in their
authorized_keys (existing boxes are NOT touched — use
` + "`containarium ssh propagate`" + ` to push the updated key set).

The <name> argument is matched against the friendly label you set
with ` + "`containarium ssh setup --name=`" + `. List the available
names with ` + "`containarium ssh list`" + `.`,
	Args: cobra.ExactArgs(1),
	RunE: runSSHRemove,
}

var sshPropagateCmd = &cobra.Command{
	Use:   "propagate",
	Short: "Push your registered SSH keys to every existing box you own",
	Long: `Walk every container you own and update its authorized_keys to
match the keys currently registered with ` + "`containarium ssh list`" + `.

Useful after:

  - Adding a new laptop with ` + "`containarium ssh setup`" + ` —
    propagate so the new key gets installed retroactively.

  - Removing a lost laptop's key with ` + "`containarium ssh remove`" + ` —
    propagate so the removal takes effect on existing boxes.

This invokes UserService.PropagateSSHKeysToBoxes on the cloud, which
fans out to every daemon hosting one of your boxes. The cloud-side
RPC is not yet implemented (see the "what's NOT in this PR" section
of the PR description); the CLI handles the resulting Unimplemented
gracefully (prints a clear warning, exits 0) so callers can wire
this into their workflow today.`,
	Example: `  # Push to every owned box
  containarium ssh propagate

  # Limit to a specific subset of boxes
  containarium ssh propagate --box=alice --box=bob`,
	RunE: runSSHPropagate,
}

func init() {
	sshSetupCmd.Flags().StringVar(&sshSetupName, "name", "", "friendly label for this key (default: <user>@<host>)")
	sshSetupCmd.Flags().StringVar(&sshSetupKeyPath, "key", "", "path to public key file (default: auto-detect ~/.ssh/id_ed25519.pub or generate)")
	sshSetupCmd.Flags().BoolVar(&sshSetupGenerate, "generate", false, "always generate a fresh ed25519 keypair (default: re-use ~/.ssh/id_ed25519.pub if present)")
	sshSetupCmd.Flags().BoolVar(&sshSetupForce, "force", false, "with --generate, allow overwriting an existing containarium_ed25519 key")
	sshSetupCmd.Flags().StringVar(&sshSetupServer, "server", "", "server URL for the upload (default: default_server from credentials file, then "+defaultLoginServer+")")

	sshListCmd.Flags().StringVar(&sshListServer, "server", "", "server URL to query (default: default_server)")
	sshRemoveCmd.Flags().StringVar(&sshRemoveServer, "server", "", "server URL to target (default: default_server)")
	sshPropagateCmd.Flags().StringVar(&sshPropagateServer, "server", "", "server URL to target (default: default_server)")
	sshPropagateCmd.Flags().StringSliceVar(&sshPropagateBoxes, "box", nil, "restrict propagation to these box names (repeatable); default: all owned boxes")

	sshCmd.AddCommand(sshSetupCmd)
	sshCmd.AddCommand(sshListCmd)
	sshCmd.AddCommand(sshRemoveCmd)
	sshCmd.AddCommand(sshPropagateCmd)
	rootCmd.AddCommand(sshCmd)
}

// pickSSHServer collapses the precedence chain for the SSH-key
// endpoints. Mirrors pickLoginServer's intent but adds a
// credentials-file fallback because we usually want the same server
// the user is logged into:
//
//  1. explicit --server flag
//  2. credentials-file default_server
//  3. defaultLoginServer constant
func pickSSHServer(explicit string) string {
	if explicit != "" {
		return strings.TrimRight(explicit, "/")
	}
	if path, err := credentials.DefaultPath(); err == nil {
		if cf, err := credentials.Load(path); err == nil && cf.DefaultServer != "" {
			return strings.TrimRight(cf.DefaultServer, "/")
		}
	}
	return defaultLoginServer
}

// sshHTTPClient is a small wrapper that talks to the cloud's
// UserService REST endpoints with the bearer token from the
// credentials store. Kept package-local rather than reaching into
// internal/client/http.go because that wrapper is daemon-shaped
// (gRPC-gateway over an mTLS-fronted daemon) — wrong surface for the
// cloud's user-keys endpoints.
type sshHTTPClient struct {
	hc     *http.Client
	server string
	token  string
}

func newSSHHTTPClient(server string) (*sshHTTPClient, error) {
	tok := resolveAuthToken(server)
	if tok == "" {
		return nil, fmt.Errorf("no auth token for %s (run `containarium login`)", server)
	}
	return &sshHTTPClient{
		hc:     &http.Client{Timeout: 30 * time.Second},
		server: server,
		token:  tok,
	}, nil
}

// doJSON sends method+path with optional body, decodes the response
// into out (if non-nil), and converts 501 Not Implemented into a gRPC
// Unimplemented status so the call-site can lean on isUnimplemented()
// (defined in ttl.go).
func (c *sshHTTPClient) doJSON(ctx context.Context, method, path string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.server+path, rdr)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusNotImplemented {
		return status.Errorf(codes.Unimplemented, "%s %s: server returned 501 Not Implemented", method, path)
	}
	if resp.StatusCode == http.StatusNotFound {
		// grpc-gateway emits 404 for routes the cloud hasn't wired
		// yet. Treat that as Unimplemented too so the propagate path
		// can fall through gracefully — matching ttl.go's posture.
		return status.Errorf(codes.Unimplemented, "%s %s: route not found (server may not support this RPC yet)", method, path)
	}
	if resp.StatusCode == http.StatusConflict {
		// 409 = the resource already exists (e.g. this SSH key is already
		// registered). Surface it as a typed AlreadyExists so callers can
		// treat re-registration as idempotent success rather than a failure.
		return status.Errorf(codes.AlreadyExists, "%s %s: %s", method, path, strings.TrimSpace(string(rb)))
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("%s %s: status %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(rb)))
	}

	if out != nil && len(rb) > 0 {
		if err := json.Unmarshal(rb, out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

// Wire-format DTOs for the UserService SSH-key endpoints. Each
// mirrors the .proto on the cloud side; we redeclare here so the OSS
// CLI compiles without depending on a cloud-private pb package.
//
// Per CLAUDE.md: typed structs, not map[string]any.

type addSSHKeyReq struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
}

type addSSHKeyResp struct {
	Key sshkey.SSHKey `json:"key"`
}

type listSSHKeysResp struct {
	Keys []sshkey.SSHKey `json:"keys"`
}

type propagateReq struct {
	Boxes []string `json:"boxes,omitempty"` // empty = all owned
}

type propagateResp struct {
	UpdatedBoxes []string `json:"updated_boxes"`
	SkippedBoxes []string `json:"skipped_boxes"`
}

// AddSSHKey uploads pubkey under the given name. Returns the
// canonicalised SSHKey (with fingerprint + created_at) the server
// stored.
func (c *sshHTTPClient) AddSSHKey(ctx context.Context, name, pub string) (*sshkey.SSHKey, error) {
	var out addSSHKeyResp
	if err := c.doJSON(ctx, http.MethodPost, "/v1/user/ssh-keys", addSSHKeyReq{Name: name, PublicKey: pub}, &out); err != nil {
		return nil, err
	}
	return &out.Key, nil
}

func (c *sshHTTPClient) ListSSHKeys(ctx context.Context) ([]sshkey.SSHKey, error) {
	var out listSSHKeysResp
	if err := c.doJSON(ctx, http.MethodGet, "/v1/user/ssh-keys", nil, &out); err != nil {
		return nil, err
	}
	return out.Keys, nil
}

func (c *sshHTTPClient) RemoveSSHKey(ctx context.Context, name string) error {
	// Name is path-segment safe (we validate at runSSHRemove) so we
	// can inline it without url-escaping. Switch to url.PathEscape if
	// we ever loosen the validator.
	return c.doJSON(ctx, http.MethodDelete, "/v1/user/ssh-keys/"+name, nil, nil)
}

func (c *sshHTTPClient) PropagateSSHKeys(ctx context.Context, boxes []string) (*propagateResp, error) {
	var out propagateResp
	if err := c.doJSON(ctx, http.MethodPost, "/v1/user/ssh-keys:propagate", propagateReq{Boxes: boxes}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---- command handlers --------------------------------------------------

func runSSHSetup(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	srv := pickSSHServer(sshSetupServer)
	// FYI for token-access servers (cloud): registering an SSH key works, but
	// it isn't needed — `containarium connect` uses the API token. We still
	// proceed; the user ran `ssh setup` deliberately.
	if accessModelFor(srv) == credentials.AccessModelToken {
		fmt.Fprintf(out, "Note: %s uses token-based access — `containarium connect <box>` opens a shell with no SSH key.\n", srv)
	}
	name := sshSetupName
	if name == "" {
		name = defaultLocalKeyName()
	}
	if err := validateKeyName(name); err != nil {
		return err
	}

	pub, source, generated, err := obtainLocalPublicKey()
	if err != nil {
		return err
	}
	fp, err := sshkey.Fingerprint(pub)
	if err != nil {
		return fmt.Errorf("fingerprint key: %w", err)
	}

	if generated {
		fmt.Fprintf(out, "Generated new ed25519 keypair at %s\n", source)
	} else {
		fmt.Fprintf(out, "Using existing key at %s\n", source)
	}
	fmt.Fprintf(out, "  Fingerprint: %s\n", fp)
	fmt.Fprintf(out, "  Registering as %q with %s\n", name, srv)

	client, err := newSSHHTTPClient(srv)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	stored, err := client.AddSSHKey(ctx, name, pub)
	if isUnimplemented(err) {
		fmt.Fprintf(out, "\n⚠ SSH-key registration not yet supported by %s (UserService.AddSSHKey returned Unimplemented).\n", srv)
		fmt.Fprintf(out, "  Your key is on disk at %s — once the cloud-side endpoint ships, re-run `containarium ssh setup`.\n", source)
		return nil
	}
	if isAlreadyExists(err) {
		// Re-registering the same key is a no-op, not a failure. This is the
		// common case on a repeat `containarium login` from the same machine —
		// report success so the post-login banner doesn't look like an error.
		fmt.Fprintf(out, "✓ SSH key %q already registered with %s — nothing to do\n", name, srv)
		return nil
	}
	if err != nil {
		return fmt.Errorf("register key: %w", err)
	}

	fmt.Fprintf(out, "✓ Registered key %q (fingerprint %s)\n", stored.Name, stored.Fingerprint)
	return nil
}

func runSSHList(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	srv := pickSSHServer(sshListServer)
	client, err := newSSHHTTPClient(srv)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	keys, err := client.ListSSHKeys(ctx)
	if isUnimplemented(err) {
		fmt.Fprintf(out, "⚠ Listing SSH keys not yet supported by %s (UserService.ListSSHKeys returned Unimplemented).\n", srv)
		return nil
	}
	if err != nil {
		return fmt.Errorf("list keys: %w", err)
	}
	if len(keys) == 0 {
		fmt.Fprintln(out, "No SSH keys registered. Run `containarium ssh setup` to add one.")
		return nil
	}
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tFINGERPRINT\tCREATED")
	for _, k := range keys {
		created := "-"
		if !k.CreatedAt.IsZero() {
			created = k.CreatedAt.UTC().Format(time.RFC3339)
		}
		fp := k.Fingerprint
		if fp == "" && k.PublicKey != "" {
			// Compute it locally if the server didn't include it
			// — common against early/partial implementations.
			if f, err := sshkey.Fingerprint(k.PublicKey); err == nil {
				fp = f
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", k.Name, fp, created)
	}
	return tw.Flush()
}

func runSSHRemove(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	name := args[0]
	if err := validateKeyName(name); err != nil {
		return err
	}
	srv := pickSSHServer(sshRemoveServer)
	client, err := newSSHHTTPClient(srv)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = client.RemoveSSHKey(ctx, name)
	if isUnimplemented(err) {
		fmt.Fprintf(out, "⚠ SSH-key removal not yet supported by %s (UserService.RemoveSSHKey returned Unimplemented).\n", srv)
		return nil
	}
	if err != nil {
		return fmt.Errorf("remove key %q: %w", name, err)
	}
	fmt.Fprintf(out, "✓ Removed SSH key %q from %s\n", name, srv)
	fmt.Fprintln(out, "  (Existing boxes still have this key in authorized_keys — run `containarium ssh propagate` to push the removal.)")
	return nil
}

func runSSHPropagate(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	srv := pickSSHServer(sshPropagateServer)
	for _, b := range sshPropagateBoxes {
		if err := validateBoxName(b); err != nil {
			return err
		}
	}
	client, err := newSSHHTTPClient(srv)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if len(sshPropagateBoxes) == 0 {
		fmt.Fprintf(out, "Propagating keys to every owned box on %s ...\n", srv)
	} else {
		fmt.Fprintf(out, "Propagating keys to %d box(es) on %s ...\n", len(sshPropagateBoxes), srv)
	}

	res, err := client.PropagateSSHKeys(ctx, sshPropagateBoxes)
	if isUnimplemented(err) {
		fmt.Fprintf(out, "⚠ Key propagation not yet supported by %s.\n", srv)
		fmt.Fprintln(out, "  UserService.PropagateSSHKeysToBoxes is a planned cloud-side RPC that")
		fmt.Fprintln(out, "  hasn't shipped yet. New boxes still get the latest keys at create time;")
		fmt.Fprintln(out, "  this command will Just Work once the cloud-side endpoint lands —")
		fmt.Fprintln(out, "  re-run it then. See the PR that introduced `containarium ssh propagate`")
		fmt.Fprintln(out, "  for the deferred follow-up.")
		return nil
	}
	if err != nil {
		return fmt.Errorf("propagate: %w", err)
	}
	fmt.Fprintf(out, "✓ Updated %d box(es)", len(res.UpdatedBoxes))
	if len(res.SkippedBoxes) > 0 {
		fmt.Fprintf(out, ", skipped %d", len(res.SkippedBoxes))
	}
	fmt.Fprintln(out)
	for _, b := range res.UpdatedBoxes {
		fmt.Fprintf(out, "  + %s\n", b)
	}
	for _, b := range res.SkippedBoxes {
		fmt.Fprintf(out, "  - %s (skipped)\n", b)
	}
	return nil
}

// ---- helpers -----------------------------------------------------------

// obtainLocalPublicKey runs the flag-precedence chain documented on
// `ssh setup`: explicit --key wins; --generate forces creation; else
// LocateOrGenerate. Returns (pubkeyContents, sourcePath, wasGenerated, err).
func obtainLocalPublicKey() (string, string, bool, error) {
	switch {
	case sshSetupKeyPath != "":
		pub, err := sshkey.ReadPublicKey(sshSetupKeyPath)
		if err != nil {
			return "", "", false, err
		}
		return pub, sshSetupKeyPath, false, nil

	case sshSetupGenerate:
		path, pub, err := sshkey.Generate(sshkey.LocateOpts{}, sshSetupForce)
		if err != nil {
			return "", "", false, fmt.Errorf("generate keypair: %w", err)
		}
		return pub, path, true, nil

	default:
		path, pub, generated, err := sshkey.LocateOrGenerate(sshkey.LocateOpts{})
		if err != nil {
			return "", "", false, fmt.Errorf("locate or generate keypair: %w", err)
		}
		return pub, path, generated, nil
	}
}

// defaultLocalKeyName mirrors login.go's deviceName fallback so the
// "Active sessions" UI and the "SSH keys" UI on the cloud read with
// matching labels.
func defaultLocalKeyName() string {
	var who, host string
	if u, err := user.Current(); err == nil {
		who = u.Username
	}
	host, _ = os.Hostname()
	return sshkey.DefaultKeyName(who, host)
}

// validateKeyName guards the friendly-name field against obviously
// hostile input. The cloud-side will re-validate, but rejecting at
// the CLI gives a clearer message — and validating before we put the
// name into a URL path (for `ssh remove`) means we don't need
// url.PathEscape.
//
// Rules (intentionally narrow):
//   - non-empty after trim
//   - 1..64 chars
//   - alphanumerics, dash, underscore, dot, @
//
// Loosen the regex when a real user files a feature request — until
// then this is the safe baseline.
func validateKeyName(name string) error {
	n := strings.TrimSpace(name)
	if n == "" {
		return fmt.Errorf("name is empty")
	}
	if len(n) > 64 {
		return fmt.Errorf("name %q exceeds 64 characters", n)
	}
	for _, r := range n {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '-', r == '_', r == '.', r == '@':
			continue
		default:
			return fmt.Errorf("name %q contains disallowed character %q (allowed: alphanumerics, '-', '_', '.', '@')", n, r)
		}
	}
	return nil
}

// validateBoxName is the same shape as validateKeyName but tighter
// (no '@' or '.') because box names go into Linux usernames upstream.
// Keep in sync with internal/server/create_bounds.go if it changes
// there.
func validateBoxName(name string) error {
	n := strings.TrimSpace(name)
	if n == "" {
		return fmt.Errorf("box name is empty")
	}
	if len(n) > 32 {
		return fmt.Errorf("box name %q exceeds 32 characters", n)
	}
	for _, r := range n {
		switch {
		case r >= 'a' && r <= 'z',
			r >= '0' && r <= '9',
			r == '-', r == '_':
			continue
		default:
			return fmt.Errorf("box name %q contains disallowed character %q (allowed: lowercase, digits, '-', '_')", n, r)
		}
	}
	return nil
}
