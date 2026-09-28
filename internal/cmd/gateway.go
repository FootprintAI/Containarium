package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/client"
	"github.com/footprintai/containarium/internal/gatewayprovider"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/durationpb"
)

// `containarium gateway` — the model gateway's admin + mint surface (#1726).
//
// CLI-first, per the repo's own rule: every verb here is a thin wrapper over the
// same ModelGatewayService RPC the MCP tool calls, so a human can drive the whole
// feature from a shell and the agent surface adds no capability of its own.
//
// Remote-only. The daemon holds the real provider keys and signs the tokens;
// there is nothing a local fallback could do.

var gatewayCmd = &cobra.Command{
	Use:   "gateway",
	Short: "Model-gateway provider keys and scoped box tokens",
	Long: `Manage the daemon's model gateway: which upstream key each key owner
pays with, and the short-lived scoped tokens a box presents instead of one.

A box never holds a real provider key. It holds a gateway token bound to the
box, the provider, the resolved key owner, optionally one run and one model
ceiling — revocable by its jti and expiring on its own.

Key owners are namespaced: user:<username> for a self-hosted box, org:<org_id>
for a cloud-attributed one.`,
}

var gatewayKeyCmd = &cobra.Command{
	Use:   "key",
	Short: "Register, inspect or remove a key owner's upstream provider key",
	Long: `A key owner's real upstream API key, held encrypted on the daemon and
never delivered to any box.

Write-only: there is no verb, here or on the API, that reads a registered key
back. "status" reports a fingerprint and when it was set.

Requires the gateway:admin scope.`,
}

var (
	gatewayProviderFlag string
	gatewayKeyValue     string
	gatewayKeyFile      string
	gatewayMintRunID    string
	gatewayMintTTL      string
	gatewayMintModels   []string
	gatewayMintDryRun   bool
	gatewayMintEnv      bool
	gatewayModelsBox    string
)

var gatewayKeySetCmd = &cobra.Command{
	Use:   "set <key-owner>",
	Short: "Store or rotate a key owner's upstream provider key",
	Long: `Idempotent set-or-rotate for one (key owner, provider) pair.

Prefer --key-file over --key: a key passed as an argument lands in your shell
history and in the process table.

Examples:
  containarium gateway key set user:alice --provider kafeido --key-file ./key.txt
  containarium gateway key set org:0b1c… --provider kafeido --key sk-…`,
	Args: cobra.ExactArgs(1),
	RunE: runGatewayKeySet,
}

var gatewayKeyDeleteCmd = &cobra.Command{
	Use:     "delete <key-owner>",
	Aliases: []string{"rm", "remove"},
	Short:   "Remove a key owner's provider key and revoke its live tokens",
	Long: `Removes the stored key AND revokes every gateway token already issued
for that owner, so the key stops being spendable on the next call rather than
when the last token expires.

If the daemon holds no revocable owner-revocation store, the command says so:
the key is gone but already-issued tokens live until they expire.`,
	Args: cobra.ExactArgs(1),
	RunE: runGatewayKeyDelete,
}

var gatewayKeyStatusCmd = &cobra.Command{
	Use:   "status <key-owner>",
	Short: "Report whether a key owner has a provider key, and its fingerprint",
	Long: `Reports set/unset, the key's fingerprint (the first 16 hex characters
of its SHA-256) and when it was last set. Never the key.`,
	Args: cobra.ExactArgs(1),
	RunE: runGatewayKeyStatus,
}

var gatewayMintCmd = &cobra.Command{
	Use:   "mint <box>",
	Short: "Mint a scoped gateway token for a box you own",
	Long: `Issues a short-lived, revocable token the box presents to the model
gateway instead of a real provider key.

The key owner is resolved by the daemon: the box's cloud-org attribution when it
is stamped, else the box's owning username. The token's TTL is capped
server-side; --ttl may lower it, never raise it past the cap.

--dry-run validates everything a real mint validates (you own the box, the
daemon serves the provider, the resolved owner has a key) and issues nothing —
which is how an install step names a misconfiguration before the first model
call instead of after it.

--env prints the two exports a box needs, ready to be written to a 0600
gateway.env inside it.

Examples:
  containarium gateway mint alice --provider kafeido --ttl 2h --run-id run-42
  containarium gateway mint alice --provider kafeido --dry-run
  containarium gateway mint alice --provider kafeido --env > gateway.env`,
	Args: cobra.ExactArgs(1),
	RunE: runGatewayMint,
}

var gatewayModelsCmd = &cobra.Command{
	Use:   "models",
	Short: "List a provider's models through the gateway",
	Long: `Lists the models the resolved key owner's key can actually reach,
read upstream through the gateway. You never need a provider key of your own.

With --box, the lookup uses that box's key owner (and the same ownership check
minting uses); without it, your own.`,
	Args: cobra.NoArgs,
	RunE: runGatewayModels,
}

func init() {
	rootCmd.AddCommand(gatewayCmd)

	gatewayCmd.AddCommand(gatewayKeyCmd)
	gatewayKeyCmd.AddCommand(gatewayKeySetCmd)
	gatewayKeySetCmd.Flags().StringVar(&gatewayProviderFlag, "provider", "",
		"Upstream provider (one of: "+strings.Join(gatewayprovider.Names(), ", ")+")")
	gatewayKeySetCmd.Flags().StringVar(&gatewayKeyValue, "key", "", "The upstream API key (prefer --key-file)")
	gatewayKeySetCmd.Flags().StringVar(&gatewayKeyFile, "key-file", "", "Read the upstream API key from this file ('-' for stdin)")

	gatewayKeyCmd.AddCommand(gatewayKeyDeleteCmd)
	gatewayKeyDeleteCmd.Flags().StringVar(&gatewayProviderFlag, "provider", "",
		"Upstream provider (one of: "+strings.Join(gatewayprovider.Names(), ", ")+")")

	gatewayKeyCmd.AddCommand(gatewayKeyStatusCmd)
	gatewayKeyStatusCmd.Flags().StringVar(&gatewayProviderFlag, "provider", "",
		"Upstream provider (one of: "+strings.Join(gatewayprovider.Names(), ", ")+")")

	gatewayCmd.AddCommand(gatewayMintCmd)
	gatewayMintCmd.Flags().StringVar(&gatewayProviderFlag, "provider", "",
		"Upstream provider (one of: "+strings.Join(gatewayprovider.Names(), ", ")+")")
	gatewayMintCmd.Flags().StringVar(&gatewayMintRunID, "run-id", "", "Bind the token to one run, so the run's exit can revoke it")
	gatewayMintCmd.Flags().StringVar(&gatewayMintTTL, "ttl", "", "Requested lifetime (e.g. 2h). Capped server-side; the default is the cap")
	gatewayMintCmd.Flags().StringSliceVar(&gatewayMintModels, "allow-model", nil, "Restrict the token to these models (repeatable)")
	gatewayMintCmd.Flags().BoolVar(&gatewayMintDryRun, "dry-run", false, "Validate without issuing a token")
	gatewayMintCmd.Flags().BoolVar(&gatewayMintEnv, "env", false, "Print shell exports for the box's gateway.env instead of a summary")

	gatewayCmd.AddCommand(gatewayModelsCmd)
	gatewayModelsCmd.Flags().StringVar(&gatewayProviderFlag, "provider", "",
		"Upstream provider (one of: "+strings.Join(gatewayprovider.Names(), ", ")+")")
	gatewayModelsCmd.Flags().StringVar(&gatewayModelsBox, "box", "", "Use this box's key owner instead of your own")
}

// newGatewayClient dials the daemon over whichever transport the global flags
// selected. Remote-only: the daemon holds the keys and the signing secret.
func newGatewayClient() (client.ModelGatewayAPI, error) {
	if serverAddr == "" {
		return nil, fmt.Errorf("--server is required for gateway commands (the daemon holds the provider keys and signs the tokens)")
	}
	if httpMode {
		h, err := client.NewHTTPClient(serverAddr, authToken)
		if err != nil {
			return nil, err
		}
		return h, nil
	}
	g, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return nil, err
	}
	return g, nil
}

// ---------- pure request builders (table-tested; see gateway_test.go) ----------

// buildSetTenantProviderKeyRequest validates the flags for `gateway key set`.
// Pure: reading --key-file is the caller's job, so the validation is testable
// without a filesystem.
func buildSetTenantProviderKeyRequest(keyOwner, provider, key string) (*pb.SetTenantProviderKeyRequest, error) {
	p, err := gatewayprovider.FromName(provider)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(keyOwner) == "" {
		return nil, fmt.Errorf("key owner is required (user:<username> or org:<org_id>)")
	}
	if key == "" {
		return nil, fmt.Errorf("a key is required: pass --key-file (preferred) or --key")
	}
	return &pb.SetTenantProviderKeyRequest{KeyOwner: keyOwner, Provider: p, ApiKey: key}, nil
}

// buildMintGatewayTokenRequest validates the flags for `gateway mint`.
func buildMintGatewayTokenRequest(box, provider, runID, ttl string, models []string, dryRun bool) (*pb.MintGatewayTokenRequest, error) {
	p, err := gatewayprovider.FromName(provider)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(box) == "" {
		return nil, fmt.Errorf("box is required")
	}
	req := &pb.MintGatewayTokenRequest{
		Box:           box,
		Provider:      p,
		RunId:         runID,
		AllowedModels: models,
		DryRun:        dryRun,
	}
	if raw := strings.TrimSpace(ttl); raw != "" {
		d, perr := time.ParseDuration(raw)
		if perr != nil {
			return nil, fmt.Errorf("--ttl %q is not a duration (e.g. 30m, 2h): %w", ttl, perr)
		}
		if d <= 0 {
			return nil, fmt.Errorf("--ttl must be positive, got %s", ttl)
		}
		req.Ttl = durationpb.New(d)
	}
	return req, nil
}

// buildListGatewayModelsRequest validates the flags for `gateway models`.
func buildListGatewayModelsRequest(provider, box string) (*pb.ListGatewayModelsRequest, error) {
	p, err := gatewayprovider.FromName(provider)
	if err != nil {
		return nil, err
	}
	return &pb.ListGatewayModelsRequest{Provider: p, Box: box}, nil
}

// readGatewayKeyMaterial resolves --key / --key-file into the key itself.
// Exactly one source, so an operator cannot half-rotate a key by passing both
// and wondering which won.
func readGatewayKeyMaterial(key, keyFile string) (string, error) {
	switch {
	case key != "" && keyFile != "":
		return "", fmt.Errorf("pass either --key or --key-file, not both")
	case keyFile == "-":
		b, err := readAllStdin()
		if err != nil {
			return "", fmt.Errorf("reading the key from stdin: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	case keyFile != "":
		b, err := os.ReadFile(keyFile) // #nosec G304 -- operator-supplied --key-file path; reading it is the documented CLI behavior
		if err != nil {
			return "", fmt.Errorf("reading --key-file: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	default:
		return key, nil
	}
}

// readAllStdin is split out so tests can exercise readGatewayKeyMaterial's other
// branches without touching os.Stdin.
func readAllStdin() ([]byte, error) {
	return io.ReadAll(os.Stdin)
}

// ---------- handlers ----------

func runGatewayKeySet(_ *cobra.Command, args []string) error {
	key, err := readGatewayKeyMaterial(gatewayKeyValue, gatewayKeyFile)
	if err != nil {
		return err
	}
	req, err := buildSetTenantProviderKeyRequest(args[0], gatewayProviderFlag, key)
	if err != nil {
		return err
	}
	c, err := newGatewayClient()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	resp, err := c.SetTenantProviderKey(req)
	if err != nil {
		return err
	}
	name, _ := gatewayprovider.Name(resp.GetProvider())
	fmt.Printf("✓ %s key stored for %s (fingerprint=%s", name, resp.GetKeyOwner(), resp.GetFingerprint())
	if t := resp.GetSetAt(); t != nil {
		fmt.Printf(" set_at=%s", t.AsTime().UTC().Format(time.RFC3339))
	}
	fmt.Println(")")
	return nil
}

func runGatewayKeyDelete(_ *cobra.Command, args []string) error {
	p, err := gatewayprovider.FromName(gatewayProviderFlag)
	if err != nil {
		return err
	}
	c, err := newGatewayClient()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	resp, err := c.DeleteTenantProviderKey(&pb.DeleteTenantProviderKeyRequest{KeyOwner: args[0], Provider: p})
	if err != nil {
		return err
	}
	name, _ := gatewayprovider.Name(p)
	fmt.Printf("✓ %s key removed for %s\n", name, args[0])
	if resp.GetTokensRevoked() {
		fmt.Println("  live gateway tokens for this owner were revoked")
	} else {
		fmt.Println("  WARNING: this daemon has no revocable owner-revocation store — tokens already issued for this owner stay valid until they expire")
	}
	return nil
}

func runGatewayKeyStatus(_ *cobra.Command, args []string) error {
	p, err := gatewayprovider.FromName(gatewayProviderFlag)
	if err != nil {
		return err
	}
	c, err := newGatewayClient()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	resp, err := c.GetTenantProviderKeyStatus(&pb.GetTenantProviderKeyStatusRequest{KeyOwner: args[0], Provider: p})
	if err != nil {
		return err
	}
	name, _ := gatewayprovider.Name(p)
	if !resp.GetSet() {
		fmt.Printf("%s / %s: no key registered\n", resp.GetKeyOwner(), name)
		return nil
	}
	fmt.Printf("%s / %s: set fingerprint=%s", resp.GetKeyOwner(), name, resp.GetFingerprint())
	if t := resp.GetSetAt(); t != nil {
		fmt.Printf(" set_at=%s", t.AsTime().UTC().Format(time.RFC3339))
	}
	fmt.Println()
	return nil
}

func runGatewayMint(_ *cobra.Command, args []string) error {
	req, err := buildMintGatewayTokenRequest(args[0], gatewayProviderFlag, gatewayMintRunID, gatewayMintTTL, gatewayMintModels, gatewayMintDryRun)
	if err != nil {
		return err
	}
	c, err := newGatewayClient()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	resp, err := c.MintGatewayToken(req)
	if err != nil {
		return err
	}
	fmt.Print(formatMintGatewayTokenResult(resp, req.GetDryRun(), gatewayMintEnv))
	return nil
}

// formatMintGatewayTokenResult renders a mint result. Split out and pure so the
// "a dry run must never print a token" rule is a unit test, not a hope.
func formatMintGatewayTokenResult(resp *pb.MintGatewayTokenResponse, dryRun, asEnv bool) string {
	var b strings.Builder
	if dryRun {
		// Nothing was issued, so there is nothing to export — printing an env
		// block here would produce a gateway.env with an empty token.
		fmt.Fprintf(&b, "✓ a mint would succeed: key_owner=%s base_url=%s (dry run — no token issued)\n",
			resp.GetKeyOwner(), resp.GetBaseUrl())
		return b.String()
	}
	if asEnv {
		// The two variables the box's engines read (see the recipe/skill gateway
		// env contract). Write this to ~/.pi/gateway.env with mode 0600.
		fmt.Fprintf(&b, "export CONTAINARIUM_MODEL_GATEWAY_URL=%s\n", resp.GetBaseUrl())
		fmt.Fprintf(&b, "export CONTAINARIUM_GATEWAY_TOKEN=%s\n", resp.GetToken())
		return b.String()
	}
	fmt.Fprintf(&b, "token:      %s\n", resp.GetToken())
	fmt.Fprintf(&b, "base_url:   %s\n", resp.GetBaseUrl())
	fmt.Fprintf(&b, "key_owner:  %s\n", resp.GetKeyOwner())
	fmt.Fprintf(&b, "token_id:   %s  (revoke with: containarium token revoke --jti %s)\n", resp.GetTokenId(), resp.GetTokenId())
	if t := resp.GetExpiresAt(); t != nil {
		fmt.Fprintf(&b, "expires_at: %s\n", t.AsTime().UTC().Format(time.RFC3339))
	}
	return b.String()
}

func runGatewayModels(_ *cobra.Command, _ []string) error {
	req, err := buildListGatewayModelsRequest(gatewayProviderFlag, gatewayModelsBox)
	if err != nil {
		return err
	}
	c, err := newGatewayClient()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	resp, err := c.ListGatewayModels(req)
	if err != nil {
		return err
	}
	if len(resp.GetModels()) == 0 {
		fmt.Printf("no models reported for %s\n", resp.GetKeyOwner())
		return nil
	}
	fmt.Printf("models for %s:\n", resp.GetKeyOwner())
	for _, m := range resp.GetModels() {
		fmt.Printf("  %s\n", m.GetId())
	}
	return nil
}
