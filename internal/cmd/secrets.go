package cmd

import (
	"fmt"
	"strings"

	"github.com/footprintai/containarium/internal/client"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

// Tenant secrets — daemon-managed, AES-256-GCM in Postgres,
// stamped as environment.<NAME>=<value> on the LXC at container
// start. See docs/SECRETS-MANAGEMENT-DESIGN.md.
//
// Remote-only — there's no local fallback because the daemon owns
// the master key and the Postgres connection. Same pattern as
// `containarium monitoring`.

var secretsCmd = &cobra.Command{
	Use:   "secrets",
	Short: "Manage tenant secrets stored encrypted on the daemon",
	Long: `Manage tenant secrets (API keys, DB passwords, etc.) stored
encrypted at rest on the Containarium daemon. Values are stamped as
environment.<NAME>=<value> on the LXC at container start, so apps
inside docker read them via compose ${VAR} interpolation.

See docs/SECRETS-MANAGEMENT-DESIGN.md.`,
}

var secretsSetCmd = &cobra.Command{
	Use:   "set <username> <NAME> <value>",
	Short: "Create or update a tenant secret",
	Long: `Idempotent set-or-rotate. The first call creates the secret; later
calls with the same (username, NAME) bump the version and replace the
value. Names must match ^[A-Z_][A-Z0-9_]*$ (env-var convention);
values are capped at 64 KiB.

Containers stamp the new env on next CreateContainer / StartContainer.
For rotation against a running container, call:
  containarium secrets refresh <username>

Examples:
  containarium secrets set alice OPENAI_API_KEY sk-abc...
  containarium secrets set alice DATABASE_URL "postgres://..."`,
	Args: cobra.ExactArgs(3),
	RunE: runSecretsSet,
}

var secretsGetCmd = &cobra.Command{
	Use:   "get <username> <NAME>",
	Short: "Read a tenant secret's plaintext value",
	Long: `Returns the decrypted plaintext to stdout. Always audit-logged
on the daemon. Be mindful where you redirect the output.`,
	Args: cobra.ExactArgs(2),
	RunE: runSecretsGet,
}

var secretsListCmd = &cobra.Command{
	Use:   "list <username>",
	Short: "List a tenant's secrets (metadata only)",
	Long:  `Returns name/version/timestamps tuples. Values are only readable per-name via 'secrets get'.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runSecretsList,
}

var secretsDeleteCmd = &cobra.Command{
	Use:     "delete <username> <NAME>",
	Aliases: []string{"rm", "remove"},
	Short:   "Delete a tenant secret",
	Long: `Removes the secret from Postgres. Does NOT cascade to env-var
stamps on running containers — call 'secrets refresh' separately if
the change should reach the next exec without a container restart.`,
	Args: cobra.ExactArgs(2),
	RunE: runSecretsDelete,
}

var secretsRefreshCmd = &cobra.Command{
	Use:   "refresh <username>",
	Short: "Deliver the current secrets store to the tenant's box",
	Long: `Reads all of the tenant's secrets, decrypts them, and updates the
box to match.

On the LXC backend this sets the container's environment.<NAME>
config keys and rewrites tmpfs file-mode secrets. On the Kubernetes
backend it updates the box's mounted Secret, which the kubelet
refreshes in place within about a minute.

Either way, running processes keep their old environment (POSIX
inherit-at-fork); new execs and new sessions — including a fresh
'docker compose up' — see the refreshed values.

Use this after rotating a secret if you want the change to land
without restarting the box.`,
	Args: cobra.ExactArgs(1),
	RunE: runSecretsRefresh,
}

var secretsSetKMSKeyCmd = &cobra.Command{
	Use:   "set-kms-key <username> <key-resource-name>",
	Short: "Set a tenant's per-tenant KMS key for secrets (admin only)",
	Long: `Sets username's own GCP Cloud KMS CryptoKey as the key their secrets
are wrapped under going forward, and re-wraps every secret they
currently own under it (#1630).

Requires the daemon's CONTAINARIUM_KMS_BACKEND=gcp, and a token with
the admin role AND the secrets:write scope granted EXPLICITLY — the
admin role alone is not enough for this RPC, unlike the other
'secrets' subcommands. Mint one with:
  containarium token generate --roles admin --scopes secrets:write ...

key-resource-name is a full GCP Cloud KMS CryptoKey resource path:
  projects/<project>/locations/<location>/keyRings/<ring>/cryptoKeys/<key>

Use 'secrets clear-kms-key' to revert username to the shared KEK.`,
	Args: cobra.ExactArgs(2),
	RunE: runSecretsSetKMSKey,
}

var secretsClearKMSKeyCmd = &cobra.Command{
	Use:   "clear-kms-key <username>",
	Short: "Revert a tenant to the shared KMS key (admin only)",
	Long: `Reverts username from its own per-tenant KMS key back to the
daemon's shared KEK, re-wrapping every secret they currently own.
Idempotent — clearing a tenant with no override still succeeds.

Same authz requirement as 'secrets set-kms-key': admin role + the
secrets:write scope granted explicitly on the token.`,
	Args: cobra.ExactArgs(1),
	RunE: runSecretsClearKMSKey,
}

// secretsDelivery is the value bound to `--delivery` on
// `secrets set` (Phase 4.3 Phase A). Allowed values: "",
// "env" (default; server normalizes ""→"env"), "file"
// (planned tmpfs delivery, Phase B will wire behavior).
var secretsDelivery string

func init() {
	rootCmd.AddCommand(secretsCmd)
	secretsCmd.AddCommand(secretsSetCmd)
	secretsSetCmd.Flags().StringVar(&secretsDelivery, "delivery", "",
		`How the secret reaches the container. "env" (default) stamps `+
			`environment.<NAME>=<value> on the LXC; "file" writes a per-`+
			`secret tmpfs file at /run/secrets/<NAME>; "compose" writes a `+
			`shared dotenv file at /run/containarium/secrets.env that nested `+
			`docker/docker-compose apps consume via env_file: (single-line `+
			`values only). See docs/security/SECRETS-ENV-VAR-RISK.md.`)
	secretsCmd.AddCommand(secretsGetCmd)
	secretsCmd.AddCommand(secretsListCmd)
	secretsCmd.AddCommand(secretsDeleteCmd)
	secretsCmd.AddCommand(secretsRefreshCmd)
	secretsCmd.AddCommand(secretsSetKMSKeyCmd)
	secretsCmd.AddCommand(secretsClearKMSKeyCmd)
}

func runSecretsSet(cmd *cobra.Command, args []string) error {
	username, name, value := args[0], args[1], args[2]
	if serverAddr == "" {
		return fmt.Errorf("--server is required for secrets commands (daemon owns the master key)")
	}

	if httpMode {
		h, err := client.NewHTTPClient(serverAddr, authToken)
		if err != nil {
			return err
		}
		defer func() { _ = h.Close() }()
		msg, err := h.SetSecret(username, name, value, secretsDelivery)
		if err != nil {
			return err
		}
		fmt.Printf("✓ %s\n", msg)
		return nil
	}
	g, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return err
	}
	defer func() { _ = g.Close() }()
	meta, msg, err := g.SetSecret(username, name, value, secretsDelivery)
	if err != nil {
		return err
	}
	deliverySuffix := ""
	if label := secretDeliveryLabel(meta.GetDeliveryMode()); label != "" && label != "env" {
		deliverySuffix = fmt.Sprintf(" delivery=%s", label)
	}
	fmt.Printf("✓ %s (version=%d%s)\n", msg, meta.Version, deliverySuffix)
	return nil
}

func runSecretsGet(cmd *cobra.Command, args []string) error {
	username, name := args[0], args[1]
	if serverAddr == "" {
		return fmt.Errorf("--server is required for secrets commands")
	}

	if httpMode {
		h, err := client.NewHTTPClient(serverAddr, authToken)
		if err != nil {
			return err
		}
		defer func() { _ = h.Close() }()
		value, err := h.GetSecret(username, name)
		if err != nil {
			return err
		}
		// Print only the value, no trailing newline — so callers
		// can `containarium secrets get ... | clip` cleanly.
		fmt.Print(value)
		return nil
	}
	g, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return err
	}
	defer func() { _ = g.Close() }()
	_, value, err := g.GetSecret(username, name)
	if err != nil {
		return err
	}
	fmt.Print(value)
	return nil
}

func runSecretsList(cmd *cobra.Command, args []string) error {
	username := args[0]
	if serverAddr == "" {
		return fmt.Errorf("--server is required for secrets commands")
	}

	// Both transports return []*pb.SecretMetadata, so the two branches
	// differ only in how the client is built — the rendering is shared.
	// It used to be duplicated, and the copies had drifted: the HTTP one
	// read `updated_at` from an untyped map while grpc-gateway emits
	// `updatedAt`, so its UPDATED column printed <nil> (#1219).
	var list []*pb.SecretMetadata
	if httpMode {
		h, err := client.NewHTTPClient(serverAddr, authToken)
		if err != nil {
			return err
		}
		defer func() { _ = h.Close() }()
		if list, err = h.ListSecrets(username); err != nil {
			return err
		}
	} else {
		g, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
		if err != nil {
			return err
		}
		defer func() { _ = g.Close() }()
		if list, err = g.ListSecrets(username); err != nil {
			return err
		}
	}

	if len(list) == 0 {
		fmt.Printf("(no secrets for %s)\n", username)
		return nil
	}
	fmt.Printf("%-32s %-8s %s\n", "NAME", "VERSION", "UPDATED")
	for _, row := range list {
		fmt.Printf("%-32s %-8d %s\n", row.GetName(), row.GetVersion(), strings.TrimSuffix(row.GetUpdatedAt(), "Z"))
	}
	return nil
}

func runSecretsDelete(cmd *cobra.Command, args []string) error {
	username, name := args[0], args[1]
	if serverAddr == "" {
		return fmt.Errorf("--server is required for secrets commands")
	}

	if httpMode {
		h, err := client.NewHTTPClient(serverAddr, authToken)
		if err != nil {
			return err
		}
		defer func() { _ = h.Close() }()
		if err := h.DeleteSecret(username, name); err != nil {
			return err
		}
		fmt.Printf("✓ secret %s deleted\n", name)
		return nil
	}
	g, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return err
	}
	defer func() { _ = g.Close() }()
	msg, err := g.DeleteSecret(username, name)
	if err != nil {
		return err
	}
	if msg == "" {
		msg = fmt.Sprintf("secret %s deleted", name)
	}
	fmt.Printf("✓ %s\n", msg)
	return nil
}

func runSecretsRefresh(cmd *cobra.Command, args []string) error {
	username := args[0]
	if serverAddr == "" {
		return fmt.Errorf("--server is required for secrets commands")
	}

	var msg string
	var stamped int32
	var err error

	if httpMode {
		h, herr := client.NewHTTPClient(serverAddr, authToken)
		if herr != nil {
			return herr
		}
		defer func() { _ = h.Close() }()
		msg, stamped, err = h.RefreshSecrets(username)
	} else {
		g, gerr := client.NewGRPCClient(serverAddr, certsDir, insecure)
		if gerr != nil {
			return gerr
		}
		defer func() { _ = g.Close() }()
		msg, stamped, err = g.RefreshSecrets(username)
	}
	if err != nil {
		return err
	}
	fmt.Printf("✓ %s (stamped=%d)\n", msg, stamped)
	return nil
}

// secretDeliveryLabel renders the delivery enum as the short operator-facing
// word ("env" / "file" / "compose") rather than its proto name. Mirrors
// destLabel in backup.go.
//
// Reads the typed field rather than the deprecated `delivery` string: both
// are populated and always agree, but the string is the one scheduled for
// removal, so new reads go through the enum.
func secretDeliveryLabel(d pb.SecretDelivery) string {
	switch d {
	case pb.SecretDelivery_SECRET_DELIVERY_ENV:
		return "env"
	case pb.SecretDelivery_SECRET_DELIVERY_FILE:
		return "file"
	case pb.SecretDelivery_SECRET_DELIVERY_COMPOSE:
		return "compose"
	default:
		return ""
	}
}

func runSecretsSetKMSKey(cmd *cobra.Command, args []string) error {
	username, keyResourceName := args[0], args[1]
	if serverAddr == "" {
		return fmt.Errorf("--server is required for secrets commands")
	}

	var msg string
	var hasKey bool
	var err error
	if httpMode {
		h, herr := client.NewHTTPClient(serverAddr, authToken)
		if herr != nil {
			return herr
		}
		defer func() { _ = h.Close() }()
		msg, hasKey, err = h.SetTenantKMSKey(username, keyResourceName)
	} else {
		g, gerr := client.NewGRPCClient(serverAddr, certsDir, insecure)
		if gerr != nil {
			return gerr
		}
		defer func() { _ = g.Close() }()
		msg, hasKey, err = g.SetTenantKMSKey(username, keyResourceName)
	}
	if err != nil {
		return err
	}
	fmt.Printf("✓ %s (has_tenant_key=%v)\n", msg, hasKey)
	return nil
}

func runSecretsClearKMSKey(cmd *cobra.Command, args []string) error {
	username := args[0]
	if serverAddr == "" {
		return fmt.Errorf("--server is required for secrets commands")
	}

	var msg string
	var err error
	if httpMode {
		h, herr := client.NewHTTPClient(serverAddr, authToken)
		if herr != nil {
			return herr
		}
		defer func() { _ = h.Close() }()
		msg, _, err = h.SetTenantKMSKey(username, "")
	} else {
		g, gerr := client.NewGRPCClient(serverAddr, certsDir, insecure)
		if gerr != nil {
			return gerr
		}
		defer func() { _ = g.Close() }()
		msg, _, err = g.SetTenantKMSKey(username, "")
	}
	if err != nil {
		return err
	}
	fmt.Printf("✓ %s\n", msg)
	return nil
}
