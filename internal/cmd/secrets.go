package cmd

import (
	"fmt"
	"strings"

	"github.com/footprintai/containarium/internal/client"
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
	Short: "Re-stamp env vars on the LXC from the current secrets store",
	Long: `Reads all of the tenant's secrets, decrypts them, and updates the
container's environment.<NAME> config keys to match. Running
processes keep their old env (POSIX inherit-at-fork); new execs
(including a fresh 'docker compose up') see the refreshed values.

Use this after rotating a secret if you want the change to land
without restarting the whole container.`,
	Args: cobra.ExactArgs(1),
	RunE: runSecretsRefresh,
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
	if meta != nil && meta.Delivery != "" && meta.Delivery != "env" {
		deliverySuffix = fmt.Sprintf(" delivery=%s", meta.Delivery)
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

	if httpMode {
		h, err := client.NewHTTPClient(serverAddr, authToken)
		if err != nil {
			return err
		}
		defer func() { _ = h.Close() }()
		list, err := h.ListSecrets(username)
		if err != nil {
			return err
		}
		if len(list) == 0 {
			fmt.Printf("(no secrets for %s)\n", username)
			return nil
		}
		fmt.Printf("%-32s %-8s %s\n", "NAME", "VERSION", "UPDATED")
		for _, row := range list {
			fmt.Printf("%-32s %-8v %v\n", row["name"], row["version"], row["updated_at"])
		}
		return nil
	}
	g, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return err
	}
	defer func() { _ = g.Close() }()
	list, err := g.ListSecrets(username)
	if err != nil {
		return err
	}
	if len(list) == 0 {
		fmt.Printf("(no secrets for %s)\n", username)
		return nil
	}
	fmt.Printf("%-32s %-8s %s\n", "NAME", "VERSION", "UPDATED")
	for _, row := range list {
		fmt.Printf("%-32s %-8d %s\n", row.Name, row.Version, strings.TrimSuffix(row.UpdatedAt, "Z"))
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
