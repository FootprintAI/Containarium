//go:build !windows && !containarium_client

package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/footprintai/containarium/internal/config"
	"github.com/footprintai/containarium/internal/sentinel"
	"github.com/spf13/cobra"
)

var (
	sentinelDeregisterTokenSentinelURL string
	sentinelDeregisterTokenToken       string
	sentinelDeregisterTokenTokenPrefix string
	sentinelDeregisterTokenSecret      string
	sentinelDeregisterTokenKind        = sentinelTokenKindTunnelJoin
	sentinelDeregisterTokenBackend     string
)

var sentinelDeregisterTokenCmd = &cobra.Command{
	Use:   "deregister-token",
	Short: "Revoke a previously-registered tunnel-join token on a running sentinel (#999, #1963)",
	Long: `DELETE to the sentinel's binary server, revoking a tunnel token so it stops
validating, without a sentinel restart. This is register-token's inverse.

Pass exactly one of --token or --token-prefix:

  --token         revokes the exact token (the shape #999 shipped: the caller
                   must currently hold the plaintext token).
  --token-prefix   revokes EVERY currently registered token starting with the
                   given prefix (#1963) — including a reissued reconnect
                   token sharing the same host-id prefix. Registered tokens
                   are shaped "<host-id>.<secret>", so pass "<host-id>." (the
                   trailing "." is required: the sentinel rejects a prefix
                   without it, since "abc" must not accidentally match
                   "abcd.xyz"). This is the form a control plane needs: a
                   well-behaved registrar hands the plaintext token to the
                   operator exactly once and keeps only a hash, so by the
                   time a host is decommissioned it has no plaintext token
                   left to pass to --token — only the host id it minted the
                   token for.

Deregistering a token (or prefix) that was never registered, or was already
removed, is success, not an error — a decommission caller cannot know in
advance whether registration ever landed, and the end state is identical
either way.

The request is authenticated with the same admin secret as register-token:
CONTAINARIUM_SENTINEL_ADMIN_SECRET.

Examples:

  # Revoke one exact token
  containarium sentinel deregister-token \
      --url http://asia-east1.containarium.dev:8888 \
      --token 453e7e86-47d3-4063-96a8-46c220dda28d.YPkBcGdCNVTqmRNtdjJ0rGslmGdQBM5uwyZS13xEbbg

  # Decommission a host without ever having held its plaintext token
  containarium sentinel deregister-token \
      --url http://asia-east1.containarium.dev:8888 \
      --token-prefix 453e7e86-47d3-4063-96a8-46c220dda28d.`,
	RunE: runSentinelDeregisterToken,
}

func init() {
	sentinelCmd.AddCommand(sentinelDeregisterTokenCmd)

	sentinelDeregisterTokenCmd.Flags().StringVar(&sentinelDeregisterTokenSentinelURL, "url", "", "Sentinel binary-server base URL, e.g. http://asia-east1.containarium.dev:8888 (required)")
	sentinelDeregisterTokenCmd.Flags().StringVar(&sentinelDeregisterTokenToken, "token", "", "Exact tunnel-join token to revoke")
	sentinelDeregisterTokenCmd.Flags().StringVar(&sentinelDeregisterTokenTokenPrefix, "token-prefix", "", `Host-id prefix to revoke every token under, e.g. "<host-id>." (must end with ".")`)
	sentinelDeregisterTokenCmd.Flags().StringVar(&sentinelDeregisterTokenSecret, "secret", os.Getenv(config.EnvSentinelAdminSecret), "Sentinel admin secret (defaults to $CONTAINARIUM_SENTINEL_ADMIN_SECRET)")

	sentinelDeregisterTokenCmd.Flags().Var(&sentinelDeregisterTokenKind, "kind", `Which credential to remove: "tunnel-join" (default) or "audit-ingest" (a backend's SSH session shipper token, #2415)`)
	sentinelDeregisterTokenCmd.Flags().StringVar(&sentinelDeregisterTokenBackend, "backend", "", "Backend id whose audit-ingest token to remove (required for --kind audit-ingest)")

	_ = sentinelDeregisterTokenCmd.MarkFlagRequired("url")
}

func runSentinelDeregisterToken(cmd *cobra.Command, args []string) error {
	if sentinelDeregisterTokenSecret == "" {
		return fmt.Errorf("sentinel admin secret is required — pass --secret or set CONTAINARIUM_SENTINEL_ADMIN_SECRET")
	}

	var (
		endpoint string
		body     []byte
		err      error
	)
	switch sentinelDeregisterTokenKind {
	case sentinelTokenKindAuditIngest:
		if sentinelDeregisterTokenBackend == "" {
			return fmt.Errorf("--backend is required with --kind audit-ingest")
		}
		if sentinelDeregisterTokenToken != "" || sentinelDeregisterTokenTokenPrefix != "" {
			return fmt.Errorf("--token/--token-prefix do not apply to --kind audit-ingest (it removes the --backend's token)")
		}
		endpoint = sentinelDeregisterTokenSentinelURL + "/sentinel/audit-ingest-tokens"
		body, err = json.Marshal(sentinel.AuditIngestTokenDeregisterRequest{BackendID: sentinelDeregisterTokenBackend})
	default: // sentinelTokenKindTunnelJoin
		if sentinelDeregisterTokenBackend != "" {
			return fmt.Errorf("--backend applies only to --kind audit-ingest")
		}
		if sentinelDeregisterTokenToken == "" && sentinelDeregisterTokenTokenPrefix == "" {
			return fmt.Errorf("pass exactly one of --token or --token-prefix")
		}
		if sentinelDeregisterTokenToken != "" && sentinelDeregisterTokenTokenPrefix != "" {
			return fmt.Errorf("pass exactly one of --token or --token-prefix, not both")
		}
		endpoint = sentinelDeregisterTokenSentinelURL + "/sentinel/tunnel-tokens"
		body, err = json.Marshal(sentinel.TunnelTokenDeregisterRequest{
			Token:       sentinelDeregisterTokenToken,
			TokenPrefix: sentinelDeregisterTokenTokenPrefix,
		})
	}
	if err != nil {
		return err
	}

	if err := sendSentinelAdminRequest(http.MethodDelete, endpoint, sentinelDeregisterTokenSecret, body); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "token deregistered\n")
	return nil
}
