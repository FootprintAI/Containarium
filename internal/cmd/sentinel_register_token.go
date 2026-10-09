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
	sentinelRegisterTokenSentinelURL string
	sentinelRegisterTokenToken       string
	sentinelRegisterTokenPools       []string
	sentinelRegisterTokenSecret      string
	sentinelRegisterTokenKind        = sentinelTokenKindTunnelJoin
	sentinelRegisterTokenBackend     string
)

var sentinelRegisterTokenCmd = &cobra.Command{
	Use:   "register-token",
	Short: "Register a freshly-minted tunnel-join token on a running sentinel (#799)",
	Long: `POST to the sentinel's binary server, authorizing a tunnel-join token that
was minted after the sentinel started.

The sentinel's token policy is otherwise built once at startup from
--tunnel-token/--tunnel-token-policy — a token issued afterwards (e.g. by a
cloud control plane's BYOC join flow) has no way to become valid without
this call, and every handshake using it fails with "invalid token"
regardless of how correctly-formed the token is.

The request is authenticated with a DIFFERENT secret than sentinel
fetch-release/ca/peer-cert use: CONTAINARIUM_SENTINEL_ADMIN_SECRET, not
CONTAINARIUM_SENTINEL_AUTH_SECRET. Every cluster daemon holds the auth
secret for keysync/certsync; admitting a brand-new node into a pool is a
bigger capability than that, so it is gated separately.

Examples:

  # Authorize a token for any pool (the common BYOC case)
  containarium sentinel register-token \
      --url http://asia-east1.containarium.dev:8888 \
      --token 453e7e86-47d3-4063-96a8-46c220dda28d.YPkBcGdCNVTqmRNtdjJ0rGslmGdQBM5uwyZS13xEbbg

  # Restrict a token to specific pools
  containarium sentinel register-token \
      --url http://asia-east1.containarium.dev:8888 \
      --token <token> --pool lab --pool prod

  # Register the audit-ingest token the SSH session shipper uses for one
  # backend (#2415). Mint it ON that backend first:
  #   containarium token generate --username sentinel-shipper --roles service \
  #       --scopes audit:ingest --expiry 2160h --secret-file /etc/containarium/jwt.secret
  # Registering again for the same --backend replaces the token (rotation).
  containarium sentinel register-token --kind audit-ingest \
      --url http://asia-east1.containarium.dev:8888 \
      --backend <backend-id> --token <jwt>`,
	RunE: runSentinelRegisterToken,
}

func init() {
	sentinelCmd.AddCommand(sentinelRegisterTokenCmd)

	sentinelRegisterTokenCmd.Flags().StringVar(&sentinelRegisterTokenSentinelURL, "url", "", "Sentinel binary-server base URL, e.g. http://asia-east1.containarium.dev:8888 (required)")
	sentinelRegisterTokenCmd.Flags().StringVar(&sentinelRegisterTokenToken, "token", "", "Tunnel-join token to authorize (required)")
	sentinelRegisterTokenCmd.Flags().StringSliceVar(&sentinelRegisterTokenPools, "pool", nil, "Pool this token may join. Repeatable. Omit for any pool (PoolAny) — the common case for a one-off BYOC token.")
	sentinelRegisterTokenCmd.Flags().StringVar(&sentinelRegisterTokenSecret, "secret", os.Getenv(config.EnvSentinelAdminSecret), "Sentinel admin secret (defaults to $CONTAINARIUM_SENTINEL_ADMIN_SECRET)")

	sentinelRegisterTokenCmd.Flags().Var(&sentinelRegisterTokenKind, "kind", `Which credential to register: "tunnel-join" (default, BYOC join token) or "audit-ingest" (per-backend audit:ingest JWT for the SSH session shipper)`)
	sentinelRegisterTokenCmd.Flags().StringVar(&sentinelRegisterTokenBackend, "backend", "", "Backend id the token belongs to (required for --kind audit-ingest)")

	_ = sentinelRegisterTokenCmd.MarkFlagRequired("url")
	_ = sentinelRegisterTokenCmd.MarkFlagRequired("token")
}

func runSentinelRegisterToken(cmd *cobra.Command, args []string) error {
	if sentinelRegisterTokenSecret == "" {
		return fmt.Errorf("sentinel admin secret is required — pass --secret or set CONTAINARIUM_SENTINEL_ADMIN_SECRET")
	}

	var (
		endpoint string
		body     []byte
		err      error
	)
	switch sentinelRegisterTokenKind {
	case sentinelTokenKindAuditIngest:
		if sentinelRegisterTokenBackend == "" {
			return fmt.Errorf("--backend is required with --kind audit-ingest")
		}
		if len(sentinelRegisterTokenPools) > 0 {
			return fmt.Errorf("--pool does not apply to --kind audit-ingest (tokens are per backend, not per pool)")
		}
		endpoint = sentinelRegisterTokenSentinelURL + "/sentinel/audit-ingest-tokens"
		body, err = json.Marshal(sentinel.AuditIngestTokenRegisterRequest{
			BackendID: sentinelRegisterTokenBackend,
			Token:     sentinelRegisterTokenToken,
		})
	default: // sentinelTokenKindTunnelJoin
		if sentinelRegisterTokenBackend != "" {
			return fmt.Errorf("--backend applies only to --kind audit-ingest")
		}
		pools := make([]sentinel.Pool, len(sentinelRegisterTokenPools))
		for i, p := range sentinelRegisterTokenPools {
			pools[i] = sentinel.Pool(p)
		}
		endpoint = sentinelRegisterTokenSentinelURL + "/sentinel/tunnel-tokens"
		body, err = json.Marshal(sentinel.TunnelTokenRegisterRequest{
			Token: sentinelRegisterTokenToken,
			Pools: pools,
		})
	}
	if err != nil {
		return err
	}

	if err := sendSentinelAdminRequest(http.MethodPost, endpoint, sentinelRegisterTokenSecret, body); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "token registered\n")
	return nil
}
