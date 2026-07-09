//go:build !windows

package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/config"
	"github.com/footprintai/containarium/internal/sentinel"
	"github.com/spf13/cobra"
)

var (
	sentinelRegisterTokenSentinelURL string
	sentinelRegisterTokenToken       string
	sentinelRegisterTokenPools       []string
	sentinelRegisterTokenSecret      string
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
      --token <token> --pool lab --pool prod`,
	RunE: runSentinelRegisterToken,
}

func init() {
	sentinelCmd.AddCommand(sentinelRegisterTokenCmd)

	sentinelRegisterTokenCmd.Flags().StringVar(&sentinelRegisterTokenSentinelURL, "url", "", "Sentinel binary-server base URL, e.g. http://asia-east1.containarium.dev:8888 (required)")
	sentinelRegisterTokenCmd.Flags().StringVar(&sentinelRegisterTokenToken, "token", "", "Tunnel-join token to authorize (required)")
	sentinelRegisterTokenCmd.Flags().StringSliceVar(&sentinelRegisterTokenPools, "pool", nil, "Pool this token may join. Repeatable. Omit for any pool (PoolAny) — the common case for a one-off BYOC token.")
	sentinelRegisterTokenCmd.Flags().StringVar(&sentinelRegisterTokenSecret, "secret", os.Getenv(config.EnvSentinelAdminSecret), "Sentinel admin secret (defaults to $CONTAINARIUM_SENTINEL_ADMIN_SECRET)")

	_ = sentinelRegisterTokenCmd.MarkFlagRequired("url")
	_ = sentinelRegisterTokenCmd.MarkFlagRequired("token")
}

func runSentinelRegisterToken(cmd *cobra.Command, args []string) error {
	if sentinelRegisterTokenSecret == "" {
		return fmt.Errorf("sentinel admin secret is required — pass --secret or set CONTAINARIUM_SENTINEL_ADMIN_SECRET")
	}

	pools := make([]sentinel.Pool, len(sentinelRegisterTokenPools))
	for i, p := range sentinelRegisterTokenPools {
		pools[i] = sentinel.Pool(p)
	}

	body, err := json.Marshal(sentinel.TunnelTokenRegisterRequest{
		Token: sentinelRegisterTokenToken,
		Pools: pools,
	})
	if err != nil {
		return err
	}

	endpoint := sentinelRegisterTokenSentinelURL + "/sentinel/tunnel-tokens"
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	auth.SignSentinelRequest(req, []byte(sentinelRegisterTokenSecret))

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("sentinel returned %d: %s", resp.StatusCode, string(respBody))
	}

	fmt.Fprintf(cmd.OutOrStdout(), "token registered\n")
	return nil
}
