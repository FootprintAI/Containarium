//go:build !windows && !containarium_client

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
	sentinelDeregisterTokenSentinelURL string
	sentinelDeregisterTokenToken       string
	sentinelDeregisterTokenTokenPrefix string
	sentinelDeregisterTokenSecret      string
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

	_ = sentinelDeregisterTokenCmd.MarkFlagRequired("url")
}

func runSentinelDeregisterToken(cmd *cobra.Command, args []string) error {
	if sentinelDeregisterTokenSecret == "" {
		return fmt.Errorf("sentinel admin secret is required — pass --secret or set CONTAINARIUM_SENTINEL_ADMIN_SECRET")
	}
	if sentinelDeregisterTokenToken == "" && sentinelDeregisterTokenTokenPrefix == "" {
		return fmt.Errorf("pass exactly one of --token or --token-prefix")
	}
	if sentinelDeregisterTokenToken != "" && sentinelDeregisterTokenTokenPrefix != "" {
		return fmt.Errorf("pass exactly one of --token or --token-prefix, not both")
	}

	body, err := json.Marshal(sentinel.TunnelTokenDeregisterRequest{
		Token:       sentinelDeregisterTokenToken,
		TokenPrefix: sentinelDeregisterTokenTokenPrefix,
	})
	if err != nil {
		return err
	}

	endpoint := sentinelDeregisterTokenSentinelURL + "/sentinel/tunnel-tokens"
	req, err := http.NewRequest(http.MethodDelete, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	auth.SignSentinelRequest(req, []byte(sentinelDeregisterTokenSecret))

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("DELETE %s: %w", endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("sentinel returned %d: %s", resp.StatusCode, string(respBody))
	}

	fmt.Fprintf(cmd.OutOrStdout(), "token deregistered\n")
	return nil
}
