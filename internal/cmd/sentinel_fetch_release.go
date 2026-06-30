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
	"github.com/spf13/cobra"
)

var (
	sentinelFetchReleaseSentinelURL string
	sentinelFetchReleaseTag         string
	sentinelFetchReleaseSecret      string
)

var sentinelFetchReleaseCmd = &cobra.Command{
	Use:   "fetch-release",
	Short: "Tell the sentinel to fetch a GitHub release and self-upgrade (#506)",
	Long: `POST to the sentinel's binary server asking it to download the given release
tag from GitHub Releases, verify the SHA256 checksum, smoke-test the binary,
atomically replace its own binary, and restart via systemd.

The request is authenticated with the sentinel HMAC secret
(CONTAINARIUM_SENTINEL_AUTH_SECRET). The sentinel restarts shortly after
returning 200, so the response may arrive before the connection is fully
closed.

Examples:

  # Upgrade the sentinel at 10.130.0.5 to v0.50.0
  containarium sentinel fetch-release \
      --url http://10.130.0.5:8888 \
      --tag v0.50.0

  # Resolve "latest" automatically
  containarium sentinel fetch-release \
      --url http://10.130.0.5:8888 \
      --tag latest`,
	RunE: runSentinelFetchRelease,
}

func init() {
	sentinelCmd.AddCommand(sentinelFetchReleaseCmd)

	sentinelFetchReleaseCmd.Flags().StringVar(&sentinelFetchReleaseSentinelURL, "url", "", "Sentinel binary-server base URL, e.g. http://10.130.0.5:8888 (required)")
	sentinelFetchReleaseCmd.Flags().StringVar(&sentinelFetchReleaseTag, "tag", "", "Release tag to install, e.g. v0.50.0 or \"latest\" (required)")
	sentinelFetchReleaseCmd.Flags().StringVar(&sentinelFetchReleaseSecret, "secret", os.Getenv(config.EnvSentinelAuthSecret), "Sentinel HMAC secret (defaults to $CONTAINARIUM_SENTINEL_AUTH_SECRET)")

	_ = sentinelFetchReleaseCmd.MarkFlagRequired("url")
	_ = sentinelFetchReleaseCmd.MarkFlagRequired("tag")
}

func runSentinelFetchRelease(cmd *cobra.Command, args []string) error {
	if sentinelFetchReleaseSecret == "" {
		return fmt.Errorf("sentinel HMAC secret is required — pass --secret or set CONTAINARIUM_SENTINEL_AUTH_SECRET")
	}

	body, err := json.Marshal(map[string]string{"tag": sentinelFetchReleaseTag})
	if err != nil {
		return err
	}

	endpoint := sentinelFetchReleaseSentinelURL + "/sentinel/fetch-release"
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	auth.SignSentinelRequest(req, []byte(sentinelFetchReleaseSecret))

	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sentinel returned %d: %s", resp.StatusCode, string(respBody))
	}

	fmt.Fprintf(cmd.OutOrStdout(), "%s\n", string(respBody))
	return nil
}
