package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var upgradeForce bool

var backendsUpgradeCmd = &cobra.Command{
	Use:   "upgrade [backend-id]",
	Short: "Upgrade a backend's daemon to the sentinel-served binary now",
	Long: `Trigger a daemon upgrade on a backend immediately, instead of waiting for the
periodic auto-update tick. The daemon pulls the binary the sentinel currently
serves, SHA-verifies it, smoke-tests it (runs 'version'), swaps it in atomically
(keeping the previous binary as .old), and restarts.

With no backend-id it upgrades the local/primary daemon; with a peer id it
forwards to that peer (which upgrades its own daemon). Admin-only.

The upgrade is asynchronous: on a successful swap the daemon restarts, so this
command returns an upgrade id immediately. Confirm the result with
'containarium backends versions' once the daemon is back. See #354.

Requires --server pointing at the daemon's HTTP address.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runBackendsUpgrade,
}

func init() {
	backendsCmd.AddCommand(backendsUpgradeCmd)
	backendsUpgradeCmd.Flags().BoolVar(&upgradeForce, "force", false,
		"Upgrade even if the sentinel-served binary already matches the running one.")
}

// triggerUpgradeReq is the typed /v1/backends/upgrade request body. snake_case
// tags match the daemon's grpc-gateway field names.
type triggerUpgradeReq struct {
	BackendID string `json:"backend_id,omitempty"`
	Force     bool   `json:"force,omitempty"`
}

// triggerUpgradeResp mirrors the TriggerUpgrade response (camelCase via the
// grpc-gateway JSON layer).
type triggerUpgradeResp struct {
	UpgradeID      string `json:"upgradeId"`
	Status         string `json:"status"`
	CurrentVersion string `json:"currentVersion"`
	Message        string `json:"message"`
	BackendID      string `json:"backendId"`
}

func runBackendsUpgrade(cmd *cobra.Command, args []string) error {
	// Control-plane upgrades are operator-owned; not a tenant op on the
	// hosted control plane (#456).
	if isCloudTarget(serverAddr, authToken) {
		return errUnsupportedOnCloud("backends upgrade", "the platform operator owns control-plane upgrades")
	}
	if serverAddr == "" {
		return fmt.Errorf("--server is required (the platform daemon's HTTP address, e.g. http://host:8080)")
	}
	backendID := ""
	if len(args) == 1 {
		backendID = args[0]
	}

	reqBody, _ := json.Marshal(triggerUpgradeReq{BackendID: backendID, Force: upgradeForce})
	url := strings.TrimSuffix(serverAddr, "/") + "/v1/backends/upgrade"

	req, err := http.NewRequest("POST", url, bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}

	httpClient := &http.Client{Timeout: 60 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request %s: %w", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var out triggerUpgradeResp
	if err := json.Unmarshal(body, &out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	target := out.BackendID
	if target == "" {
		target = "(local)"
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Upgrade %s on %s (job %s)\n", out.Status, target, out.UpgradeID)
	if out.CurrentVersion != "" {
		fmt.Fprintf(cmd.OutOrStdout(), "  from version: %s\n", out.CurrentVersion)
	}
	if out.Message != "" {
		fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", out.Message)
	}
	return nil
}
