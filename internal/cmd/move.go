package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var (
	moveTargetBackend         string
	moveMaxIterations         int32
	moveDeltaThresholdSeconds int32
	moveStateful              bool
)

var moveCmd = &cobra.Command{
	Use:   "move <username>",
	Short: "Migrate a container to a peer daemon",
	Long: `Pre-copy snapshot-based migration of a container to a peer daemon.

The local daemon snapshots the container, copies the snapshot to the
target's incusd via Incus's native push protocol, takes iterative
delta snapshots while the source keeps serving traffic, then briefly
stops the source for a final delta + start-on-target + route swap.

Downtime is sub-second on ZFS/btrfs storage with low write rate;
potentially minutes on dir-pool or active workloads. The route store
target_ip update propagates to Caddy via RouteSyncJob within ~5
seconds — public hostname does not change.

Prerequisites:
  - Both source and target daemons must be peered (visible in
    /v1/backends).
  - The source's incusd must have the target configured as a remote:
        incus remote add <target_backend_id> https://<target-host>:8443

Examples:
  containarium move alice --target vm2
  containarium move alice --target vm2 --max-iterations 5 --delta-threshold 3`,
	Args: cobra.ExactArgs(1),
	RunE: runMove,
}

func init() {
	rootCmd.AddCommand(moveCmd)
	moveCmd.Flags().StringVar(&moveTargetBackend, "target", "", "target peer backend ID (required)")
	moveCmd.Flags().Int32Var(&moveMaxIterations, "max-iterations", 3, "max delta-refresh iterations before cutover [0..10]")
	moveCmd.Flags().Int32Var(&moveDeltaThresholdSeconds, "delta-threshold", 5, "if a delta refresh completes in less than this many seconds, skip to cutover")
	moveCmd.Flags().BoolVar(&moveStateful, "stateful", false, "attempt CRIU-based live migration (requires CRIU on both ends; not supported with podman-in-LXC)")
	_ = moveCmd.MarkFlagRequired("target")
}

func runMove(cmd *cobra.Command, args []string) error {
	username := args[0]
	if moveTargetBackend == "" {
		return fmt.Errorf("--target is required")
	}

	// Move is a daemon-orchestrated operation; the CLI is a thin
	// REST caller. We don't have a "local mode" — even when run on
	// the same host as the daemon, the orchestration logic lives in
	// the daemon process where the peer pool, route store, and
	// incus shell-out helpers are wired.
	if serverAddr == "" {
		return fmt.Errorf("move requires --server (remote mode); the daemon orchestrates the migration")
	}

	url := strings.TrimRight(serverAddr, "/") + "/v1/containers/" + username + "/move"
	body, err := json.Marshal(map[string]interface{}{
		"username":                username,
		"target_backend_id":       moveTargetBackend,
		"max_iterations":          moveMaxIterations,
		"delta_threshold_seconds": moveDeltaThresholdSeconds,
		"stateful":                moveStateful,
	})
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}

	client := &http.Client{Timeout: 30 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("call move RPC: %w", err)
	}
	defer resp.Body.Close()

	var parsed struct {
		Message         string `json:"message"`
		NewIPAddress    string `json:"newIpAddress"`
		TargetBackendID string `json:"targetBackendId"`
		IterationsRun   int32  `json:"iterationsRun"`
		DowntimeSeconds int32  `json:"downtimeSeconds"`
		Error           string `json:"error,omitempty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return fmt.Errorf("decode response: %w (status %d)", err, resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		if parsed.Error != "" {
			return fmt.Errorf("move failed: %s", parsed.Error)
		}
		return fmt.Errorf("move failed: status %d", resp.StatusCode)
	}

	fmt.Println("✓", parsed.Message)
	fmt.Printf("  target backend:    %s\n", parsed.TargetBackendID)
	fmt.Printf("  new container IP:  %s\n", parsed.NewIPAddress)
	fmt.Printf("  iterations:        %d\n", parsed.IterationsRun)
	fmt.Printf("  cutover downtime:  %ds\n", parsed.DowntimeSeconds)
	return nil
}
