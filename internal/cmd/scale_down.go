package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/client"
	"github.com/footprintai/containarium/internal/safecast"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

var (
	scaleDownEnableIdle string
)

var scaleDownCmd = &cobra.Command{
	Use:   "scale-down",
	Short: "Manage per-container auto-sleep opt-in (Phase 1)",
	Long: `Manage the per-container auto-sleep flag. Phase 1 sets the metadata;
Phase 2 (idle daemon) and Phase 3 (HTTP wake) consume it.`,
}

var scaleDownEnableCmd = &cobra.Command{
	Use:   "enable <username>",
	Short: "Opt a container into auto-sleep",
	Args:  cobra.ExactArgs(1),
	RunE:  runScaleDownEnable,
}

var scaleDownDisableCmd = &cobra.Command{
	Use:   "disable <username>",
	Short: "Opt a container out of auto-sleep (idempotent)",
	Args:  cobra.ExactArgs(1),
	RunE:  runScaleDownDisable,
}

var scaleDownStatusCmd = &cobra.Command{
	Use:   "status [username]",
	Short: "Show auto-sleep status for one or all containers",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runScaleDownStatus,
}

var sleepCmd = &cobra.Command{
	Use:   "sleep <username>",
	Short: "Stop a container (alias for stop, surfaces 'sleeping' messaging)",
	Args:  cobra.ExactArgs(1),
	RunE:  runSleep,
}

var wakeCmd = &cobra.Command{
	Use:   "wake <username>",
	Short: "Start a container and wait for its primary port to accept",
	Args:  cobra.ExactArgs(1),
	RunE:  runWake,
}

func init() {
	rootCmd.AddCommand(scaleDownCmd)
	scaleDownCmd.AddCommand(scaleDownEnableCmd)
	scaleDownCmd.AddCommand(scaleDownDisableCmd)
	scaleDownCmd.AddCommand(scaleDownStatusCmd)
	rootCmd.AddCommand(sleepCmd)
	rootCmd.AddCommand(wakeCmd)

	scaleDownEnableCmd.Flags().StringVar(&scaleDownEnableIdle, "idle", "15m",
		"Idle duration before sleep (Go duration, e.g. 15m, 1h). Minimum 1m.")
}

// parseIdleMinutes parses a Go duration string and converts to integer
// minutes. Sub-minute precision is dropped (rounded up to 1m minimum).
func parseIdleMinutes(s string) (int32, error) {
	if s == "" {
		return 15, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q: %w", s, err)
	}
	if d < time.Minute {
		return 0, fmt.Errorf("idle duration must be at least 1 minute, got %s", s)
	}
	mins := safecast.I32(d / time.Minute)
	if mins < 1 {
		mins = 1
	}
	return mins, nil
}

func runScaleDownEnable(cmd *cobra.Command, args []string) error {
	username := args[0]
	mins, err := parseIdleMinutes(scaleDownEnableIdle)
	if err != nil {
		return err
	}
	resp, err := toggleAutoSleepViaServer(username, true, mins)
	if err != nil {
		return err
	}
	fmt.Printf("✓ %s — auto_sleep_enabled=%v idle_threshold_minutes=%d\n",
		resp.Message, resp.AutoSleepEnabled, resp.IdleThresholdMinutes)
	return nil
}

func runScaleDownDisable(cmd *cobra.Command, args []string) error {
	username := args[0]
	resp, err := toggleAutoSleepViaServer(username, false, 0)
	if err != nil {
		return err
	}
	fmt.Printf("✓ %s — auto_sleep_enabled=%v\n", resp.Message, resp.AutoSleepEnabled)
	return nil
}

func runScaleDownStatus(cmd *cobra.Command, args []string) error {
	if serverAddr == "" {
		return fmt.Errorf("--server is required")
	}
	var containers []incus.ContainerInfo
	var err error
	if len(args) == 1 {
		containers, err = fetchOneContainer(args[0])
	} else {
		containers, err = fetchAllContainers()
	}
	if err != nil {
		return err
	}
	fmt.Printf("%-25s %-8s %-12s %s\n", "USERNAME", "ENABLED", "THRESHOLD", "STATE")
	fmt.Printf("%-25s %-8s %-12s %s\n", strings.Repeat("-", 25), strings.Repeat("-", 8), strings.Repeat("-", 12), strings.Repeat("-", 12))
	for _, c := range containers {
		username := strings.TrimSuffix(c.Name, "-container")
		threshold := fmt.Sprintf("%dm", c.IdleThresholdMinutes)
		fmt.Printf("%-25s %-8v %-12s %s\n", username, c.AutoSleepEnabled, threshold, c.State)
	}
	return nil
}

func runSleep(cmd *cobra.Command, args []string) error {
	username := args[0]
	if serverAddr == "" {
		return fmt.Errorf("--server is required")
	}
	if httpMode {
		httpClient, err := client.NewHTTPClient(serverAddr, authToken)
		if err != nil {
			return err
		}
		defer func() { _ = httpClient.Close() }()
		resp, err := httpClient.StopContainer(username, false)
		if err != nil {
			return err
		}
		fmt.Printf("✓ Container %s is sleeping (%s)\n", username, resp.Message)
		return nil
	}
	grpcClient, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return err
	}
	defer func() { _ = grpcClient.Close() }()
	resp, err := grpcClient.StopContainer(username, false)
	if err != nil {
		return err
	}
	fmt.Printf("✓ Container %s is sleeping (%s)\n", username, resp.Message)
	return nil
}

func runWake(cmd *cobra.Command, args []string) error {
	username := args[0]
	if serverAddr == "" {
		return fmt.Errorf("--server is required")
	}
	if httpMode {
		httpClient, err := client.NewHTTPClient(serverAddr, authToken)
		if err != nil {
			return err
		}
		defer func() { _ = httpClient.Close() }()
		resp, err := httpClient.StartContainer(username, true, 30)
		if err != nil {
			return err
		}
		printWakeResult(username, resp)
		return nil
	}
	grpcClient, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return err
	}
	defer func() { _ = grpcClient.Close() }()
	resp, err := grpcClient.StartContainer(username, true, 30)
	if err != nil {
		return err
	}
	printWakeResult(username, resp)
	return nil
}

func printWakeResult(username string, resp *pb.StartContainerResponse) {
	if resp.ReadyTimedOut {
		fmt.Printf("⚠ Container %s started but readiness probe timed out\n", username)
		return
	}
	fmt.Printf("✓ Container %s is awake (%s)\n", username, resp.Message)
}

func toggleAutoSleepViaServer(username string, enabled bool, idleMinutes int32) (*pb.ToggleAutoSleepResponse, error) {
	if serverAddr == "" {
		return nil, fmt.Errorf("--server is required")
	}
	if httpMode {
		httpClient, err := client.NewHTTPClient(serverAddr, authToken)
		if err != nil {
			return nil, err
		}
		defer func() { _ = httpClient.Close() }()
		return httpClient.ToggleAutoSleep(username, enabled, idleMinutes)
	}
	grpcClient, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return nil, err
	}
	defer func() { _ = grpcClient.Close() }()
	return grpcClient.ToggleAutoSleep(username, enabled, idleMinutes)
}

func fetchAllContainers() ([]incus.ContainerInfo, error) {
	if httpMode {
		httpClient, err := client.NewHTTPClient(serverAddr, authToken)
		if err != nil {
			return nil, err
		}
		defer func() { _ = httpClient.Close() }()
		return httpClient.ListContainers()
	}
	grpcClient, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return nil, err
	}
	defer func() { _ = grpcClient.Close() }()
	return grpcClient.ListContainers()
}

func fetchOneContainer(username string) ([]incus.ContainerInfo, error) {
	if httpMode {
		httpClient, err := client.NewHTTPClient(serverAddr, authToken)
		if err != nil {
			return nil, err
		}
		defer func() { _ = httpClient.Close() }()
		info, err := httpClient.GetContainer(username)
		if err != nil {
			return nil, err
		}
		return []incus.ContainerInfo{*info}, nil
	}
	grpcClient, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return nil, err
	}
	defer func() { _ = grpcClient.Close() }()
	info, err := grpcClient.GetContainer(username)
	if err != nil {
		return nil, err
	}
	return []incus.ContainerInfo{*info}, nil
}
