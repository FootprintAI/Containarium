package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/footprintai/containarium/internal/client"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

var (
	appListFormat   string
	appListState    string
	appListUsername string
)

var appListCmd = &cobra.Command{
	Use:   "list",
	Short: "List deployed applications",
	Long: `List all deployed applications.

Examples:
  # List all apps
  containarium app list --server <host:port> --user alice

  # List in JSON format
  containarium app list --format json

  # Filter by state
  containarium app list --state running`,
	Aliases: []string{"ls"},
	RunE:    runAppList,
}

func init() {
	appCmd.AddCommand(appListCmd)

	appListCmd.Flags().StringVarP(&appListFormat, "format", "f", "table", "Output format: table, json")
	appListCmd.Flags().StringVar(&appListState, "state", "", "Filter by state: running, stopped, failed, building")
	appListCmd.Flags().StringVarP(&appListUsername, "user", "u", "", "Username")
}

func runAppList(cmd *cobra.Command, args []string) error {
	if serverAddr == "" {
		return fmt.Errorf("--server is required")
	}

	grpcClient, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer grpcClient.Close()

	// Parse state filter
	stateFilter := pb.AppState_APP_STATE_UNSPECIFIED
	if appListState != "" {
		switch strings.ToLower(appListState) {
		case "running":
			stateFilter = pb.AppState_APP_STATE_RUNNING
		case "stopped":
			stateFilter = pb.AppState_APP_STATE_STOPPED
		case "failed":
			stateFilter = pb.AppState_APP_STATE_FAILED
		case "building":
			stateFilter = pb.AppState_APP_STATE_BUILDING
		case "uploading":
			stateFilter = pb.AppState_APP_STATE_UPLOADING
		default:
			return fmt.Errorf("invalid state: %s (use: running, stopped, failed, building, uploading)", appListState)
		}
	}

	apps, totalCount, err := grpcClient.ListApps(appListUsername, stateFilter)
	if err != nil {
		return fmt.Errorf("failed to list apps: %w", err)
	}

	// Output based on format
	switch appListFormat {
	case "table":
		printAppTableFormat(apps, totalCount)
	case "json":
		return printAppJSONFormat(apps)
	default:
		return fmt.Errorf("unknown format: %s (use: table, json)", appListFormat)
	}

	return nil
}

func printAppTableFormat(apps []*pb.App, totalCount int32) {
	fmt.Printf("%-20s %-12s %-35s %-8s %-12s\n", "NAME", "STATE", "DOMAIN", "PORT", "USER")
	fmt.Printf("%-20s %-12s %-35s %-8s %-12s\n",
		strings.Repeat("-", 20),
		strings.Repeat("-", 12),
		strings.Repeat("-", 35),
		strings.Repeat("-", 8),
		strings.Repeat("-", 12))

	if len(apps) == 0 {
		fmt.Println("No applications found.")
		return
	}

	runningCount := 0
	stoppedCount := 0

	for _, app := range apps {
		state := app.State.String()
		state = strings.TrimPrefix(state, "APP_STATE_")

		switch app.State {
		case pb.AppState_APP_STATE_RUNNING:
			runningCount++
		case pb.AppState_APP_STATE_STOPPED:
			stoppedCount++
		}

		fmt.Printf("%-20s %-12s %-35s %-8d %-12s\n",
			truncate(app.Name, 20),
			state,
			truncate(app.FullDomain, 35),
			app.Port,
			truncate(app.Username, 12))
	}

	fmt.Println()
	fmt.Printf("Total: %d apps (%d running, %d stopped)\n", totalCount, runningCount, stoppedCount)
}

func printAppJSONFormat(apps []*pb.App) error {
	output := map[string]interface{}{
		"apps":        apps,
		"total_count": len(apps),
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	fmt.Println(string(data))
	return nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
