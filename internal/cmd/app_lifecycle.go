package cmd

import (
	"fmt"
	"strings"

	"github.com/footprintai/containarium/internal/client"
	"github.com/spf13/cobra"
)

var (
	lifecycleUsername string
)

// Stop command
var appStopCmd = &cobra.Command{
	Use:   "stop <app-name>",
	Short: "Stop a running application",
	Long: `Stop a running application.

The application can be started again later using 'containarium app start'.

Examples:
  containarium app stop myapp --server <host:port> --user alice`,
	Args: cobra.ExactArgs(1),
	RunE: runAppStop,
}

// Start command
var appStartCmd = &cobra.Command{
	Use:   "start <app-name>",
	Short: "Start a stopped application",
	Long: `Start a previously stopped application.

Examples:
  containarium app start myapp --server <host:port> --user alice`,
	Args: cobra.ExactArgs(1),
	RunE: runAppStart,
}

// Restart command
var appRestartCmd = &cobra.Command{
	Use:   "restart <app-name>",
	Short: "Restart an application",
	Long: `Restart an application by stopping and starting it.

Examples:
  containarium app restart myapp --server <host:port> --user alice`,
	Args: cobra.ExactArgs(1),
	RunE: runAppRestart,
}

func init() {
	appCmd.AddCommand(appStopCmd)
	appCmd.AddCommand(appStartCmd)
	appCmd.AddCommand(appRestartCmd)

	// Add username flag to all lifecycle commands
	appStopCmd.Flags().StringVarP(&lifecycleUsername, "user", "u", "", "Username (required)")
	appStartCmd.Flags().StringVarP(&lifecycleUsername, "user", "u", "", "Username (required)")
	appRestartCmd.Flags().StringVarP(&lifecycleUsername, "user", "u", "", "Username (required)")
}

func runAppStop(cmd *cobra.Command, args []string) error {
	appName := args[0]

	if serverAddr == "" {
		return fmt.Errorf("--server is required")
	}

	if lifecycleUsername == "" {
		return fmt.Errorf("--user is required")
	}

	grpcClient, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer grpcClient.Close()

	app, err := grpcClient.StopApp(lifecycleUsername, appName)
	if err != nil {
		return fmt.Errorf("failed to stop app: %w", err)
	}

	state := strings.TrimPrefix(app.State.String(), "APP_STATE_")
	fmt.Printf("Application %s stopped successfully (state: %s)\n", appName, state)

	return nil
}

func runAppStart(cmd *cobra.Command, args []string) error {
	appName := args[0]

	if serverAddr == "" {
		return fmt.Errorf("--server is required")
	}

	if lifecycleUsername == "" {
		return fmt.Errorf("--user is required")
	}

	grpcClient, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer grpcClient.Close()

	app, err := grpcClient.StartApp(lifecycleUsername, appName)
	if err != nil {
		return fmt.Errorf("failed to start app: %w", err)
	}

	state := strings.TrimPrefix(app.State.String(), "APP_STATE_")
	fmt.Printf("Application %s started successfully (state: %s)\n", appName, state)
	fmt.Printf("URL: https://%s\n", app.FullDomain)

	return nil
}

func runAppRestart(cmd *cobra.Command, args []string) error {
	appName := args[0]

	if serverAddr == "" {
		return fmt.Errorf("--server is required")
	}

	if lifecycleUsername == "" {
		return fmt.Errorf("--user is required")
	}

	grpcClient, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer grpcClient.Close()

	fmt.Printf("Restarting application %s...\n", appName)
	app, err := grpcClient.RestartApp(lifecycleUsername, appName)
	if err != nil {
		return fmt.Errorf("failed to restart app: %w", err)
	}

	state := strings.TrimPrefix(app.State.String(), "APP_STATE_")
	fmt.Printf("Application %s restarted successfully (state: %s)\n", appName, state)
	fmt.Printf("URL: https://%s\n", app.FullDomain)

	return nil
}
