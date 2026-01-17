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
	getUsername string
	getFormat   string
)

var appGetCmd = &cobra.Command{
	Use:   "get <app-name>",
	Short: "Get application details",
	Long: `Display detailed information about a deployed application.

Examples:
  # Get app details
  containarium app get myapp --server <host:port> --user alice

  # Get in JSON format
  containarium app get myapp --format json`,
	Args: cobra.ExactArgs(1),
	RunE: runAppGet,
}

func init() {
	appCmd.AddCommand(appGetCmd)

	appGetCmd.Flags().StringVarP(&getUsername, "user", "u", "", "Username (required)")
	appGetCmd.Flags().StringVarP(&getFormat, "format", "f", "table", "Output format: table, json")
}

func runAppGet(cmd *cobra.Command, args []string) error {
	appName := args[0]

	if serverAddr == "" {
		return fmt.Errorf("--server is required")
	}

	if getUsername == "" {
		return fmt.Errorf("--user is required")
	}

	grpcClient, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer grpcClient.Close()

	app, err := grpcClient.GetApp(getUsername, appName)
	if err != nil {
		return fmt.Errorf("failed to get app: %w", err)
	}

	switch getFormat {
	case "table":
		printAppDetails(app)
	case "json":
		return printAppJSON(app)
	default:
		return fmt.Errorf("unknown format: %s (use: table, json)", getFormat)
	}

	return nil
}

func printAppDetails(app *pb.App) {
	state := strings.TrimPrefix(app.State.String(), "APP_STATE_")

	fmt.Println("Application Details")
	fmt.Println(strings.Repeat("=", 50))
	fmt.Printf("Name:           %s\n", app.Name)
	fmt.Printf("ID:             %s\n", app.Id)
	fmt.Printf("Username:       %s\n", app.Username)
	fmt.Printf("State:          %s\n", state)
	fmt.Printf("Domain:         %s\n", app.FullDomain)
	fmt.Printf("Port:           %d\n", app.Port)
	fmt.Printf("Container:      %s\n", app.ContainerName)

	if app.DockerImage != "" {
		fmt.Printf("Docker Image:   %s\n", app.DockerImage)
	}

	if app.ErrorMessage != "" {
		fmt.Printf("Error:          %s\n", app.ErrorMessage)
	}

	if len(app.EnvVars) > 0 {
		fmt.Println("\nEnvironment Variables:")
		for key, value := range app.EnvVars {
			fmt.Printf("  %s=%s\n", key, value)
		}
	}

	fmt.Println("\nTimestamps:")
	if app.CreatedAt != nil {
		fmt.Printf("  Created:      %s\n", app.CreatedAt.AsTime().Format("2006-01-02 15:04:05"))
	}
	if app.UpdatedAt != nil {
		fmt.Printf("  Updated:      %s\n", app.UpdatedAt.AsTime().Format("2006-01-02 15:04:05"))
	}
	if app.DeployedAt != nil {
		fmt.Printf("  Deployed:     %s\n", app.DeployedAt.AsTime().Format("2006-01-02 15:04:05"))
	}

	if app.RestartCount > 0 {
		fmt.Printf("\nRestart Count:  %d\n", app.RestartCount)
	}
}

func printAppJSON(app *pb.App) error {
	data, err := json.MarshalIndent(app, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	fmt.Println(string(data))
	return nil
}
