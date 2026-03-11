package cmd

import (
	"fmt"

	"github.com/footprintai/containarium/internal/client"
	"github.com/footprintai/containarium/internal/container"
	"github.com/spf13/cobra"
)

var installStackCmd = &cobra.Command{
	Use:   "install-stack <username> <stack-id>",
	Short: "Install a software stack on a running container",
	Long: `Install a pre-configured software stack or base script on an existing running container.

Stacks are developer tool bundles (nodejs, python, golang, etc.) whose post-install
commands run as the container user. Base scripts are system-level scripts
(e.g. ntp) that run as root.

Examples:
  # Install Node.js on alice's container
  containarium install-stack alice nodejs

  # Install NTP time sync (base script)
  containarium install-stack alice ntp

  # Remote mode via HTTP
  containarium install-stack alice nodejs --server https://containarium.example.com --http --token <token>`,
	Args: cobra.ExactArgs(2),
	RunE: runInstallStack,
}

func init() {
	rootCmd.AddCommand(installStackCmd)
}

func runInstallStack(cmd *cobra.Command, args []string) error {
	username := args[0]
	stackID := args[1]

	if verbose {
		fmt.Printf("Installing stack %q on container for user: %s\n", stackID, username)
	}

	if httpMode && serverAddr != "" {
		return installStackRemoteHTTP(username, stackID)
	}
	if serverAddr != "" {
		return installStackRemoteGRPC(username, stackID)
	}
	return installStackLocal(username, stackID)
}

func installStackLocal(username, stackID string) error {
	mgr, err := container.New()
	if err != nil {
		return fmt.Errorf("failed to connect to Incus: %w", err)
	}

	if err := mgr.InstallStack(username, stackID); err != nil {
		return fmt.Errorf("failed to install stack: %w", err)
	}

	fmt.Printf("\n✓ Stack %q installed successfully on %s-container\n", stackID, username)
	return nil
}

func installStackRemoteGRPC(username, stackID string) error {
	grpcClient, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return fmt.Errorf("failed to connect to remote server: %w", err)
	}
	defer grpcClient.Close()

	if err := grpcClient.InstallStack(username, stackID); err != nil {
		return fmt.Errorf("failed to install stack: %w", err)
	}

	fmt.Printf("\n✓ Stack %q installed successfully on %s-container\n", stackID, username)
	return nil
}

func installStackRemoteHTTP(username, stackID string) error {
	httpClient, err := client.NewHTTPClient(serverAddr, authToken)
	if err != nil {
		return fmt.Errorf("failed to create HTTP client: %w", err)
	}
	defer httpClient.Close()

	if err := httpClient.InstallStack(username, stackID); err != nil {
		return fmt.Errorf("failed to install stack: %w", err)
	}

	fmt.Printf("\n✓ Stack %q installed successfully on %s-container\n", stackID, username)
	return nil
}
