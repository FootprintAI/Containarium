package cmd

import (
	"fmt"

	"github.com/footprintai/containarium/internal/client"
	"github.com/spf13/cobra"
)

var collaboratorRemoveCmd = &cobra.Command{
	Use:   "remove <owner-username> <collaborator-username>",
	Short: "Remove a collaborator from a container",
	Long: `Remove a collaborator from a container.

This will:
1. Remove the collaborator's user account from the container
2. Remove the collaborator's jump server account
3. Remove the collaborator from the database

Examples:
  # Remove bob as a collaborator from alice's container
  containarium collaborator remove alice bob

  # Against a remote daemon
  containarium collaborator remove alice bob --server daemon.example.com:50051`,
	Args: cobra.ExactArgs(2),
	RunE: runCollaboratorRemove,
}

func init() {
	collaboratorCmd.AddCommand(collaboratorRemoveCmd)
}

func runCollaboratorRemove(cmd *cobra.Command, args []string) error {
	ownerUsername := args[0]
	collaboratorUsername := args[1]

	switch {
	case httpMode && serverAddr != "":
		return removeCollaboratorRemoteHTTP(ownerUsername, collaboratorUsername)
	case serverAddr != "":
		return removeCollaboratorRemote(ownerUsername, collaboratorUsername)
	default:
		return removeCollaboratorLocal(ownerUsername, collaboratorUsername)
	}
}

func removeCollaboratorRemote(ownerUsername, collaboratorUsername string) error {
	grpcClient, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return fmt.Errorf("failed to connect to remote server: %w", err)
	}
	defer func() { _ = grpcClient.Close() }()

	resp, err := grpcClient.RemoveCollaborator(ownerUsername, collaboratorUsername)
	if err != nil {
		return fmt.Errorf("failed to remove collaborator: %w", err)
	}
	fmt.Println(resp.GetMessage())
	return nil
}

func removeCollaboratorRemoteHTTP(ownerUsername, collaboratorUsername string) error {
	httpClient, err := client.NewHTTPClient(serverAddr, authToken)
	if err != nil {
		return fmt.Errorf("failed to create HTTP client: %w", err)
	}
	defer func() { _ = httpClient.Close() }()

	resp, err := httpClient.RemoveCollaborator(ownerUsername, collaboratorUsername)
	if err != nil {
		return fmt.Errorf("failed to remove collaborator: %w", err)
	}
	fmt.Println(resp.GetMessage())
	return nil
}
