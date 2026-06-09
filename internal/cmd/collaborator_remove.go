//go:build !windows

package cmd

import (
	"context"
	"fmt"

	"github.com/footprintai/containarium/internal/collaborator"
	"github.com/footprintai/containarium/pkg/core/container"
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
  containarium collaborator remove alice bob`,
	Args: cobra.ExactArgs(2),
	RunE: runCollaboratorRemove,
}

func init() {
	collaboratorCmd.AddCommand(collaboratorRemoveCmd)
}

func runCollaboratorRemove(cmd *cobra.Command, args []string) error {
	ownerUsername := args[0]
	collaboratorUsername := args[1]

	// Local mode only for now (requires PostgreSQL)
	return removeCollaboratorLocal(ownerUsername, collaboratorUsername)
}

func removeCollaboratorLocal(ownerUsername, collaboratorUsername string) error {
	// Create container manager
	containerMgr, err := container.New()
	if err != nil {
		return fmt.Errorf("failed to connect to Incus: %w (is Incus running?)", err)
	}

	// Create collaborator store
	collaboratorStore, err := collaborator.NewStore(context.Background(), getPostgresConnString())
	if err != nil {
		return fmt.Errorf("failed to connect to collaborator database: %w\n(Is PostgreSQL running? Set CONTAINARIUM_POSTGRES_URL if using non-default location)", err)
	}
	defer collaboratorStore.Close()

	// Create collaborator manager
	collaboratorMgr := container.NewCollaboratorManager(containerMgr, collaboratorStore)

	// Remove collaborator
	if err := collaboratorMgr.RemoveCollaborator(ownerUsername, collaboratorUsername); err != nil {
		return fmt.Errorf("failed to remove collaborator: %w", err)
	}

	fmt.Printf("Collaborator %s removed from %s-container\n", collaboratorUsername, ownerUsername)
	return nil
}
