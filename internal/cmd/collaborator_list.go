package cmd

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/footprintai/containarium/internal/collaborator"
	"github.com/spf13/cobra"
)

var collaboratorListCmd = &cobra.Command{
	Use:   "list <owner-username>",
	Short: "List collaborators for a container",
	Long: `List all collaborators who have access to a container.

Examples:
  # List collaborators for alice's container
  containarium collaborator list alice`,
	Args: cobra.ExactArgs(1),
	RunE: runCollaboratorList,
}

func init() {
	collaboratorCmd.AddCommand(collaboratorListCmd)
}

func runCollaboratorList(cmd *cobra.Command, args []string) error {
	ownerUsername := args[0]

	// Local mode only for now (requires PostgreSQL)
	return listCollaboratorsLocal(ownerUsername)
}

func listCollaboratorsLocal(ownerUsername string) error {
	containerName := ownerUsername + "-container"

	// Create collaborator store
	collaboratorStore, err := collaborator.NewStore(context.Background(), getPostgresConnString())
	if err != nil {
		return fmt.Errorf("failed to connect to collaborator database: %w\n(Is PostgreSQL running? Set CONTAINARIUM_POSTGRES_URL if using non-default location)", err)
	}
	defer collaboratorStore.Close()

	// List collaborators
	collaborators, err := collaboratorStore.List(context.Background(), containerName)
	if err != nil {
		return fmt.Errorf("failed to list collaborators: %w", err)
	}

	if len(collaborators) == 0 {
		fmt.Printf("No collaborators found for %s\n", containerName)
		return nil
	}

	fmt.Printf("Collaborators for %s:\n\n", containerName)

	// Print as table
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "USERNAME\tACCOUNT NAME\tADDED AT\tADDED BY")
	fmt.Fprintln(w, "--------\t------------\t--------\t--------")

	for _, c := range collaborators {
		addedAt := c.CreatedAt.Format(time.RFC3339)
		addedBy := c.CreatedBy
		if addedBy == "" {
			addedBy = "-"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", c.CollaboratorUsername, c.AccountName, addedAt, addedBy)
	}
	_ = w.Flush()

	fmt.Printf("\nTotal: %d collaborator(s)\n", len(collaborators))
	return nil
}
