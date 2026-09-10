package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/footprintai/containarium/internal/client"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

var collaboratorListCmd = &cobra.Command{
	Use:   "list <owner-username>",
	Short: "List collaborators for a container",
	Long: `List all collaborators who have access to a container.

Examples:
  # List collaborators for alice's container
  containarium collaborator list alice

  # Against a remote daemon
  containarium collaborator list alice --server daemon.example.com:50051`,
	Args: cobra.ExactArgs(1),
	RunE: runCollaboratorList,
}

func init() {
	collaboratorCmd.AddCommand(collaboratorListCmd)
}

// collaboratorRow is the local/remote-agnostic shape printCollaboratorTable
// needs — local mode reads internal/collaborator.Collaborator straight from
// Postgres, remote mode gets pb.Collaborator off the wire; both normalize
// into this before printing so the table code is written once. Defined
// here (not in collaborator_local.go) so it's visible under both build
// tags: the containarium_client stub for listCollaboratorsLocal returns
// this same type.
type collaboratorRow struct {
	CollaboratorUsername string
	AccountName          string
	CreatedAt            time.Time
	CreatedBy            string
}

func runCollaboratorList(cmd *cobra.Command, args []string) error {
	ownerUsername := args[0]
	containerName := ownerUsername + "-container"

	var (
		rows []collaboratorRow
		err  error
	)
	switch {
	case httpMode && serverAddr != "":
		rows, err = listCollaboratorsRemoteHTTP(ownerUsername)
	case serverAddr != "":
		rows, err = listCollaboratorsRemote(ownerUsername)
	default:
		rows, err = listCollaboratorsLocal(ownerUsername)
	}
	if err != nil {
		return err
	}

	printCollaboratorTable(containerName, rows)
	return nil
}

func listCollaboratorsRemote(ownerUsername string) ([]collaboratorRow, error) {
	grpcClient, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to remote server: %w", err)
	}
	defer func() { _ = grpcClient.Close() }()

	resp, err := grpcClient.ListCollaborators(ownerUsername)
	if err != nil {
		return nil, fmt.Errorf("failed to list collaborators: %w", err)
	}
	return pbCollaboratorsToRows(resp.GetCollaborators()), nil
}

func listCollaboratorsRemoteHTTP(ownerUsername string) ([]collaboratorRow, error) {
	httpClient, err := client.NewHTTPClient(serverAddr, authToken)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}
	defer func() { _ = httpClient.Close() }()

	resp, err := httpClient.ListCollaborators(ownerUsername)
	if err != nil {
		return nil, fmt.Errorf("failed to list collaborators: %w", err)
	}
	return pbCollaboratorsToRows(resp.GetCollaborators()), nil
}

func pbCollaboratorsToRows(collaborators []*pb.Collaborator) []collaboratorRow {
	rows := make([]collaboratorRow, 0, len(collaborators))
	for _, c := range collaborators {
		rows = append(rows, collaboratorRow{
			CollaboratorUsername: c.GetCollaboratorUsername(),
			AccountName:          c.GetAccountName(),
			CreatedAt:            time.Unix(c.GetAddedAt(), 0),
			CreatedBy:            c.GetCreatedBy(),
		})
	}
	return rows
}

func printCollaboratorTable(containerName string, rows []collaboratorRow) {
	if len(rows) == 0 {
		fmt.Printf("No collaborators found for %s\n", containerName)
		return
	}

	fmt.Printf("Collaborators for %s:\n\n", containerName)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "USERNAME\tACCOUNT NAME\tADDED AT\tADDED BY")
	fmt.Fprintln(w, "--------\t------------\t--------\t--------")

	for _, row := range rows {
		addedBy := row.CreatedBy
		if addedBy == "" {
			addedBy = "-"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", row.CollaboratorUsername, row.AccountName, row.CreatedAt.Format(time.RFC3339), addedBy)
	}
	_ = w.Flush()

	fmt.Printf("\nTotal: %d collaborator(s)\n", len(rows))
}
