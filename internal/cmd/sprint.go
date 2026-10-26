package cmd

import (
	"errors"
	"fmt"

	"github.com/footprintai/containarium/internal/client"
	"github.com/spf13/cobra"
)

// `containarium sprint list|board` reads the sprint board a hosted control
// plane mirrors onto each sprint umbrella issue. The platform MCP tools
// sprint_list and sprint_board call the same internal/client functions and
// formatters, so the CLI and an agent see identical results.
//
// REST only: the routes (GET /v1/orgs/{org}/sprints[/board]) exist only on a
// hosted control plane and have no gRPC transport here. Read-only.

var (
	sprintOrg      string
	sprintProject  string
	sprintNumber   int64
	sprintProvider string
)

var sprintCmd = &cobra.Command{
	Use:   "sprint",
	Short: "Read sprint boards mirrored by a hosted control plane",
	Long: `Read the sprint board a hosted control plane mirrors onto each sprint
umbrella issue. Read-only: boards are read, never computed live.

These commands need a hosted control plane. A standalone daemon does not
serve the sprint routes and the command says so.`,
}

var sprintListCmd = &cobra.Command{
	Use:   "list --org <org>",
	Short: "List an organization's sprints with each one's mirror state",
	Long: `List the organization's sprints (open issues labelled "sprint" on
repositories that opted in) with each one's mirror state. Use "sprint board"
to read a board.`,
	Args: cobra.NoArgs,
	RunE: runSprintList,
}

var sprintBoardCmd = &cobra.Command{
	Use:   "board --org <org> --project <owner/repo> --number <n>",
	Short: "Read the board mirrored on one sprint umbrella issue",
	Long: `Print the sprint board mirrored on one umbrella issue as rendered
markdown, after a one-line summary.

NO_MIRROR_YET, NOT_ENABLED and PROVIDER_NOT_SUPPORTED are normal results:
the state is printed and the exit status is 0. A REJECTED mirror (it failed
verification) exits non-zero.`,
	Args: cobra.NoArgs,
	RunE: runSprintBoard,
}

func init() {
	rootCmd.AddCommand(sprintCmd)
	sprintCmd.AddCommand(sprintListCmd, sprintBoardCmd)

	sprintListCmd.Flags().StringVar(&sprintOrg, "org", "", "Organization id. Required.")
	sprintBoardCmd.Flags().StringVar(&sprintOrg, "org", "", "Organization id. Required.")
	sprintBoardCmd.Flags().StringVar(&sprintProject, "project", "", `Repository of the umbrella issue, e.g. "owner/repo". Required.`)
	sprintBoardCmd.Flags().Int64Var(&sprintNumber, "number", 0, "Umbrella issue number. Required.")
	sprintBoardCmd.Flags().StringVar(&sprintProvider, "provider", "github", `Tracker provider of the umbrella: "github" or "gitlab".`)
}

func newSprintClient() (*client.HTTPClient, error) {
	if serverAddr == "" {
		return nil, fmt.Errorf("--server is required for sprint commands")
	}
	return client.NewHTTPClient(serverAddr, authToken)
}

// sprintReadError turns the standalone daemon's route-not-found into the
// actionable message; every other error passes through unchanged.
func sprintReadError(err error) error {
	if client.IsSprintRouteMissing(err) {
		return errors.New("sprint boards need a hosted control plane: this server does not serve the sprint routes (a standalone daemon does not)")
	}
	return err
}

func runSprintList(cmd *cobra.Command, _ []string) error {
	if sprintOrg == "" {
		return fmt.Errorf("--org is required")
	}
	h, err := newSprintClient()
	if err != nil {
		return err
	}
	defer func() { _ = h.Close() }()
	sprints, err := h.ListSprints(client.ListSprintsRequest{OrgID: sprintOrg})
	if err != nil {
		return sprintReadError(err)
	}
	fmt.Fprintln(cmd.OutOrStdout(), client.FormatSprintList(sprints))
	return nil
}

func runSprintBoard(cmd *cobra.Command, _ []string) error {
	if sprintOrg == "" || sprintProject == "" || sprintNumber <= 0 {
		return fmt.Errorf("--org, --project and a positive --number are required")
	}
	provider, err := client.ParseSprintProvider(sprintProvider)
	if err != nil {
		return err
	}
	h, err := newSprintClient()
	if err != nil {
		return err
	}
	defer func() { _ = h.Close() }()
	m, err := h.GetSprintBoard(client.GetSprintBoardRequest{OrgID: sprintOrg, Provider: provider, Project: sprintProject, Number: sprintNumber})
	if err != nil {
		return sprintReadError(err)
	}
	out, err := client.FormatSprintBoard(sprintProject, sprintNumber, m)
	if err != nil {
		return err
	}
	fmt.Fprintln(cmd.OutOrStdout(), out)
	return nil
}
