package cmd

import (
	"fmt"

	"github.com/footprintai/containarium/internal/client"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

var crewCmd = &cobra.Command{
	Use:   "crew",
	Short: "Run crews — collaborating sets of agent skills (Phase 3)",
	Long: `A crew is a collaborating set of skills bound to a task purpose, wired by a
topology (pipeline / orchestrator / freeform). 'crew run' validates the
topology against the members' allowed_peers, provisions each member's box under
one trace id, and returns the run.

  containarium crew list
  containarium crew get hello-crew
  containarium crew run hello-crew --input '{"q":"hi"}' --server <host>
  containarium crew status <run-id> --server <host>`,
}

func init() {
	rootCmd.AddCommand(crewCmd)
}

type crewAPI interface {
	ListCrews() ([]*pb.Crew, error)
	GetCrew(id string) (*pb.Crew, error)
	RunCrew(crewID, backendID, pool, inputJSON string) (*pb.CrewRun, error)
	GetCrewRun(id string) (*pb.CrewRun, error)
	Close() error
}

func newCrewClient() (crewAPI, error) {
	if serverAddr == "" {
		return nil, fmt.Errorf("--server is required")
	}
	if httpMode {
		return client.NewHTTPClient(serverAddr, authToken)
	}
	return client.NewGRPCClient(serverAddr, certsDir, insecure)
}
