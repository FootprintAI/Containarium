package cmd

import (
	"fmt"
	"strings"

	"github.com/footprintai/containarium/pkg/core/crews"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

var (
	crewRunBackendID string
	crewRunPool      string
	crewRunInput     string
)

var crewListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List available crews",
	Args:    cobra.NoArgs,
	RunE:    runCrewList,
}

var crewGetCmd = &cobra.Command{
	Use:   "get <crew-id>",
	Short: "Show a crew's definition",
	Args:  cobra.ExactArgs(1),
	RunE:  runCrewGet,
}

var crewRunCmd = &cobra.Command{
	Use:   "run <crew-id>",
	Short: "Run a crew",
	Args:  cobra.ExactArgs(1),
	RunE:  runCrewRun,
}

var crewStatusCmd = &cobra.Command{
	Use:   "status <run-id>",
	Short: "Show a crew run's status",
	Args:  cobra.ExactArgs(1),
	RunE:  runCrewStatus,
}

func init() {
	crewCmd.AddCommand(crewListCmd, crewGetCmd, crewRunCmd, crewStatusCmd)
	crewRunCmd.Flags().StringVar(&crewRunBackendID, "backend-id", "", "Target backend ID")
	crewRunCmd.Flags().StringVar(&crewRunPool, "pool", "", "Target pool")
	crewRunCmd.Flags().StringVar(&crewRunInput, "input", "", "Crew input as a JSON string (defaults to {})")
}

func runCrewList(cmd *cobra.Command, args []string) error {
	var list []*pb.Crew
	if serverAddr == "" {
		list = crews.GetDefault().List() // catalog is compiled into the CLI
	} else {
		c, err := newCrewClient()
		if err != nil {
			return err
		}
		defer func() { _ = c.Close() }()
		if list, err = c.ListCrews(); err != nil {
			return err
		}
	}
	if len(list) == 0 {
		fmt.Println("No crews available.")
		return nil
	}
	fmt.Printf("%-16s %-14s %-28s %s\n", "ID", "TOPOLOGY", "SKILLS", "DESCRIPTION")
	fmt.Println(strings.Repeat("-", 90))
	for _, c := range list {
		fmt.Printf("%-16s %-14s %-28s %s\n", c.Id, crewTopologyName(c.Topology), strings.Join(c.SkillIds, ","), c.Description)
	}
	return nil
}

func runCrewGet(cmd *cobra.Command, args []string) error {
	var crew *pb.Crew
	var err error
	if serverAddr == "" {
		crew, err = crews.GetDefault().Get(args[0])
	} else {
		var c crewAPI
		if c, err = newCrewClient(); err != nil {
			return err
		}
		defer func() { _ = c.Close() }()
		crew, err = c.GetCrew(args[0])
	}
	if err != nil {
		return err
	}
	fmt.Printf("ID:          %s\n", crew.Id)
	fmt.Printf("Name:        %s\n", crew.Name)
	fmt.Printf("Description: %s\n", crew.Description)
	fmt.Printf("Topology:    %s\n", crewTopologyName(crew.Topology))
	fmt.Printf("Skills:      %s\n", strings.Join(crew.SkillIds, " -> "))
	return nil
}

func runCrewRun(cmd *cobra.Command, args []string) error {
	c, err := newCrewClient()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	fmt.Printf("Running crew %q...\n", args[0])
	run, err := c.RunCrew(args[0], crewRunBackendID, crewRunPool, crewRunInput)
	if err != nil {
		return err
	}
	printCrewRun(run)
	return nil
}

func runCrewStatus(cmd *cobra.Command, args []string) error {
	c, err := newCrewClient()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	run, err := c.GetCrewRun(args[0])
	if err != nil {
		return err
	}
	printCrewRun(run)
	return nil
}

func printCrewRun(run *pb.CrewRun) {
	fmt.Printf("\nRun:      %s\n", run.Id)
	fmt.Printf("Crew:     %s\n", run.CrewId)
	fmt.Printf("State:    %s\n", run.State)
	fmt.Printf("Trace:    %s\n", run.TraceId)
	if run.Error != "" {
		fmt.Printf("Error:    %s\n", run.Error)
	}
	if run.ArtifactJson != "" {
		fmt.Printf("Artifact: %s\n", run.ArtifactJson)
	}
}

func crewTopologyName(t pb.CrewTopology) string {
	switch t {
	case pb.CrewTopology_CREW_TOPOLOGY_PIPELINE:
		return "pipeline"
	case pb.CrewTopology_CREW_TOPOLOGY_ORCHESTRATOR:
		return "orchestrator"
	case pb.CrewTopology_CREW_TOPOLOGY_FREEFORM:
		return "freeform"
	default:
		return "unspecified"
	}
}
