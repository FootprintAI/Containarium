package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/footprintai/containarium/pkg/core/crews"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

var (
	crewRunBackendID         string
	crewRunPool              string
	crewRunInput             string
	crewRunGitSource         string
	crewRunGitRef            string
	crewRunGitCredentialFile string
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
	Long: `Provision every member's box (scoped token + per-box allowed_peers policy),
start them in serve mode, and drive the crew's topology over A2A.

--git-source/--git-ref (#1554) fetch the SAME repo+ref into EVERY member's
own per-run workspace before the crew is driven — the shared codebase
between crew members is git at a pinned SHA, not a shared filesystem.

Examples:
  containarium crew run hello-crew --input '{"q":"hi"}' --server <host>
  containarium crew run freeform-crew --git-source https://github.com/org/repo     --git-ref main --server <host>`,
	Args: cobra.ExactArgs(1),
	RunE: runCrewRun,
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
	crewRunCmd.Flags().StringVar(&crewRunGitSource, "git-source", "",
		"Git clone URL fetched into EVERY member's own per-run workspace before the crew is driven (e.g. https://github.com/org/repo). Empty = no fetch.")
	crewRunCmd.Flags().StringVar(&crewRunGitRef, "git-ref", "",
		"Exact ref to check out for --git-source: full SHA (preferred), branch, tag, or refs/pull/N/merge. Empty = the remote's default branch.")
	crewRunCmd.Flags().StringVar(&crewRunGitCredentialFile, "git-credential-file", "",
		"Path to a file holding a bearer token for a private --git-source. Used daemon-side for each member's fetch; never written to any box's .git/config.")
}

// resolveCrewRunGitCredential reads --git-credential-file if one was
// supplied, mirroring resolveAgentRunGitCredential's handling of the same
// flag on `containarium agent run`.
func resolveCrewRunGitCredential() (string, error) {
	if crewRunGitCredentialFile == "" {
		return "", nil
	}
	// #nosec G304 -- operator-supplied path; reading it is the documented
	// purpose of --git-credential-file (same trust as reading an SSH key file).
	data, err := os.ReadFile(crewRunGitCredentialFile)
	if err != nil {
		return "", fmt.Errorf("failed to read --git-credential-file: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
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
	gitCredential, err := resolveCrewRunGitCredential()
	if err != nil {
		return err
	}

	c, err := newCrewClient()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	fmt.Printf("Running crew %q...\n", args[0])
	run, err := c.RunCrew(args[0], crewRunBackendID, crewRunPool, crewRunInput,
		crewRunGitSource, crewRunGitRef, gitCredential)
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
	if run.GetGitSource() != "" {
		// GitCommit is empty until the first member's fetch resolves one
		// (#1554) — a run still RUNNING, or one that failed before any
		// member's fetch completed, shows the source without a commit yet.
		if run.GetGitCommit() != "" {
			fmt.Printf("Git:      %s @ %s\n", run.GetGitSource(), run.GetGitCommit())
		} else {
			fmt.Printf("Git:      %s (commit not yet resolved)\n", run.GetGitSource())
		}
	}
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
