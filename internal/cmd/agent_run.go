package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	agentRunBackendID string
	agentRunPool      string
	agentRunInput     string
)

var agentRunCmd = &cobra.Command{
	Use:   "run <skill-id>",
	Short: "Run an agent skill in a box",
	Long: `Provision the skill's box, mint a token scoped to exactly the skill's
allowed_scopes, seed the system prompt + token + task input into the box, and
return the box.

Phase 0: the in-box agent loop (the agent-runtime image's job) consumes the
seed; the returned artifact is empty until that lands.

Examples:
  containarium agent run hello-agent --input '{"q":"hi"}' --server <host>`,
	Args: cobra.ExactArgs(1),
	RunE: runAgentRun,
}

func init() {
	agentCmd.AddCommand(agentRunCmd)
	agentRunCmd.Flags().StringVar(&agentRunBackendID, "backend-id", "",
		"Target backend ID (must be the local backend in v1)")
	agentRunCmd.Flags().StringVar(&agentRunPool, "pool", "",
		"Target pool (not supported in v1)")
	agentRunCmd.Flags().StringVar(&agentRunInput, "input", "",
		"Task input as a JSON string (defaults to {})")
}

func runAgentRun(cmd *cobra.Command, args []string) error {
	skillID := args[0]

	c, err := newAgentClient()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	fmt.Printf("Running agent skill %q...\n", skillID)
	resp, err := c.RunAgentSkill(skillID, agentRunBackendID, agentRunPool, agentRunInput)
	if err != nil {
		return err
	}

	if resp.Container != nil {
		fmt.Printf("\n✓ box ready: %s (%s)\n", resp.Container.Name, resp.Container.State)
	}
	if resp.ArtifactJson != "" {
		fmt.Printf("\nArtifact:\n%s\n", resp.ArtifactJson)
	} else {
		fmt.Println("\n(no artifact — the in-box agent loop is a Phase 0 seam; see docs/AGENT-SKILLS-QUICKSTART.md)")
	}
	return nil
}
