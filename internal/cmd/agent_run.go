package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var (
	agentRunBackendID         string
	agentRunPool              string
	agentRunInput             string
	agentRunGitSource         string
	agentRunGitRef            string
	agentRunGitCredentialFile string
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
  containarium agent run hello-agent --input '{"q":"hi"}' --server <host>
  containarium agent run code-review --git-source https://github.com/org/repo \
    --git-ref main --server <host>`,
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
	agentRunCmd.Flags().StringVar(&agentRunGitSource, "git-source", "",
		"Git clone URL fetched into the run's workspace before the agent starts (e.g. https://github.com/org/repo). Empty = no fetch.")
	agentRunCmd.Flags().StringVar(&agentRunGitRef, "git-ref", "",
		"Exact ref to check out for --git-source: full SHA (preferred), branch, tag, or refs/pull/N/merge. Empty = the remote's default branch.")
	agentRunCmd.Flags().StringVar(&agentRunGitCredentialFile, "git-credential-file", "",
		"Path to a file holding a bearer token for a private --git-source. Used daemon-side for one fetch; never written to the box's .git/config.")
}

// resolveAgentRunGitCredential reads --git-credential-file if one was
// supplied, mirroring resolveGitSourceOpts's handling of the same flag on
// `containarium create`.
func resolveAgentRunGitCredential() (string, error) {
	if agentRunGitCredentialFile == "" {
		return "", nil
	}
	// #nosec G304 -- operator-supplied path; reading it is the documented
	// purpose of --git-credential-file (same trust as reading an SSH key file).
	data, err := os.ReadFile(agentRunGitCredentialFile)
	if err != nil {
		return "", fmt.Errorf("failed to read --git-credential-file: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
}

func runAgentRun(cmd *cobra.Command, args []string) error {
	skillID := args[0]

	gitCredential, err := resolveAgentRunGitCredential()
	if err != nil {
		return err
	}

	c, err := newAgentClient()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	fmt.Printf("Running agent skill %q...\n", skillID)
	resp, err := c.RunAgentSkill(skillID, agentRunBackendID, agentRunPool, agentRunInput,
		agentRunGitSource, agentRunGitRef, gitCredential)
	if err != nil {
		return err
	}

	if resp.Container != nil {
		fmt.Printf("\n✓ box ready: %s (%s)\n", resp.Container.Name, resp.Container.State)
	}
	if resp.GitCommit != "" {
		fmt.Printf("Git:       %s @ %s\n", agentRunGitSource, resp.GitCommit)
		fmt.Printf("Workspace: %s\n", resp.WorkspacePath)
	}
	if resp.ArtifactJson != "" {
		fmt.Printf("\nArtifact:\n%s\n", resp.ArtifactJson)
	} else {
		fmt.Println("\n(no artifact — the in-box agent loop is a Phase 0 seam; see docs/AGENT-SKILLS-QUICKSTART.md)")
	}
	return nil
}
