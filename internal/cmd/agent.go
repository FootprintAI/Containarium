package cmd

import (
	"fmt"

	"github.com/footprintai/containarium/internal/client"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Run packaged agent skills (Phase 0: agent-as-a-box)",
	Long: `An agent skill is a packaged, runnable agent: a box (a recipe) plus a
typed manifest (system prompt, allowed scopes, allowed peers). 'agent run'
provisions the skill's box, mints a token scoped to exactly the skill's
allowed_scopes, and seeds the prompt/token/input into the box.

  containarium agent list
  containarium agent get hello-agent
  containarium agent run hello-agent --input '{"q":"hi"}' --server <host>`,
}

func init() {
	rootCmd.AddCommand(agentCmd)
}

// agentAPI is the subset of the typed client used by agent commands. Both the
// gRPC and HTTP clients satisfy it, so commands dispatch on --http without
// duplicating method calls.
type agentAPI interface {
	ListAgentSkills() ([]*pb.AgentSkill, error)
	GetAgentSkill(id string) (*pb.AgentSkill, error)
	RunAgentSkill(skillID, backendID, pool, inputJSON string) (*pb.RunAgentSkillResponse, error)
	SendAgentTask(fromSkillID, toPeerID, inputJSON string) (*pb.AgentArtifact, error)
	Close() error
}

// newAgentClient returns an agent-capable client for the configured server.
func newAgentClient() (agentAPI, error) {
	if serverAddr == "" {
		return nil, fmt.Errorf("--server is required")
	}
	if httpMode {
		return client.NewHTTPClient(serverAddr, authToken)
	}
	return client.NewGRPCClient(serverAddr, certsDir, insecure)
}
