package cmd

import (
	"fmt"
	"strings"

	"github.com/footprintai/containarium/internal/agentengine"
	"github.com/footprintai/containarium/pkg/core/skills"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

var agentGetCmd = &cobra.Command{
	Use:   "get <skill-id>",
	Short: "Show an agent skill's definition",
	Args:  cobra.ExactArgs(1),
	RunE:  runAgentGet,
}

func init() {
	agentCmd.AddCommand(agentGetCmd)
}

func runAgentGet(cmd *cobra.Command, args []string) error {
	id := args[0]

	var s *pb.AgentSkill
	var err error
	if serverAddr == "" {
		s, err = skills.GetDefault().Get(id)
	} else {
		var c agentAPI
		c, err = newAgentClient()
		if err != nil {
			return err
		}
		defer func() { _ = c.Close() }()
		s, err = c.GetAgentSkill(id)
	}
	if err != nil {
		return err
	}

	fmt.Printf("ID:            %s\n", s.Id)
	fmt.Printf("Name:          %s\n", s.Name)
	fmt.Printf("Description:   %s\n", s.Description)
	fmt.Printf("Box (recipe):  %s\n", s.GetRecipeId())
	fmt.Printf("Model:         %s\n", formatModel(s))
	fmt.Printf("Engine:        %s\n", formatEngine(s.GetEngine()))
	fmt.Printf("Allowed scopes: %s\n", strings.Join(s.AllowedScopes, ", "))
	peers := "(none — leaf agent)"
	if len(s.AllowedPeers) > 0 {
		peers = strings.Join(s.AllowedPeers, ", ")
	}
	fmt.Printf("Allowed peers: %s\n", peers)
	if s.AgentCard != nil {
		fmt.Printf("Capabilities:  %s\n", strings.Join(s.AgentCard.Capabilities, ", "))
	}
	fmt.Printf("\nSystem prompt:\n%s\n", s.SystemPrompt)
	return nil
}

// formatEngine is the human-readable form of an AgentSkill's engine for `agent
// get` (#2222). AGENT_ENGINE_UNSPECIFIED gets an explanatory placeholder,
// never a blank line that could read as "nothing here" — this is the field
// whose daemon-side meaning is "the gateway's primary provider (or the box's
// own default in direct mode) decides", which a bare empty string wouldn't
// convey.
func formatEngine(e pb.AgentEngine) string {
	if name := agentengine.EnvValue(e); name != "" {
		return name
	}
	return "(unspecified — runtime/gateway default decides)"
}

// formatModel is the human-readable form of an AgentSkill's pinned model for
// `agent get` (#2229). Whether that pin is actually a live ceiling is
// decided entirely by the manifest's own Engine field (#2222's own rule:
// CONTAINARIUM_AGENT_MODEL is exported, and the gateway mints allowed_models,
// only for a NAMED-engine skill) — no daemon/gateway round trip needed to say
// so, since this is static manifest state either way. A bare model string
// with no annotation would read as "this is honored" even when it is not
// (the unspecified-engine case), which is exactly the gap #2229 was filed to
// close in the readiness surface; `agent get` is this decision's home rather
// than `agent engines` (#2223), because a model ceiling is a property of one
// skill, not of an engine — two named-engine skills on the same engine can
// pin two different models, which an engine-keyed row cannot represent.
func formatModel(s *pb.AgentSkill) string {
	if s.GetModel() == "" {
		return "(none — engine's own default)"
	}
	if s.GetEngine() == pb.AgentEngine_AGENT_ENGINE_UNSPECIFIED {
		return s.Model + " (not enforced — no engine named on this skill, #2222/#2229)"
	}
	return s.Model + " (honored — exported as this run's model; in gateway mode its token is also scoped to exactly this one, #2229)"
}
