package cmd

import (
	"fmt"
	"strings"

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
	fmt.Printf("Model:         %s\n", s.Model)
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
