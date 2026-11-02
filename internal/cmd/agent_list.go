package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/footprintai/containarium/pkg/core/skills"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

var agentListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List available agent skills",
	Long: `List built-in agent skills. Reads the embedded catalog when no --server
is given, or the daemon's catalog when --server is set.`,
	Args: cobra.NoArgs,
	RunE: runAgentList,
}

func init() {
	agentCmd.AddCommand(agentListCmd)
}

func runAgentList(cmd *cobra.Command, args []string) error {
	var list []*pb.AgentSkill
	if serverAddr == "" {
		// Offline: the catalog is compiled into the CLI binary too.
		list = skills.GetDefault().List()
	} else {
		c, err := newAgentClient()
		if err != nil {
			return err
		}
		defer func() { _ = c.Close() }()
		list, err = c.ListAgentSkills()
		if err != nil {
			return err
		}
	}

	if len(list) == 0 {
		fmt.Println("No agent skills available.")
		return nil
	}
	printAgentSkillList(os.Stdout, list)
	return nil
}

// printAgentSkillList renders the `agent list` table. Skill ids, boxes and
// descriptions come from the daemon's catalog, which tenants can extend
// (#3453).
func printAgentSkillList(w io.Writer, list []*pb.AgentSkill) {
	fmt.Fprintf(w, "%-16s %-16s %-24s %s\n", "ID", "BOX", "SCOPES", "DESCRIPTION")
	fmt.Fprintln(w, strings.Repeat("-", 90))
	for _, s := range list {
		fmt.Fprintf(w, "%-16s %-16s %-24s %s\n",
			escapeControl(s.Id), escapeControl(s.GetRecipeId()), escapeControl(strings.Join(s.AllowedScopes, ",")), escapeControl(s.Description))
	}
}
