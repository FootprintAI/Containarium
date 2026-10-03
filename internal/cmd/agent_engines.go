package cmd

import (
	"fmt"
	"io"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/footprintai/containarium/internal/agentengine"
	"github.com/footprintai/containarium/internal/gatewayprovider"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

var agentEnginesJSONOut bool

var agentEnginesCmd = &cobra.Command{
	Use:   "engines",
	Short: "Report which agent engines this deployment can run, and why not",
	Long: `Reports, for each agent engine, whether a skill naming it would be
refused right now — the same check RunAgentSkill's refusal enforces, read
only. No live model call, no bundle inspection: computed from the keys this
daemon already holds.`,
	Args: cobra.NoArgs,
	RunE: runAgentEngines,
}

func init() {
	agentCmd.AddCommand(agentEnginesCmd)
	agentEnginesCmd.Flags().BoolVar(&agentEnginesJSONOut, "json", false, "Print the raw ListAgentEnginesResponse as JSON")
}

func runAgentEngines(cmd *cobra.Command, _ []string) error {
	if serverAddr == "" {
		return fmt.Errorf("--server is required: readiness is daemon state, there is no offline answer")
	}
	c, err := newAgentClient()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	resp, err := c.ListAgentEngines()
	if err != nil {
		return err
	}
	return renderAgentEngines(cmd.OutOrStdout(), resp, agentEnginesJSONOut)
}

// renderAgentEngines is runAgentEngines' output, split out so it is testable
// without a daemon: the fetch above is the only part that needs one.
func renderAgentEngines(w io.Writer, resp *pb.ListAgentEnginesResponse, asJSON bool) error {
	if asJSON {
		data, err := protojson.MarshalOptions{Indent: "  "}.Marshal(resp)
		if err != nil {
			return fmt.Errorf("marshal response: %w", err)
		}
		_, err = fmt.Fprintln(w, string(data))
		return err
	}

	owner := resp.GetKeyOwner()
	if owner == "" {
		owner = "(global — admin view, or direct mode)"
	}
	fmt.Fprintf(w, "Key owner: %s\n\n", owner)
	fmt.Fprintf(w, "%-8s %-10s %-20s %-12s %-8s %-20s %s\n", "ENGINE", "PROVIDER", "READY", "SOURCE", "DEFAULT", "SKILLS", "REASON")
	fmt.Fprintln(w, strings.Repeat("-", 110))
	for _, e := range resp.GetEngines() {
		provider, _ := gatewayprovider.Name(e.GetProvider())
		skills := strings.Join(e.GetSkillIds(), ",")
		if skills == "" {
			skills = "-"
		}
		fmt.Fprintf(w, "%-8s %-10s %-20s %-12s %-8v %-20s %s\n",
			agentengine.EnvValue(e.GetEngine()),
			provider,
			trimEnumPrefix(e.GetReadiness().String(), "AGENT_ENGINE_READINESS_"),
			trimEnumPrefix(e.GetSource().String(), "AGENT_CREDENTIAL_SOURCE_"),
			e.GetIsDefault(),
			skills,
			e.GetReason(),
		)
	}
	return nil
}

// trimEnumPrefix strips a proto enum's generated String() prefix, e.g.
// "AGENT_ENGINE_READINESS_NOT_READY" -> "NOT_READY". Falls back to the full
// name for the zero/unspecified value, which has no suffix worth showing
// alone (it never appears in a real row).
func trimEnumPrefix(s, prefix string) string {
	if trimmed := strings.TrimPrefix(s, prefix); trimmed != s && trimmed != "" {
		return trimmed
	}
	return s
}
