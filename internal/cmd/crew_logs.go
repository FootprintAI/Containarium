package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/footprintai/containarium/internal/runlog"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

var (
	crewLogsSkill  string
	crewLogsFollow bool
)

var crewLogsCmd = &cobra.Command{
	Use:   "logs <run-id>",
	Short: "Print a run's journal (crew or single-skill run)",
	Long: `Print the journal a run's agent writes on its member box: status, assistant,
tool_use, tool_result and error lines, one JSON object per line.

--skill picks the member (default: the only member of a skill run, or the
crew's entry skill). --follow keeps reading until the journal's "run ended"
line; a dropped connection loses nothing, since every read resumes at the
byte offset the previous one ended at.

Examples:
  containarium crew logs <run-id> --server <host>
  containarium crew logs <run-id> --skill hello-agent --follow --server <host>`,
	Args: cobra.ExactArgs(1),
	RunE: runCrewLogs,
}

func init() {
	crewCmd.AddCommand(crewLogsCmd)
	crewLogsCmd.Flags().StringVar(&crewLogsSkill, "skill", "", "Member skill whose journal to read (default: the only member, or the crew's entry skill)")
	crewLogsCmd.Flags().BoolVarP(&crewLogsFollow, "follow", "f", false, "Keep reading until the run ends")
}

func runCrewLogs(cmd *cobra.Command, args []string) error {
	c, err := newCrewClient()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	return crewLogs(cmd, c, args[0], crewLogsSkill, crewLogsFollow, os.Stdout)
}

// crewLogs copies the run's journal to w through the shared runlog function
// the MCP crew_logs tool also uses.
func crewLogs(cmd *cobra.Command, t runlog.Tailer, runID, skillID string, follow bool, w io.Writer) error {
	end, err := runlog.Copy(cmd.Context(), t, &pb.TailRunLogRequest{RunId: runID, SkillId: skillID}, w, follow)
	if err != nil {
		return fmt.Errorf("%w (read up to byte %d)", err, end)
	}
	return nil
}
