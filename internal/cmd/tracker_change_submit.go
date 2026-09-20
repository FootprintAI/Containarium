package cmd

import (
	"fmt"

	"github.com/footprintai/containarium/internal/client"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

// tracker change submit (#1923) — publishes the calling run's committed
// workspace and opens a change request, without a push credential ever
// entering the box. See docs/architecture/agent-tracker-broker.md's
// "Submit path". This is the human/CI surface; an in-box agent reaches
// the same RPC through the platform MCP (D4), never this binary.
var trackerChangeSubmitCmd = &cobra.Command{
	Use:   "submit <username> <connection> <issue>",
	Short: "Bundle the calling run's committed workspace and open a change request",
	Long: `Bundles the calling run's committed workspace out of its box, pushes it
from a fresh temporary bare repository on the host to a daemon-chosen
branch, and opens a change request referencing issue — no push
credential ever enters the box. Requires a run-scoped token whose run
has a recorded git_source.

Example:
  containarium tracker change submit alice default 42 \
    --title "Fix the flaky retry test" \
    --description "Adds a jittered backoff." `,
	Args: cobra.ExactArgs(3),
	RunE: runTrackerChangeSubmit,
}

var (
	trackerChangeSubmitTitle       string
	trackerChangeSubmitDescription string
	trackerChangeSubmitDraft       bool
)

func init() {
	trackerChangeCmd.AddCommand(trackerChangeSubmitCmd)
	trackerChangeSubmitCmd.Flags().StringVar(&trackerChangeSubmitTitle, "title", "", "Change request title (required)")
	trackerChangeSubmitCmd.Flags().StringVar(&trackerChangeSubmitDescription, "description", "", "Change request description")
	trackerChangeSubmitCmd.Flags().BoolVar(&trackerChangeSubmitDraft, "draft", false, "Open as a draft/WIP")
	_ = trackerChangeSubmitCmd.MarkFlagRequired("title")
}

func runTrackerChangeSubmit(cmd *cobra.Command, args []string) error {
	username, connection := args[0], args[1]
	issue, err := parseTrackerIssueNumber(args[2])
	if err != nil {
		return err
	}
	if serverAddr == "" {
		return fmt.Errorf("--server is required for tracker commands")
	}

	req := &pb.SubmitTrackerChangeRequest{
		Username:    username,
		Connection:  connection,
		Issue:       issue,
		Title:       trackerChangeSubmitTitle,
		Description: trackerChangeSubmitDescription,
		Draft:       trackerChangeSubmitDraft,
	}
	var change *pb.TrackerChange
	if httpMode {
		h, err := client.NewHTTPClient(serverAddr, authToken)
		if err != nil {
			return err
		}
		defer func() { _ = h.Close() }()
		if change, err = h.SubmitTrackerChange(req); err != nil {
			return err
		}
	} else {
		g, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
		if err != nil {
			return err
		}
		defer func() { _ = g.Close() }()
		if change, err = g.SubmitTrackerChange(req); err != nil {
			return err
		}
	}

	fmt.Printf("#%d opened on branch %s\n", change.GetNumber(), change.GetBranch())
	if change.GetUrl() != "" {
		fmt.Printf("url: %s\n", change.GetUrl())
	}
	return nil
}
