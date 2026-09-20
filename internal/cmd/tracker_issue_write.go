package cmd

import (
	"fmt"
	"time"

	"github.com/footprintai/containarium/internal/client"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

// Tracker issue write verbs (#1922). tracker_issue.go's own doc comment
// said these "land in a follow-up story" — the typed client
// (internal/client/{grpc,http}.go) and the platform MCP tools
// (internal/mcp/tracker_tools.go) both got them; this CLI surface did
// not, until now. Gated by tracker:write on the token, same as the RPCs
// themselves.

var trackerIssueCommentCmd = &cobra.Command{
	Use:   "comment <username> <connection> <number> --body <text>",
	Short: "Post a stamped, sanitized comment on an issue or change request",
	Args:  cobra.ExactArgs(3),
	RunE:  runTrackerIssueComment,
}

var trackerIssueClaimCmd = &cobra.Command{
	Use:   "claim <username> <connection> <number>",
	Short: "Claim an issue for the calling run",
	Long: `Posts a stamped claim comment and assigns the calling run if the issue is
unassigned, unless a live or recent claim from a different run already
holds it. Idempotent for the same run.

Example:
  containarium tracker issue claim alice default 42
  containarium tracker issue claim alice default 42 --stale-after 4h`,
	Args: cobra.ExactArgs(3),
	RunE: runTrackerIssueClaim,
}

var trackerIssueLabelCmd = &cobra.Command{
	Use:   "label <username> <connection> <number>",
	Short: "Add and/or remove labels on an issue",
	Long: `Example:
  containarium tracker issue label alice default 42 --add triaged --remove needs-triage`,
	Args: cobra.ExactArgs(3),
	RunE: runTrackerIssueLabel,
}

var (
	trackerIssueCommentBody string
	trackerIssueClaimStale  time.Duration
	trackerIssueLabelAdd    []string
	trackerIssueLabelRemove []string
)

func init() {
	trackerIssueCmd.AddCommand(trackerIssueCommentCmd)
	trackerIssueCommentCmd.Flags().StringVar(&trackerIssueCommentBody, "body", "", "Comment text (required)")
	_ = trackerIssueCommentCmd.MarkFlagRequired("body")

	trackerIssueCmd.AddCommand(trackerIssueClaimCmd)
	trackerIssueClaimCmd.Flags().DurationVar(&trackerIssueClaimStale, "stale-after", 0,
		"How long a claim from an unconfirmed run is still honored before being takeable. 0 uses the daemon's default (2 hours).")

	trackerIssueCmd.AddCommand(trackerIssueLabelCmd)
	trackerIssueLabelCmd.Flags().StringArrayVar(&trackerIssueLabelAdd, "add", nil, "Label to add (repeat for multiple)")
	trackerIssueLabelCmd.Flags().StringArrayVar(&trackerIssueLabelRemove, "remove", nil, "Label to remove (repeat for multiple)")
}

func runTrackerIssueComment(cmd *cobra.Command, args []string) error {
	username, connection := args[0], args[1]
	number, err := parseTrackerIssueNumber(args[2])
	if err != nil {
		return err
	}
	if serverAddr == "" {
		return fmt.Errorf("--server is required for tracker commands")
	}

	req := &pb.CommentOnTrackerIssueRequest{Username: username, Connection: connection, Number: number, Body: trackerIssueCommentBody}
	var comment *pb.TrackerComment
	if httpMode {
		h, err := client.NewHTTPClient(serverAddr, authToken)
		if err != nil {
			return err
		}
		defer func() { _ = h.Close() }()
		if comment, err = h.CommentOnTrackerIssue(req); err != nil {
			return err
		}
	} else {
		g, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
		if err != nil {
			return err
		}
		defer func() { _ = g.Close() }()
		if comment, err = g.CommentOnTrackerIssue(req); err != nil {
			return err
		}
	}

	fmt.Printf("comment posted by %s\n", comment.GetAuthor())
	return nil
}

func runTrackerIssueClaim(cmd *cobra.Command, args []string) error {
	username, connection := args[0], args[1]
	number, err := parseTrackerIssueNumber(args[2])
	if err != nil {
		return err
	}
	if serverAddr == "" {
		return fmt.Errorf("--server is required for tracker commands")
	}

	req := &pb.ClaimTrackerIssueRequest{
		Username: username, Connection: connection, Number: number,
		StaleAfterSeconds: int64(trackerIssueClaimStale.Seconds()),
	}
	var result *pb.ClaimTrackerIssueResponse
	if httpMode {
		h, err := client.NewHTTPClient(serverAddr, authToken)
		if err != nil {
			return err
		}
		defer func() { _ = h.Close() }()
		if result, err = h.ClaimTrackerIssue(req); err != nil {
			return err
		}
	} else {
		g, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
		if err != nil {
			return err
		}
		defer func() { _ = g.Close() }()
		if result, err = g.ClaimTrackerIssue(req); err != nil {
			return err
		}
	}

	if !result.GetClaimed() {
		fmt.Printf("not claimed — already held by run %s\n", result.GetAlreadyClaimedByRunId())
		return nil
	}
	if result.GetAssigned() {
		fmt.Println("claimed and assigned")
	} else {
		fmt.Println("claimed (issue already had an assignee)")
	}
	return nil
}

func runTrackerIssueLabel(cmd *cobra.Command, args []string) error {
	username, connection := args[0], args[1]
	number, err := parseTrackerIssueNumber(args[2])
	if err != nil {
		return err
	}
	if serverAddr == "" {
		return fmt.Errorf("--server is required for tracker commands")
	}
	if len(trackerIssueLabelAdd) == 0 && len(trackerIssueLabelRemove) == 0 {
		return fmt.Errorf("at least one of --add or --remove is required")
	}

	req := &pb.SetTrackerIssueLabelsRequest{
		Username: username, Connection: connection, Number: number,
		AddLabels: trackerIssueLabelAdd, RemoveLabels: trackerIssueLabelRemove,
	}
	var msg string
	if httpMode {
		h, err := client.NewHTTPClient(serverAddr, authToken)
		if err != nil {
			return err
		}
		defer func() { _ = h.Close() }()
		if msg, err = h.SetTrackerIssueLabels(req); err != nil {
			return err
		}
	} else {
		g, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
		if err != nil {
			return err
		}
		defer func() { _ = g.Close() }()
		if msg, err = g.SetTrackerIssueLabels(req); err != nil {
			return err
		}
	}

	fmt.Println(msg)
	return nil
}
