package cmd

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/footprintai/containarium/internal/client"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

// Tracker issue/change read verbs (#1922) — provider-neutral reads
// through the connection registered via `tracker connect`. Gated by
// tracker:read on the token (agent runs get this scope, not
// tracker:admin — see tracker.go's doc comment). Write verbs
// (comment/claim/label) are in tracker_issue_write.go; submitting a
// change request is in tracker_change_submit.go.

var trackerIssueCmd = &cobra.Command{
	Use:   "issue",
	Short: "Read tracker issues",
}

var trackerIssueViewCmd = &cobra.Command{
	Use:   "view <username> <connection> <number>",
	Short: "Get a single issue, including its comments",
	Args:  cobra.ExactArgs(3),
	RunE:  runTrackerIssueView,
}

var trackerIssueListCmd = &cobra.Command{
	Use:   "list <username> <connection>",
	Short: "List issues, optionally filtered",
	Long: `Lists issues on the tracker the named connection points at.

Examples:
  containarium tracker issue list alice default
  containarium tracker issue list alice default --state open --label bug --label p1
  containarium tracker issue list alice default --search "crash on startup"`,
	Args: cobra.ExactArgs(2),
	RunE: runTrackerIssueList,
}

var trackerChangeCmd = &cobra.Command{
	Use:   "change",
	Short: "Read tracker change requests (pull/merge requests)",
}

var trackerChangeViewCmd = &cobra.Command{
	Use:   "view <username> <connection> <number>",
	Short: "Get a change request's state and CI verdict",
	Args:  cobra.ExactArgs(3),
	RunE:  runTrackerChangeView,
}

var (
	trackerIssueListState  string
	trackerIssueListLabels []string
	trackerIssueListSearch string
)

func init() {
	trackerCmd.AddCommand(trackerIssueCmd)
	trackerIssueCmd.AddCommand(trackerIssueViewCmd)
	trackerIssueCmd.AddCommand(trackerIssueListCmd)
	trackerIssueListCmd.Flags().StringVar(&trackerIssueListState, "state", "",
		`Filter by state: "open" or "closed". Empty matches any state.`)
	trackerIssueListCmd.Flags().StringArrayVar(&trackerIssueListLabels, "label", nil,
		`Require this label (repeat for multiple — AND semantics). `)
	trackerIssueListCmd.Flags().StringVar(&trackerIssueListSearch, "search", "",
		`Free-text search against title/body, passed through to the provider's own search (best-effort, not authoritative).`)

	trackerCmd.AddCommand(trackerChangeCmd)
	trackerChangeCmd.AddCommand(trackerChangeViewCmd)
}

// parseTrackerIssueListState maps the CLI's --state flag to the proto
// enum. Unlike --provider, empty IS a valid default here (matches any
// state) rather than an error.
func parseTrackerIssueListState(s string) (pb.TrackerIssueState, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return pb.TrackerIssueState_TRACKER_ISSUE_STATE_UNSPECIFIED, nil
	case "open":
		return pb.TrackerIssueState_TRACKER_ISSUE_STATE_OPEN, nil
	case "closed":
		return pb.TrackerIssueState_TRACKER_ISSUE_STATE_CLOSED, nil
	default:
		return pb.TrackerIssueState_TRACKER_ISSUE_STATE_UNSPECIFIED, fmt.Errorf(`--state must be "open" or "closed", got %q`, s)
	}
}

func parseTrackerIssueNumber(s string) (int64, error) {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("issue/change number must be an integer, got %q", s)
	}
	return n, nil
}

func runTrackerIssueView(cmd *cobra.Command, args []string) error {
	username, connection := args[0], args[1]
	number, err := parseTrackerIssueNumber(args[2])
	if err != nil {
		return err
	}
	if serverAddr == "" {
		return fmt.Errorf("--server is required for tracker commands")
	}

	req := &pb.GetTrackerIssueRequest{Username: username, Connection: connection, Number: number}
	var issue *pb.TrackerIssue
	if httpMode {
		h, err := client.NewHTTPClient(serverAddr, authToken)
		if err != nil {
			return err
		}
		defer func() { _ = h.Close() }()
		if issue, err = h.GetTrackerIssue(req); err != nil {
			return err
		}
	} else {
		g, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
		if err != nil {
			return err
		}
		defer func() { _ = g.Close() }()
		if issue, err = g.GetTrackerIssue(req); err != nil {
			return err
		}
	}

	printTrackerIssue(issue)
	return nil
}

// printTrackerIssue renders a single issue. Factored out from
// runTrackerIssueView so it's testable without a client.
func printTrackerIssue(issue *pb.TrackerIssue) {
	fmt.Printf("#%d %s\n", issue.GetNumber(), issue.GetTitle())
	fmt.Printf("state:    %s\n", trackerIssueStateLabel(issue.GetState()))
	assignee := issue.GetAssignee()
	if assignee == "" {
		assignee = "(unassigned)"
	}
	fmt.Printf("assignee: %s\n", assignee)
	if len(issue.GetLabels()) > 0 {
		fmt.Printf("labels:   %s\n", strings.Join(issue.GetLabels(), ", "))
	}
	if issue.GetBody() != "" {
		fmt.Printf("\n%s\n", issue.GetBody())
	}
	if len(issue.GetComments()) > 0 {
		fmt.Printf("\n--- %d comment(s) ---\n", len(issue.GetComments()))
		for _, c := range issue.GetComments() {
			when := ""
			if c.GetCreatedAt() != nil {
				when = c.GetCreatedAt().AsTime().Format("2006-01-02 15:04")
			}
			fmt.Printf("\n[%s] %s\n%s\n", when, c.GetAuthor(), c.GetBody())
		}
	}
}

func runTrackerIssueList(cmd *cobra.Command, args []string) error {
	username, connection := args[0], args[1]
	if serverAddr == "" {
		return fmt.Errorf("--server is required for tracker commands")
	}
	state, err := parseTrackerIssueListState(trackerIssueListState)
	if err != nil {
		return err
	}

	req := &pb.ListTrackerIssuesRequest{
		Username: username, Connection: connection,
		State: state, Labels: trackerIssueListLabels, Search: trackerIssueListSearch,
	}
	var issues []*pb.TrackerIssue
	if httpMode {
		h, err := client.NewHTTPClient(serverAddr, authToken)
		if err != nil {
			return err
		}
		defer func() { _ = h.Close() }()
		if issues, err = h.ListTrackerIssues(req); err != nil {
			return err
		}
	} else {
		g, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
		if err != nil {
			return err
		}
		defer func() { _ = g.Close() }()
		if issues, err = g.ListTrackerIssues(req); err != nil {
			return err
		}
	}

	if len(issues) == 0 {
		fmt.Printf("(no issues match)\n")
		return nil
	}
	fmt.Printf("%-8s %-8s %-24s %s\n", "NUMBER", "STATE", "LABELS", "TITLE")
	for _, i := range issues {
		fmt.Printf("%-8d %-8s %-24s %s\n", i.GetNumber(), trackerIssueStateLabel(i.GetState()), strings.Join(i.GetLabels(), ","), i.GetTitle())
	}
	return nil
}

func runTrackerChangeView(cmd *cobra.Command, args []string) error {
	username, connection := args[0], args[1]
	number, err := parseTrackerIssueNumber(args[2])
	if err != nil {
		return err
	}
	if serverAddr == "" {
		return fmt.Errorf("--server is required for tracker commands")
	}

	req := &pb.GetTrackerChangeRequest{Username: username, Connection: connection, Number: number}
	var change *pb.TrackerChange
	if httpMode {
		h, err := client.NewHTTPClient(serverAddr, authToken)
		if err != nil {
			return err
		}
		defer func() { _ = h.Close() }()
		if change, err = h.GetTrackerChange(req); err != nil {
			return err
		}
	} else {
		g, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
		if err != nil {
			return err
		}
		defer func() { _ = g.Close() }()
		if change, err = g.GetTrackerChange(req); err != nil {
			return err
		}
	}

	fmt.Printf("#%d\n", change.GetNumber())
	fmt.Printf("state:      %s\n", trackerIssueStateLabel(change.GetState()))
	fmt.Printf("ci verdict: %s\n", trackerCiVerdictLabel(change.GetCiVerdict()))
	if change.GetUrl() != "" {
		fmt.Printf("url:        %s\n", change.GetUrl())
	}
	return nil
}

// trackerIssueStateLabel renders TrackerIssueState without its prefix.
func trackerIssueStateLabel(s pb.TrackerIssueState) string {
	switch s {
	case pb.TrackerIssueState_TRACKER_ISSUE_STATE_OPEN:
		return "open"
	case pb.TrackerIssueState_TRACKER_ISSUE_STATE_CLOSED:
		return "closed"
	case pb.TrackerIssueState_TRACKER_ISSUE_STATE_MERGED:
		return "merged"
	default:
		return "unspecified"
	}
}

// trackerCiVerdictLabel renders TrackerCiVerdict without its prefix.
func trackerCiVerdictLabel(v pb.TrackerCiVerdict) string {
	switch v {
	case pb.TrackerCiVerdict_TRACKER_CI_VERDICT_NONE:
		return "none"
	case pb.TrackerCiVerdict_TRACKER_CI_VERDICT_PENDING:
		return "pending"
	case pb.TrackerCiVerdict_TRACKER_CI_VERDICT_SUCCESS:
		return "success"
	case pb.TrackerCiVerdict_TRACKER_CI_VERDICT_FAILED:
		return "failed"
	default:
		return "unspecified"
	}
}
