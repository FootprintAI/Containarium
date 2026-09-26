package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/footprintai/containarium/internal/client"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

// Tracker dispatch (#2022): turn routed `scope:<role>` labels into runs.
// Each tick is one DispatchTrackerIssues call — the daemon does the work
// and guarantees exactly one run per issue across restarts and
// concurrent dispatchers. This command is only the loop around it.
// Requires tracker:admin and agents:run. Not importing internal/tracker
// here is deliberate: it links pgx, which the client build must not
// (scripts/test-cli-split-deps.sh).

var trackerDispatchCmd = &cobra.Command{
	Use:   "dispatch <username> <connection> [--once | --interval 60s]",
	Short: "Start the routed skill for issues labeled scope:<role>, exactly once each",
	Long: `Poll a tracker connection and, for every open issue carrying a routed
scope:<role> label and no agent:* state label (and not gated with
agent:needs-approval), start the routed skill and label the issue
agent:queued. The run gets the issue reference, never its body.

An issue is dispatched at most once while a run for it is queued or
running, even across restarts or several dispatchers. To re-run a
finished issue, remove agent:done / agent:failed and re-add the scope
label. A scope:* label with no route gets one warning comment.

  containarium tracker dispatch alice default --once
  containarium tracker dispatch alice default --interval 60s

Requires tracker:admin and agents:run.`,
	Args: cobra.ExactArgs(2),
	RunE: runTrackerDispatch,
}

var trackerDispatchesCmd = &cobra.Command{
	Use:   "dispatches <username> <connection> [--state queued|running|done|failed]",
	Short: "List a connection's dispatches, newest first",
	Args:  cobra.ExactArgs(2),
	RunE:  runTrackerDispatches,
}

const defaultDispatchInterval = 60 * time.Second

var (
	trackerDispatchOnce     bool
	trackerDispatchInterval time.Duration
	trackerDispatchesState  string
)

func init() {
	trackerCmd.AddCommand(trackerDispatchCmd)
	trackerDispatchCmd.Flags().BoolVar(&trackerDispatchOnce, "once", false, "Run one tick and exit.")
	trackerDispatchCmd.Flags().DurationVar(&trackerDispatchInterval, "interval", defaultDispatchInterval,
		"Time between ticks when looping (minimum 1s). Stops on Ctrl-C / SIGTERM.")

	trackerCmd.AddCommand(trackerDispatchesCmd)
	trackerDispatchesCmd.Flags().StringVar(&trackerDispatchesState, "state", "",
		"Only list dispatches in this state: queued, running, done or failed.")
}

// trackerDispatchClient is the slice of the typed client these commands
// need; both transports satisfy it.
type trackerDispatchClient interface {
	DispatchTrackerIssues(username, connection string) (*pb.DispatchTrackerIssuesResponse, error)
	ListTrackerDispatches(username, connection string, state pb.TrackerDispatchState) ([]*pb.TrackerDispatch, error)
	Close() error
}

var (
	_ trackerDispatchClient = (*client.GRPCClient)(nil)
	_ trackerDispatchClient = (*client.HTTPClient)(nil)
)

func newTrackerDispatchClient() (trackerDispatchClient, error) {
	if serverAddr == "" {
		return nil, fmt.Errorf("--server is required for tracker commands (the daemon runs the dispatch)")
	}
	if httpMode {
		return client.NewHTTPClient(serverAddr, authToken)
	}
	return client.NewGRPCClient(serverAddr, certsDir, insecure)
}

// validateDispatchFlags rejects --once combined with an explicit
// --interval, and an interval short enough to hammer the forge.
func validateDispatchFlags(once bool, interval time.Duration, intervalChanged bool) error {
	if once && intervalChanged {
		return fmt.Errorf("--once and --interval are mutually exclusive")
	}
	if !once && interval < time.Second {
		return fmt.Errorf("--interval must be at least 1s, got %s", interval)
	}
	return nil
}

// parseDispatchStateFlag maps --state onto the proto enum; empty means
// every state.
func parseDispatchStateFlag(s string) (pb.TrackerDispatchState, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_UNSPECIFIED, nil
	}
	v, ok := pb.TrackerDispatchState_value["TRACKER_DISPATCH_STATE_"+strings.ToUpper(s)]
	if !ok || v == int32(pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_UNSPECIFIED) {
		return 0, fmt.Errorf("--state %q is invalid: use queued, running, done or failed", s)
	}
	return pb.TrackerDispatchState(v), nil
}

// dispatchStateName is the lowercase short form printed in tables.
func dispatchStateName(s pb.TrackerDispatchState) string {
	return strings.ToLower(strings.TrimPrefix(s.String(), "TRACKER_DISPATCH_STATE_"))
}

// runDispatchLoop runs tick once (returning its error) or every
// interval until ctx is cancelled. In loop mode a failed tick is logged
// and the loop carries on: a transient forge or network error must not
// stop a long-running dispatcher, and the daemon's durable rows make a
// retried tick safe.
func runDispatchLoop(ctx context.Context, once bool, interval time.Duration, tick func() error, logf func(string, ...any)) error {
	if once {
		return tick()
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if err := tick(); err != nil {
			logf("dispatch tick failed: %v", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

func runTrackerDispatch(cmd *cobra.Command, args []string) error {
	username, connection := args[0], args[1]
	intervalChanged := cmd.Flags().Changed("interval")
	if err := validateDispatchFlags(trackerDispatchOnce, trackerDispatchInterval, intervalChanged); err != nil {
		return err
	}
	c, err := newTrackerDispatchClient()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	parent := cmd.Context()
	if parent == nil {
		parent = context.Background()
	}
	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stop()

	tick := func() error {
		resp, err := c.DispatchTrackerIssues(username, connection)
		if err != nil {
			return err
		}
		printDispatchTick(resp)
		return nil
	}
	logf := func(format string, a ...any) { fmt.Fprintf(os.Stderr, format+"\n", a...) }
	return runDispatchLoop(ctx, trackerDispatchOnce, trackerDispatchInterval, tick, logf)
}

func runTrackerDispatches(cmd *cobra.Command, args []string) error {
	username, connection := args[0], args[1]
	state, err := parseDispatchStateFlag(trackerDispatchesState)
	if err != nil {
		return err
	}
	c, err := newTrackerDispatchClient()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	rows, err := c.ListTrackerDispatches(username, connection, state)
	if err != nil {
		return err
	}
	printTrackerDispatches(username, connection, rows)
	return nil
}

func printDispatchTick(resp *pb.DispatchTrackerIssuesResponse) {
	ts := time.Now().Format(time.RFC3339)
	for _, d := range resp.GetStarted() {
		fmt.Printf("%s started #%d %s%s -> %s (run %s)\n", ts, d.GetIssueNumber(), scopeLabelPrefix, d.GetScope(), d.GetSkillId(), d.GetRunId())
	}
	for _, d := range resp.GetFailed() {
		fmt.Printf("%s failed  #%d %s%s -> %s: %s\n", ts, d.GetIssueNumber(), scopeLabelPrefix, d.GetScope(), d.GetSkillId(), d.GetFailureReason())
	}
	for _, d := range resp.GetTimedOut() {
		cause := strings.ToLower(strings.TrimPrefix(d.GetFailure().String(), "TRACKER_DISPATCH_FAILURE_"))
		fmt.Printf("%s swept   #%d %s%s -> %s (run %s) %s: %s\n", ts, d.GetIssueNumber(), scopeLabelPrefix, d.GetScope(), d.GetSkillId(),
			d.GetRunId(), cause, d.GetFailureReason())
	}
	fmt.Printf("%s tick: started=%d failed=%d timed_out=%d skipped approval=%d active=%d unrouted=%d\n", ts,
		len(resp.GetStarted()), len(resp.GetFailed()), len(resp.GetTimedOut()),
		resp.GetSkippedNeedsApproval(), resp.GetSkippedActive(), resp.GetSkippedUnrouted())
}

func printTrackerDispatches(username, connection string, rows []*pb.TrackerDispatch) {
	if len(rows) == 0 {
		fmt.Printf("(no dispatches on %s/%s)\n", username, connection)
		return
	}
	fmt.Printf("%-8s %-8s %-24s %-24s %-38s %s\n", "ISSUE", "STATE", "LABEL", "SKILL", "RUN", "CREATED / REASON")
	for _, d := range rows {
		detail := ""
		if d.GetCreatedAt() != nil {
			detail = d.GetCreatedAt().AsTime().Format(time.RFC3339)
		}
		if r := d.GetFailureReason(); r != "" {
			detail += "  " + r
		}
		fmt.Printf("%-8s %-8s %-24s %-24s %-38s %s\n", fmt.Sprintf("#%d", d.GetIssueNumber()), dispatchStateName(d.GetState()),
			scopeLabelPrefix+d.GetScope(), d.GetSkillId(), d.GetRunId(), strings.TrimSpace(detail))
	}
}
