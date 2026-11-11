package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/client"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

// `containarium code sweep-checkouts` (#3296) runs the daemon's per-run
// checkout sweep once on one box, through SweepBoxRunCheckouts: the same sweep
// the daemon runs hourly and after a run ends.

var (
	codeSweepDryRun bool
	codeSweepAll    bool
)

var codeSweepCheckoutsCmd = &cobra.Command{
	Use:   "sweep-checkouts <box>",
	Short: "Remove a box's stale per-run checkouts of platform runs",
	Long: `Run the daemon's per-run checkout sweep once on a box (#3296).

A platform-started run clones into a directory of its own directly under a box
user's ~/work, named <repo>-run-<8 hex>. The sweep removes those directories,
in the owner's and the run user's ~/work, whose newest modification is older
than the daemon's --run-checkout-max-age (default 7 days), that no process has
as its working directory and that are not a live run's. Symlinks are never
followed or removed, and nothing whose name does not match is touched: your own
~/work/<repo> checkout is never considered. The daemon also runs this sweep
hourly and after a run is stopped.

--dry-run prints exactly what a real sweep would remove and removes nothing.
--all also prints the matching entries that are kept, with the reason.

Examples:
  containarium code sweep-checkouts alice --dry-run --server <host>
  containarium code sweep-checkouts alice --server <host>`,
	Args: cobra.ExactArgs(1),
	RunE: runCodeSweepCheckouts,
}

func init() {
	codeCmd.AddCommand(codeSweepCheckoutsCmd)
	codeSweepCheckoutsCmd.Flags().BoolVar(&codeSweepDryRun, "dry-run", false, "List what would be removed; remove nothing")
	codeSweepCheckoutsCmd.Flags().BoolVar(&codeSweepAll, "all", false, "Also list the matching entries that are kept, with the reason")
}

// boxCheckoutSweeper is what the command needs from a daemon client.
type boxCheckoutSweeper interface {
	SweepBoxRunCheckouts(req *pb.SweepBoxRunCheckoutsRequest) (*pb.SweepBoxRunCheckoutsResponse, error)
}

func runCodeSweepCheckouts(cmd *cobra.Command, args []string) error {
	if err := validateBoxName(args[0]); err != nil {
		return err
	}
	if serverAddr == "" {
		return fmt.Errorf("--server is required")
	}
	var c interface {
		boxCheckoutSweeper
		Close() error
	}
	var err error
	if httpMode {
		c, err = client.NewHTTPClient(serverAddr, authToken)
	} else {
		c, err = client.NewGRPCClient(serverAddr, certsDir, insecure)
	}
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	return codeSweepCheckouts(c, args[0], codeSweepDryRun, codeSweepAll, os.Stdout)
}

func codeSweepCheckouts(c boxCheckoutSweeper, box string, dryRun, all bool, w io.Writer) error {
	resp, err := c.SweepBoxRunCheckouts(&pb.SweepBoxRunCheckoutsRequest{Username: box, DryRun: dryRun})
	if isUnimplemented(err) {
		return fmt.Errorf("this daemon does not support the run checkout sweep (SweepBoxRunCheckouts); upgrade it")
	}
	if err != nil {
		return fmt.Errorf("sweep run checkouts on %s: %w", box, err)
	}
	_, err = io.WriteString(w, renderCheckoutSweep(box, resp, dryRun, all))
	return err
}

// checkoutKeptReason is the CLI wording of a kept disposition.
func checkoutKeptReason(d pb.BoxRunCheckoutDisposition) string {
	switch d {
	case pb.BoxRunCheckoutDisposition_BOX_RUN_CHECKOUT_DISPOSITION_KEPT_RECENT:
		return "kept: recent"
	case pb.BoxRunCheckoutDisposition_BOX_RUN_CHECKOUT_DISPOSITION_KEPT_LIVE_RUN:
		return "kept: may be a live run's"
	case pb.BoxRunCheckoutDisposition_BOX_RUN_CHECKOUT_DISPOSITION_KEPT_IN_USE:
		return "kept: a process is in it"
	case pb.BoxRunCheckoutDisposition_BOX_RUN_CHECKOUT_DISPOSITION_KEPT_SYMLINK:
		return "kept: symlink"
	case pb.BoxRunCheckoutDisposition_BOX_RUN_CHECKOUT_DISPOSITION_KEPT_NOT_DIRECTORY:
		return "kept: not a directory"
	case pb.BoxRunCheckoutDisposition_BOX_RUN_CHECKOUT_DISPOSITION_KEPT_CHANGED:
		return "kept: changed during the sweep"
	case pb.BoxRunCheckoutDisposition_BOX_RUN_CHECKOUT_DISPOSITION_REMOVE_FAILED:
		return "removal failed"
	}
	return "kept"
}

// renderCheckoutSweep prints the removal set (REMOVED, or WOULD_REMOVE on a
// dry run) and, with all, the kept entries too. Failures are always printed.
func renderCheckoutSweep(box string, resp *pb.SweepBoxRunCheckoutsResponse, dryRun, all bool) string {
	var b strings.Builder
	if !resp.GetPlatformRuns() {
		fmt.Fprintf(&b, "%s: no platform-started run on this box; nothing is swept\n", box)
		return b.String()
	}
	verb, target := "Removed", pb.BoxRunCheckoutDisposition_BOX_RUN_CHECKOUT_DISPOSITION_REMOVED
	if dryRun {
		verb, target = "Would remove", pb.BoxRunCheckoutDisposition_BOX_RUN_CHECKOUT_DISPOSITION_WOULD_REMOVE
	}
	line := func(c *pb.BoxRunCheckout, note string) {
		mod := "-"
		if c.GetNewestModification() != nil {
			mod = c.GetNewestModification().AsTime().UTC().Format(time.RFC3339)
		}
		fmt.Fprintf(&b, "  %s:~/work/%s  %s  modified %s", c.GetUser(), c.GetName(), humanBytes(c.GetSizeBytes()), mod)
		if note != "" {
			fmt.Fprintf(&b, "  (%s)", note)
		}
		b.WriteString("\n")
	}
	var n int
	var total int64
	for _, c := range resp.GetCheckouts() {
		if c.GetDisposition() == target {
			n++
			total += c.GetSizeBytes()
		}
	}
	fmt.Fprintf(&b, "%s %d per-run checkout(s) on %s, %s (older than %s):\n", verb, n, box, humanBytes(total), resp.GetMaxAge().AsDuration())
	for _, c := range resp.GetCheckouts() {
		if c.GetDisposition() == target {
			line(c, "")
		}
	}
	for _, c := range resp.GetCheckouts() {
		d := c.GetDisposition()
		if d == target {
			continue
		}
		if all || d == pb.BoxRunCheckoutDisposition_BOX_RUN_CHECKOUT_DISPOSITION_REMOVE_FAILED {
			line(c, checkoutKeptReason(d))
		}
	}
	return b.String()
}
