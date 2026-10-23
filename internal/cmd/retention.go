package cmd

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/footprintai/containarium/internal/client"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// `containarium retention policy|hold|mode|report` (#2875, #2876, #2877;
// slices A to C of #2576): thin clients over RetentionService. They store the
// policy, the holds and the mode, and print what a sweep would remove or did
// remove. The daemon deletes only while the mode is ENFORCE.

// retentionAPI is the slice of the typed clients these commands use.
type retentionAPI interface {
	GetRetentionPolicy() (*pb.GetRetentionPolicyResponse, error)
	SetRetentionPolicy(req *pb.SetRetentionPolicyRequest) (*pb.SetRetentionPolicyResponse, error)
	ListLegalHolds() (*pb.ListLegalHoldsResponse, error)
	SetLegalHold(req *pb.SetLegalHoldRequest) (*pb.SetLegalHoldResponse, error)
	ReleaseLegalHold(orgID string) (*pb.ReleaseLegalHoldResponse, error)
	GetRetentionReport(refresh bool) (*pb.GetRetentionReportResponse, error)
	GetRetentionMode() (*pb.GetRetentionModeResponse, error)
	SetRetentionMode(req *pb.SetRetentionModeRequest) (*pb.SetRetentionModeResponse, error)
}

// newRetentionAPI builds the client from the global --server/--http flags. A
// variable so tests can substitute a fake.
var newRetentionAPI = func() (retentionAPI, func(), error) {
	if serverAddr == "" {
		return nil, nil, errors.New("--server is required for retention commands")
	}
	if httpMode {
		h, err := client.NewHTTPClient(serverAddr, authToken)
		if err != nil {
			return nil, nil, err
		}
		return h, func() { _ = h.Close() }, nil
	}
	g, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
	if err != nil {
		return nil, nil, err
	}
	return g, func() { _ = g.Close() }, nil
}

// retentionClassFlags maps each per-class flag onto its class, in enum order.
var retentionClassFlags = []struct {
	flag  string
	class pb.RetentionClass
}{
	{"prompts", pb.RetentionClass_RETENTION_CLASS_PROMPTS},
	{"responses", pb.RetentionClass_RETENTION_CLASS_RESPONSES},
	{"gateway-logs", pb.RetentionClass_RETENTION_CLASS_GATEWAY_LOGS},
	{"session-transcripts", pb.RetentionClass_RETENTION_CLASS_SESSION_TRANSCRIPTS},
	{"evidence-bundles", pb.RetentionClass_RETENTION_CLASS_EVIDENCE_BUNDLES},
}

func retentionClassName(c pb.RetentionClass) string {
	for _, f := range retentionClassFlags {
		if f.class == c {
			return f.flag
		}
	}
	return c.String()
}

var retentionCmd = &cobra.Command{
	Use:   "retention",
	Short: "Retention windows per data class and legal holds per org (admin only; talks to the daemon)",
	Long: `Read and set how long each class of customer data is kept, place or
release legal holds, switch the sweeper between dry-run and enforce, and see
what a sweep would remove or did remove. The daemon starts in dry-run, where
the sweeper only counts and nothing is deleted; "retention mode set --mode
enforce" makes it delete (see docs/security/DATA-FLOW-AND-RETENTION.md).

Every command needs the admin role. A change writes an audit entry naming the
caller and is refused if that entry cannot be written. A daemon with no audit
store (no Postgres, REST disabled, or an audit store that failed to start)
accepts the change and keeps no audit entry.`,
}

var retentionPolicyCmd = &cobra.Command{Use: "policy", Short: "Read or set the retention windows"}

var retentionPolicyGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Show the window of every data class",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return withRetentionAPI(func(api retentionAPI) error {
			resp, err := api.GetRetentionPolicy()
			if err != nil {
				return err
			}
			p := resp.GetPolicy()
			out := cmd.OutOrStdout()
			for _, w := range p.GetWindows() {
				suffix := ""
				if w.GetIsDefault() {
					suffix = " (default)"
				}
				fmt.Fprintf(out, "%-20s %d days%s\n", retentionClassName(w.GetClass()), w.GetDays(), suffix)
			}
			fmt.Fprintf(out, "Policy revision %d", p.GetRevision())
			if p.GetUpdatedBy() != "" {
				fmt.Fprintf(out, ", set by %s", p.GetUpdatedBy())
			}
			_, err = fmt.Fprintln(out, "\nWindows apply when the mode is enforce (see `retention mode get` and `retention report`).")
			return err
		})
	},
}

var retentionPolicySetCmd = &cobra.Command{
	Use:   "set",
	Short: "Set the window, in days, of one or more classes (admin only)",
	Long: `Set the window of the classes given as flags; the other classes keep theirs.

Examples:
  containarium retention policy set --prompts 14 --server <host>:50051
  containarium retention policy set --gateway-logs 180 --evidence-bundles 730`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		req := &pb.SetRetentionPolicyRequest{}
		for _, f := range retentionClassFlags {
			if !cmd.Flags().Changed(f.flag) {
				continue
			}
			days, err := cmd.Flags().GetInt32(f.flag)
			if err != nil {
				return err
			}
			req.Windows = append(req.Windows, &pb.RetentionWindow{Class: f.class, Days: days})
		}
		if len(req.Windows) == 0 {
			names := make([]string, len(retentionClassFlags))
			for i, f := range retentionClassFlags {
				names[i] = "--" + f.flag
			}
			return fmt.Errorf("give at least one of %s", strings.Join(names, ", "))
		}
		return withRetentionAPI(func(api retentionAPI) error {
			resp, err := api.SetRetentionPolicy(req)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Retention policy stored: revision %d, by %s\n",
				resp.GetPolicy().GetRevision(), resp.GetPolicy().GetUpdatedBy())
			return err
		})
	},
}

var retentionReportCmd = &cobra.Command{
	Use:   "report",
	Short: "Show what a retention sweep would remove, or did remove (a read; deletes nothing itself)",
	Long: `Show, per data class and store, how many records are past the class window,
how many a legal hold keeps, how many an enforcing sweep would remove and, for
a sweep that ran in enforce mode, how many it removed.

The daemon sweeps hourly and keeps the last report; --refresh counts now. A
refresh only counts, in any mode: it never deletes.
The hash-chained audit log classes and evidence bundles are listed as "not
swept" with the slice that handles them. Admin role only.

Example:
  containarium retention report --server <host>:50051 --refresh`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		refresh, _ := cmd.Flags().GetBool("refresh")
		return withRetentionAPI(func(api retentionAPI) error {
			resp, err := api.GetRetentionReport(refresh)
			if err != nil {
				return err
			}
			return printRetentionReport(cmd.OutOrStdout(), resp.GetReport())
		})
	},
}

func retentionModeName(m pb.RetentionMode) string {
	switch m {
	case pb.RetentionMode_RETENTION_MODE_DRY_RUN:
		return "dry-run"
	case pb.RetentionMode_RETENTION_MODE_ENFORCE:
		return "enforce"
	}
	return m.String()
}

// parseRetentionMode maps the --mode flag onto the typed mode.
func parseRetentionMode(s string) (pb.RetentionMode, error) {
	switch s {
	case "dry-run":
		return pb.RetentionMode_RETENTION_MODE_DRY_RUN, nil
	case "enforce":
		return pb.RetentionMode_RETENTION_MODE_ENFORCE, nil
	}
	return pb.RetentionMode_RETENTION_MODE_UNSPECIFIED, fmt.Errorf("--mode must be enforce or dry-run, got %q", s)
}

var retentionModeCmd = &cobra.Command{Use: "mode", Short: "Read or switch dry-run and enforce"}

var retentionModeGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Show whether the sweeper counts only (dry-run) or deletes (enforce)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return withRetentionAPI(func(api retentionAPI) error {
			resp, err := api.GetRetentionMode()
			if err != nil {
				return err
			}
			st := resp.GetState()
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Retention mode: %s", retentionModeName(st.GetMode()))
			if st.GetUpdatedBy() == "" {
				_, err = fmt.Fprintln(out, " (default, never set)")
				return err
			}
			_, err = fmt.Fprintf(out, ", set by %s at %s\n", st.GetUpdatedBy(), st.GetUpdatedAt().AsTime().Format("2006-01-02T15:04:05Z"))
			return err
		})
	},
}

var retentionModeSetCmd = &cobra.Command{
	Use:   "set --mode enforce|dry-run",
	Short: "Switch the sweeper between dry-run (count only) and enforce (delete) (admin only)",
	Long: `In dry-run, the default, the sweeper counts what is past its window and
deletes nothing. In enforce, the daemon's next hourly sweep permanently deletes
the records past their class window that no legal hold keeps, in the stores
outside the hash chain (agent tasks and results, crew runs, gateway traffic).

The change writes an audit entry naming the caller and is refused if that
entry cannot be written; every enforced sweep writes one more with the
per-class counts. Check "retention report" and your legal holds first.

Example:
  containarium retention mode set --mode enforce --server <host>:50051`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		flag, _ := cmd.Flags().GetString("mode")
		mode, err := parseRetentionMode(flag)
		if err != nil {
			return err
		}
		return withRetentionAPI(func(api retentionAPI) error {
			resp, err := api.SetRetentionMode(&pb.SetRetentionModeRequest{Mode: mode})
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Retention mode set to %s by %s\n", retentionModeName(resp.GetState().GetMode()), resp.GetState().GetUpdatedBy())
			if resp.GetState().GetMode() == pb.RetentionMode_RETENTION_MODE_ENFORCE {
				_, err = fmt.Fprintln(out, "The next sweep (hourly) permanently deletes records past their class window that no legal hold keeps.")
				return err
			}
			return nil
		})
	},
}

func printRetentionReport(out io.Writer, r *pb.RetentionReport) error {
	switch {
	case r.GetEnforced():
		fmt.Fprintf(out, "Retention report (mode: %s, records past the window were deleted by this sweep)\n", retentionModeName(r.GetMode()))
	case r.GetMode() == pb.RetentionMode_RETENTION_MODE_ENFORCE:
		fmt.Fprintf(out, "Retention report (mode: %s; this count deleted nothing, the next sweep deletes the eligible records)\n", retentionModeName(r.GetMode()))
	default:
		fmt.Fprintf(out, "Retention report (mode: %s, nothing is deleted)\n", retentionModeName(r.GetMode()))
	}
	holds := "no active legal holds"
	if n := r.GetActiveHolds(); n > 0 {
		holds = fmt.Sprintf("%d active legal hold(s); records with no org count as held", n)
	}
	fmt.Fprintf(out, "Counted %s, policy revision %d, %s\n\n",
		r.GetGeneratedAt().AsTime().Format("2006-01-02T15:04:05Z"), r.GetPolicyRevision(), holds)
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	header := "CLASS\tSTORE\tWINDOW\tCUTOFF\tOLDER\tELIGIBLE\tHELD"
	if r.GetEnforced() {
		header += "\tREMOVED"
	}
	fmt.Fprintln(tw, header)
	for _, s := range r.GetStores() {
		window := fmt.Sprintf("%dd", s.GetWindowDays())
		switch s.GetStatus() {
		case pb.RetentionSweepStatus_RETENTION_SWEEP_STATUS_COUNTED:
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%d\t%d", retentionClassName(s.GetClass()), s.GetStore(), window,
				s.GetCutoff().AsTime().Format("2006-01-02T15:04:05Z"), s.GetOlderThanCutoff(), s.GetEligible(), s.GetHeld())
			if r.GetEnforced() {
				fmt.Fprintf(tw, "\t%d", s.GetRemoved())
			}
			if s.GetNote() != "" {
				fmt.Fprintf(tw, "\t%s", s.GetNote())
			}
			fmt.Fprintln(tw)
		case pb.RetentionSweepStatus_RETENTION_SWEEP_STATUS_NOT_SWEPT:
			fmt.Fprintf(tw, "%s\t%s\t%s\t-\t-\t-\t-\tnot swept: %s\n", retentionClassName(s.GetClass()), s.GetStore(), window, s.GetNote())
		default:
			fmt.Fprintf(tw, "%s\t%s\t%s\t-\t-\t-\t-\terror: %s\n", retentionClassName(s.GetClass()), s.GetStore(), window, s.GetNote())
		}
	}
	return tw.Flush()
}

var retentionHoldCmd = &cobra.Command{Use: "hold", Short: "List, place or release legal holds per org"}

var retentionHoldListCmd = &cobra.Command{
	Use:   "list",
	Short: "List the active legal holds",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return withRetentionAPI(func(api retentionAPI) error {
			resp, err := api.ListLegalHolds()
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if len(resp.GetHolds()) == 0 {
				_, err = fmt.Fprintln(out, "No legal holds.")
				return err
			}
			for _, h := range resp.GetHolds() {
				fmt.Fprintf(out, "%s\tset by %s at %s\t%s\n", h.GetOrgId(), h.GetSetBy(),
					h.GetSetAt().AsTime().Format("2006-01-02T15:04:05Z"), h.GetReason())
			}
			return nil
		})
	},
}

var retentionHoldSetCmd = &cobra.Command{
	Use:   "set <org-id>",
	Short: "Place a legal hold on an org (admin only; no expiry)",
	Long: `Hold every record of the org, in every class, until the hold is released.

Example:
  containarium retention hold set <org-id> --reason "<case reference>"`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		reason, _ := cmd.Flags().GetString("reason")
		return withRetentionAPI(func(api retentionAPI) error {
			resp, err := api.SetLegalHold(&pb.SetLegalHoldRequest{OrgId: args[0], Reason: reason})
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Legal hold placed on %s by %s\n", resp.GetHold().GetOrgId(), resp.GetHold().GetSetBy())
			return err
		})
	},
}

var retentionHoldReleaseCmd = &cobra.Command{
	Use:   "release <org-id>",
	Short: "Release an org's legal hold (admin only)",
	Long: `Release the hold. The org's records past their window become eligible on the
next sweep, with no grace period; in enforce mode that sweep deletes them.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return withRetentionAPI(func(api retentionAPI) error {
			resp, err := api.ReleaseLegalHold(args[0])
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Legal hold on %s released\n", resp.GetHold().GetOrgId())
			return err
		})
	},
}

func withRetentionAPI(fn func(retentionAPI) error) error {
	api, done, err := newRetentionAPI()
	if err != nil {
		return err
	}
	defer done()
	return fn(api)
}

func init() {
	for _, f := range retentionClassFlags {
		retentionPolicySetCmd.Flags().Int32(f.flag, 0, "days to keep "+f.flag+" (1 to 36500)")
	}
	retentionReportCmd.Flags().Bool("refresh", false, "count now instead of showing the daemon's last hourly report")
	retentionHoldSetCmd.Flags().String("reason", "", "why the hold exists, such as a case reference (required)")
	_ = retentionHoldSetCmd.MarkFlagRequired("reason")
	retentionPolicyCmd.AddCommand(retentionPolicyGetCmd, retentionPolicySetCmd)
	retentionHoldCmd.AddCommand(retentionHoldListCmd, retentionHoldSetCmd, retentionHoldReleaseCmd)
	retentionModeSetCmd.Flags().String("mode", "", "enforce or dry-run (required)")
	retentionModeCmd.AddCommand(retentionModeGetCmd, retentionModeSetCmd)
	retentionCmd.AddCommand(retentionPolicyCmd, retentionHoldCmd, retentionModeCmd, retentionReportCmd)
	rootCmd.AddCommand(retentionCmd)
}
