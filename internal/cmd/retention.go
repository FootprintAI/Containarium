package cmd

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/footprintai/containarium/internal/client"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// `containarium retention policy|hold` (#2875, slice A of #2576): thin clients
// over RetentionService. They store the policy and the holds; nothing is
// swept or deleted yet (the dry-run sweeper is #2876).

// retentionAPI is the slice of the typed clients these commands use.
type retentionAPI interface {
	GetRetentionPolicy() (*pb.GetRetentionPolicyResponse, error)
	SetRetentionPolicy(req *pb.SetRetentionPolicyRequest) (*pb.SetRetentionPolicyResponse, error)
	ListLegalHolds() (*pb.ListLegalHoldsResponse, error)
	SetLegalHold(req *pb.SetLegalHoldRequest) (*pb.SetLegalHoldResponse, error)
	ReleaseLegalHold(orgID string) (*pb.ReleaseLegalHoldResponse, error)
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
	Long: `Read and set how long each class of customer data is kept, and place or
release legal holds. The windows are stored only: no sweeper runs yet, so
nothing is deleted (see docs/security/DATA-FLOW-AND-RETENTION.md).

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
			_, err = fmt.Fprintln(out, "\nStored only, not enforced: no sweeper runs yet.")
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
	Long: `Release the hold. Once a sweeper runs, the org's records past their window
become eligible on its next pass, with no grace period.`,
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
		retentionPolicySetCmd.Flags().Int32(f.flag, 0, "days to keep "+f.flag+" (1 or more)")
	}
	retentionHoldSetCmd.Flags().String("reason", "", "why the hold exists, such as a case reference (required)")
	_ = retentionHoldSetCmd.MarkFlagRequired("reason")
	retentionPolicyCmd.AddCommand(retentionPolicyGetCmd, retentionPolicySetCmd)
	retentionHoldCmd.AddCommand(retentionHoldListCmd, retentionHoldSetCmd, retentionHoldReleaseCmd)
	retentionCmd.AddCommand(retentionPolicyCmd, retentionHoldCmd)
	rootCmd.AddCommand(retentionCmd)
}
