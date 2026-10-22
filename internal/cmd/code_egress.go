package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/footprintai/containarium/internal/client"
	"github.com/footprintai/containarium/internal/codeegress"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// `containarium code egress-policy` (#2378) manages the admin-approved egress
// allowlist for the coding tool's own traffic. With no tenant argument each
// verb acts on the cluster default. set/delete are admin-only; get is for an
// admin or the tenant itself holding code-egress:read. The policy is stored
// only; nothing enforces it yet.
var codeEgressPolicyCmd = &cobra.Command{
	Use:   "egress-policy",
	Short: "Manage the coding tool's egress allowlist",
	Long: `Manage the coding tool's egress allowlist (#2370).

A tenant policy replaces the cluster default (no tenant argument). With
neither, coding runs are unrestricted. A policy with no CIDRs or domains under
--mode enforce denies every listed destination; the box's DNS resolver and
the model gateway stay allowed and are shown by get.

This is separate from network-policy: it never changes a tenant's own
NetworkPolicy. Requires --server.`,
}

var (
	codeEgressMode    string
	codeEgressCIDRs   []string
	codeEgressDomains []string
	codeEgressJSON    bool
)

var codeEgressPolicyGetCmd = &cobra.Command{
	Use:   "get [tenant]",
	Short: "Show the stored and effective policy (no tenant = cluster default)",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		return runCodeEgressGet(os.Stdout, args, codeEgressJSON)
	},
}

var codeEgressPolicySetCmd = &cobra.Command{
	Use:   "set [tenant] --mode log_only|enforce [--egress-cidr C]... [--egress-domain D]...",
	Short: "Create or replace a policy (no tenant = cluster default; admin)",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		return runCodeEgressSet(os.Stdout, args, codeEgressMode, codeEgressCIDRs, codeEgressDomains)
	},
}

var codeEgressPolicyDeleteCmd = &cobra.Command{
	Use:     "delete [tenant]",
	Aliases: []string{"rm"},
	Short:   "Remove a policy (no tenant = cluster default; admin)",
	Args:    cobra.MaximumNArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		return runCodeEgressDelete(os.Stdout, args)
	},
}

func init() {
	codeCmd.AddCommand(codeEgressPolicyCmd)
	codeEgressPolicyCmd.AddCommand(codeEgressPolicyGetCmd, codeEgressPolicySetCmd, codeEgressPolicyDeleteCmd)
	codeEgressPolicyGetCmd.Flags().BoolVar(&codeEgressJSON, "json", false, "Print the response as JSON")
	// No default: an admin who forgot --mode enforce would otherwise store
	// a policy that drops nothing (#2378).
	codeEgressPolicySetCmd.Flags().StringVar(&codeEgressMode, "mode", "", "Required: log_only (record what would be dropped) | enforce (drop)")
	_ = codeEgressPolicySetCmd.MarkFlagRequired("mode")
	codeEgressPolicySetCmd.Flags().StringSliceVar(&codeEgressCIDRs, "egress-cidr", nil, "Allowed destination CIDR, IPv4 or IPv6 (repeatable)")
	codeEgressPolicySetCmd.Flags().StringSliceVar(&codeEgressDomains, "egress-domain", nil, "Allowed destination hostname (repeatable)")
}

// newCodeEgressClient dials the daemon over the transport the global flags
// selected. A variable so tests can substitute a fake.
var newCodeEgressClient = func() (client.CodeEgressAPI, error) {
	if serverAddr == "" {
		return nil, fmt.Errorf("--server is required for code egress-policy (the daemon holds the policy)")
	}
	if httpMode {
		return client.NewHTTPClient(serverAddr, authToken)
	}
	return client.NewGRPCClient(serverAddr, certsDir, insecure)
}

func tenantArg(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[0]
}

func runCodeEgressGet(w io.Writer, args []string, asJSON bool) error {
	c, err := newCodeEgressClient()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	resp, err := codeegress.Get(c, tenantArg(args))
	if err != nil {
		return err
	}
	if asJSON {
		b, err := protojson.MarshalOptions{Multiline: true}.Marshal(resp)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(w, string(b))
		return err
	}
	return codeegress.WriteResponse(w, resp)
}

func runCodeEgressSet(w io.Writer, args []string, mode string, cidrs, domains []string) error {
	m, err := codeegress.ParseMode(mode)
	if err != nil {
		return err
	}
	c, err := newCodeEgressClient()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	p, err := codeegress.Set(c, tenantArg(args), m, cidrs, domains)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "✓ coding-tool egress policy stored for %s: revision %d, mode %s, %d CIDR(s), %d domain(s)\n",
		displayCodeEgressTenant(p.GetTenant()), p.GetRevision(), codeEgressModeName(p.GetMode()), len(p.GetEgressCidrs()), len(p.GetEgressDomains()))
	return err
}

func runCodeEgressDelete(w io.Writer, args []string) error {
	c, err := newCodeEgressClient()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	tenant := tenantArg(args)
	if _, err := c.DeleteCodingToolEgressPolicy(&pb.DeleteCodingToolEgressPolicyRequest{Tenant: tenant}); err != nil {
		return fmt.Errorf("delete coding-tool egress policy for %s: %w", displayCodeEgressTenant(tenant), err)
	}
	_, err = fmt.Fprintf(w, "✓ coding-tool egress policy removed for %s\n", displayCodeEgressTenant(tenant))
	return err
}

// codeEgressModeName prints the mode the daemon stored, in --mode spelling.
func codeEgressModeName(m pb.NetworkPolicyMode) string {
	return strings.ToLower(strings.TrimPrefix(m.String(), "NETWORK_POLICY_MODE_"))
}

func displayCodeEgressTenant(t string) string {
	if t == "" {
		return "the cluster default"
	}
	return t
}
