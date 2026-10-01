package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/footprintai/containarium/internal/client"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// `containarium anon` — operator surface for the anonymous-box door
// (docs/architecture/ssh-new-anonymous-box.md). CLI-first: every verb is a
// thin wrapper over AnonymousBoxService, the same RPCs the cloud control
// plane calls. `claim` lands with #2199; enable/disable/ban/list are #2200.
var anonCmd = &cobra.Command{
	Use:   "anon",
	Short: "Operate the anonymous-box door (ssh new.<domain>)",
}

var (
	anonClaimTenant string
	anonClaimKeys   []string
)

var anonClaimCmd = &cobra.Command{
	Use:   "claim <token>",
	Short: "Redeem a claim token: bind an anonymous box to a tenant (admin)",
	Long: `Redeem the single-use token an anonymous box prints with
'containarium claim' and bind the box to --tenant: its TTL is cleared,
the trial egress limits are lifted, --key keys are added beside the
claiming key, and the box shows up in the tenant's 'containarium list'
under its existing name. Access stays via the door with the claiming key.

Requires role admin or scope anon:admin. The cloud control plane calls
the same RPC after signup.

Examples:
  containarium anon claim v1.anon-1a2b3c4d-container.… --tenant alice
  containarium anon claim "$(cat token)" --tenant alice --key "$(cat ~/.ssh/id_ed25519.pub)"`,
	Args: cobra.ExactArgs(1),
	RunE: runAnonClaim,
}

func init() {
	rootCmd.AddCommand(anonCmd)
	anonCmd.AddCommand(anonClaimCmd)
	anonClaimCmd.Flags().StringVar(&anonClaimTenant, "tenant", "", "Username that will own the box (required)")
	anonClaimCmd.Flags().StringArrayVar(&anonClaimKeys, "key", nil, "authorized_keys line to add for the tenant (repeatable; a value starting with @ is read from that file)")
	_ = anonClaimCmd.MarkFlagRequired("tenant")
}

func runAnonClaim(cmd *cobra.Command, args []string) error {
	keys, err := resolveAnonClaimKeys(anonClaimKeys)
	if err != nil {
		return err
	}
	req := &pb.ClaimAnonymousBoxRequest{ClaimToken: strings.TrimSpace(args[0]), Tenant: strings.TrimSpace(anonClaimTenant), AuthorizedKeys: keys}

	var resp *pb.ClaimAnonymousBoxResponse
	if httpMode {
		hc, err := client.NewHTTPClient(serverAddr, authToken)
		if err != nil {
			return err
		}
		defer func() { _ = hc.Close() }()
		resp, err = hc.ClaimAnonymousBox(req)
		if err != nil {
			return err
		}
	} else {
		gc, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
		if err != nil {
			return err
		}
		defer func() { _ = gc.Close() }()
		resp, err = gc.ClaimAnonymousBox(req)
		if err != nil {
			return err
		}
	}
	fmt.Fprintf(cmd.OutOrStdout(), "✅ %s is now owned by %s (TTL cleared, egress limits lifted, %d key(s) added). It stays reachable through the door with the claiming key.\n",
		resp.GetBoxName(), resp.GetTenant(), len(keys))
	return nil
}

// resolveAnonClaimKeys expands "@path" entries into file contents (one key
// per non-empty line) and drops blanks.
func resolveAnonClaimKeys(in []string) ([]string, error) {
	var out []string
	for _, k := range in {
		k = strings.TrimSpace(k)
		switch {
		case k == "":
			continue
		case strings.HasPrefix(k, "@"):
			raw, err := os.ReadFile(k[1:])
			if err != nil {
				return nil, fmt.Errorf("read key file %s: %w", k[1:], err)
			}
			for _, line := range strings.Split(string(raw), "\n") {
				if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
					out = append(out, line)
				}
			}
		default:
			out = append(out, k)
		}
	}
	return out, nil
}
