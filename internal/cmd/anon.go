package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/footprintai/containarium/internal/client"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// `containarium anon` — operator surface for the anonymous-box door
// (docs/architecture/ssh-new-anonymous-box.md). CLI-first: every verb is a
// thin wrapper over AnonymousBoxService, the same RPCs the cloud control
// plane calls. `claim` is #2199; enable/disable/status/ban/unban/list are
// #2200.
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

// anonAPI is the slice of the typed clients the door verbs use; both
// transports satisfy it.
type anonAPI interface {
	GetAnonymousDoorConfig() (*pb.AnonymousDoorConfig, error)
	SetAnonymousDoorConfig(cfg *pb.AnonymousDoorConfig) (*pb.AnonymousDoorConfig, error)
	ListAnonymousBoxes() (*pb.ListAnonymousBoxesResponse, error)
	Close() error
}

func newAnonAPI() (anonAPI, error) {
	if httpMode {
		return client.NewHTTPClient(serverAddr, authToken)
	}
	return client.NewGRPCClient(serverAddr, certsDir, insecure)
}

var anonDoorMessage string

var anonEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Open the anonymous door (admin)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return anonSetDoor(cmd, func(c *pb.AnonymousDoorConfig) { c.Enabled = true; c.DisabledMessage = "" })
	},
}

var anonDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Close the anonymous door — every new connection is refused with --message (admin)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return anonSetDoor(cmd, func(c *pb.AnonymousDoorConfig) { c.Enabled = false; c.DisabledMessage = anonDoorMessage })
	},
}

var anonBanCmd = &cobra.Command{
	Use:   "ban <fingerprint>",
	Short: "Refuse a key (SHA256:… fingerprint) at the door (admin)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return anonSetDoor(cmd, func(c *pb.AnonymousDoorConfig) {
			c.BannedFingerprints = append(c.BannedFingerprints, strings.TrimSpace(args[0]))
		})
	},
}

var anonUnbanCmd = &cobra.Command{
	Use:   "unban <fingerprint>",
	Short: "Lift a ban (admin)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return anonSetDoor(cmd, func(c *pb.AnonymousDoorConfig) {
			c.BannedFingerprints = removeString(c.BannedFingerprints, strings.TrimSpace(args[0]))
		})
	},
}

var anonStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the door's state, bans and fixed limits (admin)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		api, err := newAnonAPI()
		if err != nil {
			return err
		}
		defer func() { _ = api.Close() }()
		cfg, err := api.GetAnonymousDoorConfig()
		if err != nil {
			return err
		}
		fmt.Fprint(cmd.OutOrStdout(), formatDoorConfig(cfg))
		return nil
	},
}

var anonListCmd = &cobra.Command{
	Use:   "list",
	Short: "List live anonymous boxes on this daemon (admin)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		api, err := newAnonAPI()
		if err != nil {
			return err
		}
		defer func() { _ = api.Close() }()
		resp, err := api.ListAnonymousBoxes()
		if err != nil {
			return err
		}
		fmt.Fprint(cmd.OutOrStdout(), formatAnonBoxes(resp.GetBoxes()))
		return nil
	},
}

// anonSetDoor is read-modify-write over the door config: fetch, apply
// mut, set, print. Limits are read-only server-side and ignored.
func anonSetDoor(cmd *cobra.Command, mut func(*pb.AnonymousDoorConfig)) error {
	api, err := newAnonAPI()
	if err != nil {
		return err
	}
	defer func() { _ = api.Close() }()
	cfg, err := api.GetAnonymousDoorConfig()
	if err != nil {
		return err
	}
	mut(cfg)
	out, err := api.SetAnonymousDoorConfig(cfg)
	if err != nil {
		return err
	}
	fmt.Fprint(cmd.OutOrStdout(), formatDoorConfig(out))
	return nil
}

func removeString(in []string, s string) []string {
	out := in[:0]
	for _, v := range in {
		if v != s {
			out = append(out, v)
		}
	}
	return out
}

func formatDoorConfig(cfg *pb.AnonymousDoorConfig) string {
	var sb strings.Builder
	if cfg.GetEnabled() {
		sb.WriteString("Door: OPEN\n")
	} else {
		sb.WriteString("Door: CLOSED")
		if m := cfg.GetDisabledMessage(); m != "" {
			sb.WriteString(" — " + m)
		}
		sb.WriteString("\n")
	}
	if l := cfg.GetLimits(); l != nil {
		fmt.Fprintf(&sb, "Limits: %s vCPU, %s RAM, %s disk, TTL %s; cap %d boxes; per key %.2g/min burst %d; per IP %.2g/min burst %d\n",
			l.GetCpu(), l.GetMemory(), l.GetDisk(), (time.Duration(l.GetTtlSeconds()) * time.Second).String(),
			l.GetMaxBoxes(), l.GetPerFingerprintRps()*60, l.GetPerFingerprintBurst(), l.GetPerIpRps()*60, l.GetPerIpBurst())
	}
	if n := len(cfg.GetBannedFingerprints()); n > 0 {
		fmt.Fprintf(&sb, "Banned (%d):\n", n)
		for _, fp := range cfg.GetBannedFingerprints() {
			sb.WriteString("  " + fp + "\n")
		}
	} else {
		sb.WriteString("Banned: none\n")
	}
	return sb.String()
}

func formatAnonBoxes(boxes []*pb.AnonymousBox) string {
	if len(boxes) == 0 {
		return "No anonymous boxes.\n"
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "%-28s %-16s %-16s %-20s %s\n", "BOX", "FP HASH", "IP", "EXPIRES", "CLAIMED")
	for _, b := range boxes {
		exp := "-"
		if b.GetTtlExpiresAt() != nil {
			exp = b.GetTtlExpiresAt().AsTime().UTC().Format("2006-01-02 15:04Z")
		}
		fp := b.GetFingerprintHash()
		if len(fp) > 16 {
			fp = fp[:16]
		}
		claimed := "no"
		if b.GetClaimed() {
			claimed = "yes"
		}
		fmt.Fprintf(&sb, "%-28s %-16s %-16s %-20s %s\n", b.GetBoxName(), fp, b.GetSshHost(), exp, claimed)
	}
	fmt.Fprintf(&sb, "Total: %d\n", len(boxes))
	return sb.String()
}

func init() {
	rootCmd.AddCommand(anonCmd)
	anonCmd.AddCommand(anonClaimCmd, anonEnableCmd, anonDisableCmd, anonStatusCmd, anonBanCmd, anonUnbanCmd, anonListCmd)
	anonDisableCmd.Flags().StringVar(&anonDoorMessage, "message", "the anonymous door is closed for maintenance", "What a refused caller is told while the door is closed")
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
