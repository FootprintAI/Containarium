//go:build !windows && !containarium_client

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/footprintai/containarium/internal/hostharden"
)

// hostharden is internal plumbing (#1103 fix 3), not a documented top-level
// workflow: `cloud enroll` and `pool join` invoke BlockMetadataFromBridge
// directly, and the persistent systemd unit InstallPersistentUnit writes
// shells out to THIS subcommand (rather than duplicating the iptables/incus
// invocation inline) so the unit and the enrollment-time call can never
// drift apart. Hidden from `containarium --help`; still fully usable if an
// operator needs to re-run it by hand.
var hostHardenCmd = &cobra.Command{
	Use:    "hostharden",
	Short:  "Narrow host-hardening mutations, applied by cloud enroll / pool join and the reboot unit they install",
	Hidden: true,
}

var hostHardenBlockMetadataCmd = &cobra.Command{
	Use:   "block-metadata <bridge>",
	Short: "Idempotently drop FORWARDED traffic from <bridge>'s subnet to the cloud metadata endpoint",
	Long: `Inserts (if not already present) an iptables FORWARD rule dropping traffic
from <bridge>'s configured subnet to 169.254.169.254 — the cloud metadata
endpoint every major provider serves at that link-local address. Scoped to
FORWARDED (container-bridge) traffic only; the host's own OUTPUT-originated
requests are untouched, so cloud-provider tooling running on the host itself
keeps working. See internal/hostharden and #1103.`,
	Args: cobra.ExactArgs(1),
	RunE: runHostHardenBlockMetadata,
}

func init() {
	rootCmd.AddCommand(hostHardenCmd)
	hostHardenCmd.AddCommand(hostHardenBlockMetadataCmd)
}

func runHostHardenBlockMetadata(cmd *cobra.Command, args []string) error {
	applied, detail, err := hostharden.BlockMetadataFromBridge(args[0])
	if err != nil {
		return err
	}
	mark := "="
	if applied {
		mark = "✓"
	}
	fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", mark, detail)
	return nil
}
