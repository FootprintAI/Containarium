//go:build !windows && !containarium_client

package cmd

import (
	"fmt"
	"os"

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
keeps working. See internal/hostharden and #1103.

--persist also installs and enables the systemd unit that re-applies the
rule on every boot — what ` + "`cloud enroll`" + ` / ` + "`pool join`" + ` do — so one command
restores both halves the host posture check looks for (#2298). The unit
itself runs this command WITHOUT --persist.`,
	Args: cobra.ExactArgs(1),
	RunE: runHostHardenBlockMetadata,
}

var hostHardenPersist bool

func init() {
	rootCmd.AddCommand(hostHardenCmd)
	hostHardenCmd.AddCommand(hostHardenBlockMetadataCmd)
	hostHardenBlockMetadataCmd.Flags().BoolVar(&hostHardenPersist, "persist", false,
		"also install and enable the boot unit that re-applies the rule after a reboot")
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
	if !hostHardenPersist {
		return nil
	}
	bin, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve this binary's path for the boot unit: %w", err)
	}
	if err := hostharden.InstallPersistentUnit(bin, args[0]); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "✓ boot unit %s installed and enabled\n", hostharden.ImdsBlockUnitPath)
	return nil
}
