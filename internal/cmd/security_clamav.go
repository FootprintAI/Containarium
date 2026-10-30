// `containarium security clamav install <box>` — install ClamAV and its
// signatures inside one box so the tenant-run malware scan can run (#2659).
// CLI-first: it calls the same mcp.Client.InstallClamav the install_clamav MCP
// tool uses.
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var securityClamavCmd = &cobra.Command{
	Use:   "clamav",
	Short: "Manage the tenant-run ClamAV malware scan",
}

var securityClamavInstallCmd = &cobra.Command{
	Use:   "install <box>",
	Short: "Install ClamAV and its signatures inside a box",
	Long: `Installs ClamAV and its signatures inside the named box, so a malware scan
(containarium security-scan <box> --kind clamav) can run there.

The install runs INSIDE the box with the box's own privileges, started by its
owner; the platform does not read the box's files. It needs:
  - a running Debian/Ubuntu box (other families: install ClamAV manually),
  - at least 4 GB RAM (a one-shot scan loads about 1.5 GB of signatures),
  - outbound access to the package mirror and the ClamAV signature servers.

Safe to run again: a box that already has ClamAV and signatures runs nothing.
It can take several minutes.`,
	Args: cobra.ExactArgs(1),
	RunE: runSecurityClamavInstall,
}

func runSecurityClamavInstall(cmd *cobra.Command, args []string) error {
	c, err := newSecurityClient()
	if err != nil {
		return err
	}
	resp, err := c.InstallClamav(args[0])
	if err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "%s: %s\n", resp.Outcome, resp.Message)
	switch resp.Outcome {
	case "CLAMAV_INSTALL_OUTCOME_INSTALLED", "CLAMAV_INSTALL_OUTCOME_ALREADY_PRESENT":
		return nil
	}
	return fmt.Errorf("clamav install did not complete: %s", resp.Outcome)
}

func init() {
	securityClamavCmd.AddCommand(securityClamavInstallCmd)
	securityCmd.AddCommand(securityClamavCmd)
}
