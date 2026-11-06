//go:build !windows && !containarium_client

package cmd

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/footprintai/containarium/pkg/core/toolchain"
)

var toolchainCmd = &cobra.Command{
	Use:   "toolchain",
	Short: "Inspect the host's managed build toolchain release",
}

var toolchainListCmd = &cobra.Command{
	Use:   "list",
	Short: "List the active release's tools with version and source",
	Long: `List every tool in the active managed toolchain release, whether it ships
with Containarium (managed) or came from a deployer-supplied extra lock (extra).
Reads ` + toolchain.HostRoot + `/current/manifest.json on this host.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		inv, err := toolchain.ReadInventory(toolchain.HostRoot)
		if err != nil {
			return fmt.Errorf("%w\n%s", err, toolchain.MissingAdvice)
		}
		printToolchainList(cmd.OutOrStdout(), inv)
		return nil
	},
}

func printToolchainList(w io.Writer, inv toolchain.Inventory) {
	_, _ = fmt.Fprintf(w, "Release %s (%s)\n", inv.Release, inv.Arch)
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "TOOL\tVERSION\tSOURCE")
	for _, t := range inv.Tools {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\n", t.Name, t.Version, t.Source)
	}
	_ = tw.Flush()
	if inv.ExtraLockSHA256 != "" {
		_, _ = fmt.Fprintf(w, "extra lock sha256: %s\n", inv.ExtraLockSHA256)
	}
}

func init() {
	toolchainCmd.AddCommand(toolchainListCmd)
	rootCmd.AddCommand(toolchainCmd)
}
