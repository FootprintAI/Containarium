//go:build containarium_client

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// osExit is os.Exit, indirected so tests can observe the exit code instead
// of killing the test binary.
var osExit = os.Exit

// movedServerCommands are every top-level server/operator command name that
// exists in containariumd but is tagged !containarium_client (#1774) out of
// the client build. Registering a stub for each — rather than leaving
// cobra's default "unknown command" — exists for exactly one failure mode
// (design doc, Rollout Phase 2): a host whose systemd unit or startup
// script still runs e.g. `containarium daemon` after the client build has
// taken over the `containarium` name. The stub's message names the fix.
var movedServerCommands = []string{
	"daemon",
	"sentinel",
	"service",
	"tunnel",
	"node",
	"hypervisor-agent",
	"egress-relay",
	"upgrade-watchdog",
	"sync-accounts",
	"recover",
	"image-bake",
	"doctor",
	"hosting",
	"portforward",
	"passthrough",
	"collaborator",
	"audit",
	"export",
	"cloud",
}

// movedCommandMessage is the stub's stderr line — factored out so the exact
// wording is covered by a plain unit test without going through cobra/exit.
func movedCommandMessage(name string) string {
	return fmt.Sprintf("%s lives in containariumd on the host; this is the client binary", name)
}

func init() {
	for _, name := range movedServerCommands {
		rootCmd.AddCommand(&cobra.Command{
			Use:                name,
			Short:              name + " (moved to containariumd)",
			Annotations:        map[string]string{movedStubAnnotation: "true"},
			DisableFlagParsing: true, // accept any flags/subcommand args without cobra erroring first
			Run: func(cmd *cobra.Command, args []string) {
				fmt.Fprintln(os.Stderr, movedCommandMessage(name))
				osExit(2)
			},
		})
	}
}
