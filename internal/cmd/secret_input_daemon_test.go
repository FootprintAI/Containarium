//go:build !windows && !containarium_client

package cmd

import (
	"testing"

	"github.com/spf13/cobra"
)

// tunnelCmd and hypervisorAgentCmd exist only in the full (non-client,
// non-windows) build, so their flag-registration check carries the same
// build constraint as the files that define them.
func TestSecretInputFlagsRegisteredDaemonCmds(t *testing.T) {
	for name, c := range map[string]*cobra.Command{
		"tunnel":           tunnelCmd,
		"hypervisor-agent": hypervisorAgentCmd,
	} {
		for _, fl := range []string{"token-file", "stdin"} {
			if c.Flags().Lookup(fl) == nil {
				t.Errorf("%s: missing --%s", name, fl)
			}
		}
	}
}
