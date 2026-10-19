//go:build !windows && !containarium_client

package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
)

// TestSSHBanPluginCommandIsRegistered pins the production invocation in the
// rendered systemd units; a library-only implementation cannot satisfy it.
func TestSSHBanPluginCommandIsRegistered(t *testing.T) {
	var plugin *cobra.Command
	for _, c := range sentinelCmd.Commands() {
		if c.Name() == "ssh-ban-plugin" {
			plugin = c
		}
	}
	if plugin == nil {
		t.Fatal("sentinel ssh-ban-plugin is not registered")
	}
	for _, flag := range []string{"listener", "max-failures", "ban-duration", "ignore-ip", "control-socket", "max-entries"} {
		if plugin.Flags().Lookup(flag) == nil {
			t.Errorf("missing policy flag: %s", flag)
		}
	}
}

// TestSSHBanPluginRejectsInvalidPolicyBeforeOpeningSocket ensures invalid
// provisioning cannot start a permissive or partially configured plugin.
func TestSSHBanPluginRejectsInvalidPolicyBeforeOpeningSocket(t *testing.T) {
	for _, args := range [][]string{{"--listener", "other"}, {"--max-failures", "0"}, {"--ban-duration", "0s"}, {"--max-entries", "0"}, {"--ignore-ip", "garbage"}} {
		c := newSSHBanPluginCommand()
		socket := filepath.Join(t.TempDir(), "private", "control.sock")
		c.SetArgs(append(args, "--control-socket", socket))
		c.SilenceErrors, c.SilenceUsage = true, true
		if err := c.Execute(); err == nil {
			t.Fatalf("accepted invalid policy %v", args)
		}
		if _, err := os.Stat(socket); !os.IsNotExist(err) {
			t.Fatalf("invalid policy exposed socket: %v", err)
		}
	}
}
