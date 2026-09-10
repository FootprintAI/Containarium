//go:build !windows && !containarium_client

package cmd

import "testing"

// TestUpgradeWatchdogDefaultBinaryPath is part of #1779's artifact-name
// gate: the watchdog restores .old at the same path the daemon just
// swapped (dual_server.go's NewAutoUpdater call, sentinel/binaryserver.go's
// defaultBinaryPath) — all three must agree on containariumd.
func TestUpgradeWatchdogDefaultBinaryPath(t *testing.T) {
	f := upgradeWatchdogCmd.Flags().Lookup("binary-path")
	if f == nil {
		t.Fatal("--binary-path flag not registered")
	}
	if f.DefValue != "/usr/local/bin/containariumd" {
		t.Errorf("--binary-path default = %q, want %q", f.DefValue, "/usr/local/bin/containariumd")
	}
}
