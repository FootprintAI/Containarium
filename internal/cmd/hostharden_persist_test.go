//go:build !windows && !containarium_client

package cmd

import "testing"

// #2300: `block-metadata --persist` is the supported way to restore the boot
// unit after the rule was applied without it; it must stay opt-in so the unit
// itself (which runs this command) does not reinstall itself on every boot.
func TestHostHardenBlockMetadata_PersistFlag(t *testing.T) {
	f := hostHardenBlockMetadataCmd.Flags().Lookup("persist")
	if f == nil {
		t.Fatal("block-metadata has no --persist flag")
	}
	if f.DefValue != "false" {
		t.Errorf("--persist default = %q, want false", f.DefValue)
	}
}
