package cmd

import "testing"

// TestNoDuplicateTopLevelCommandNames guards the class of bug found while
// implementing #1921: "collaborator" was registered on rootCmd twice under
// the containarium_client build — once as the real (hybrid, #1785) command
// and once as a moved-to-containariumd stub (moved_stubs_client.go's
// movedServerCommands list, a stale entry from before #1785 made
// collaborator a proper hybrid instead of a fully-moved command).
//
// cobra has no defined tie-break for two top-level commands sharing a
// Name() — Command.Commands() sorts by name for display, and Go's sort is
// not guaranteed stable for equal keys, so which of the two
// same-named nodes Command.Find() resolves to is unspecified and can
// change with unrelated edits elsewhere in the package (as it did here:
// adding one new, unrelated top-level command flipped
// TestMovedServerCommands_ExitTwoNamingContainariumd from a coincidental
// pass to a deterministic fail). No build tag — this runs against
// whichever command tree the current build produces, client or server.
func TestNoDuplicateTopLevelCommandNames(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range rootCmd.Commands() {
		name := c.Name()
		if seen[name] {
			t.Errorf("duplicate top-level command name %q registered on rootCmd — cobra.Command.Find has no defined tie-break for this", name)
			continue
		}
		seen[name] = true
	}
}
