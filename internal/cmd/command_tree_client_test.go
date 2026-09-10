//go:build containarium_client

package cmd

import (
	"os"
	"strings"
	"testing"
)

const clientCommandTreeGolden = "testdata/client_command_tree.golden"

func loadGolden(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile(clientCommandTreeGolden)
	if err != nil {
		t.Fatalf("read golden file: %v", err)
	}
	var lines []string
	for _, l := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		if l != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

// TestClientCommandTree_MatchesGoldenAllowList is #1778's allow-list gate:
// every path registered under containarium_client must be in the checked-in
// golden list, and every approved path must still be registered. A new
// client command that isn't deliberately added here fails the build; a
// server command that leaks into the client (a forgotten
// !containarium_client tag) shows up as an unapproved path too — this is
// the gate that catches that even when the dependency-graph gate (an
// import-only check) wouldn't, e.g. a new command shelling out to
// `systemctl` with no gated import at all.
func TestClientCommandTree_MatchesGoldenAllowList(t *testing.T) {
	golden := loadGolden(t)
	got := renderCommandTree(rootCmd)

	goldenSet := make(map[string]bool, len(golden))
	for _, p := range golden {
		goldenSet[p] = true
	}
	gotSet := make(map[string]bool, len(got))
	for _, p := range got {
		gotSet[p] = true
	}

	for _, p := range got {
		if !goldenSet[p] {
			t.Errorf("unapproved command path registered in the client build: %q — add it to %s if intentional (see docs/architecture/cli-client-server-split.md), or fix the missing !containarium_client tag if not", p, clientCommandTreeGolden)
		}
	}
	for _, p := range golden {
		if !gotSet[p] {
			t.Errorf("approved command path missing from the client build: %q — the split lost a command that %s says should be there", p, clientCommandTreeGolden)
		}
	}
}
