//go:build !containarium_client

package cmd

import (
	"os"
	"strings"
	"testing"
)

// TestContainariumdCommandTree_SupersetOfClientGolden is #1778's
// untagged-build parity gate: the split must never *lose* a command from
// the server binary. containariumd's tree is asserted to be a strict
// superset of the client's golden list, once every "moved:" entry is
// resolved to what it actually means in containariumd:
//
//   - a moved name that is itself runnable server-side (daemon, sentinel,
//     tunnel, …) must appear as-is;
//   - a moved name that is a group-only parent in containariumd (audit,
//     cloud, hosting, …, no RunE of its own — only its subcommands are
//     runnable) is satisfied by at least one "<name> <child>" path
//     existing, since renderCommandTree only lists runnable leaves and a
//     bare group name is never one.
//
// Every other (non-"moved:") golden entry is a real client command that
// containariumd carries unchanged (the design's superset guarantee), so it
// must appear byte-for-byte.
func TestContainariumdCommandTree_SupersetOfClientGolden(t *testing.T) {
	b, err := os.ReadFile("testdata/client_command_tree.golden")
	if err != nil {
		t.Fatalf("read golden file: %v", err)
	}

	daemonTree := renderCommandTree(rootCmd)
	daemonSet := make(map[string]bool, len(daemonTree))
	for _, p := range daemonTree {
		daemonSet[p] = true
	}
	hasPrefix := func(prefix string) bool {
		for _, p := range daemonTree {
			if strings.HasPrefix(p, prefix+" ") {
				return true
			}
		}
		return false
	}

	for i, line := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		if line == "" {
			continue
		}
		name, isMoved := strings.CutPrefix(line, "moved:")
		if !isMoved {
			if !daemonSet[line] {
				t.Errorf("golden line %d (%q): containariumd is missing a command the client has — the split lost it", i+1, line)
			}
			continue
		}
		if !daemonSet[name] && !hasPrefix(name) {
			t.Errorf("golden line %d (%q): containariumd has neither %q itself nor any %q child — the moved command doesn't actually exist server-side", i+1, line, name, name+" *")
		}
	}
}
