package cmd

import (
	"strings"
	"testing"
)

// #2733 (slice B of #2263): `containarium bridge-dns status` is removed in
// both the client and the daemon builds, along with the RPC it called.
func TestBridgeDNSCommandRemoved(t *testing.T) {
	tree := renderCommandTree(rootCmd)
	if len(tree) == 0 {
		t.Fatal("empty command tree; test harness broken")
	}
	for _, p := range tree {
		if p == "bridge-dns" || strings.HasPrefix(p, "bridge-dns ") {
			t.Errorf("command %q is still registered", p)
		}
	}
}
