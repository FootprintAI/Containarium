//go:build !windows

package cmd

import (
	"fmt"
	"strings"
	"testing"

	"github.com/footprintai/containarium/pkg/core/stacks"
)

// TestStackFlagUsageShowsNames guards the --stack usage string against the two
// ways it was previously wrong: a hard-coded list that drifted from the catalog
// (eight ids listed, fifteen shipped) and ids shown without their human name, so
// "database" read as "a database server" when the stack is clients-only (#1128).
//
// Asserted against the live catalog rather than a literal, so the test cannot
// itself go stale the way the string it replaced did.
func TestStackFlagUsageShowsNames(t *testing.T) {
	usage := stackFlagUsage()
	all := stacks.GetDefault().GetAllStacks()
	if len(all) == 0 {
		t.Skip("no stack catalog available in this environment")
	}

	for _, s := range all {
		want := s.ID
		if s.Name != "" && s.Name != s.ID {
			want = fmt.Sprintf("%s (%s)", s.ID, s.Name)
		}
		if !strings.Contains(usage, want) {
			t.Errorf("--stack usage is missing %q; a stack absent from the help is\n"+
				"undiscoverable from the CLI. usage=%q", want, usage)
		}
	}
}

// TestStackFlagUsageDisambiguatesClientOnlyStacks pins the specific confusion that
// prompted #1128: an id that names a category ("database") while the stack installs
// only clients. Whatever the catalog calls it, the id must not appear bare.
func TestStackFlagUsageDisambiguatesClientOnlyStacks(t *testing.T) {
	all := stacks.GetDefault().GetAllStacks()
	var target *stacks.Stack
	for i := range all {
		if all[i].ID == "database" {
			target = &all[i]
			break
		}
	}
	if target == nil {
		t.Skip("no 'database' stack in this catalog")
	}
	if target.Name == "" || target.Name == target.ID {
		t.Fatalf("the 'database' stack has no distinguishing name to surface (name=%q); "+
			"without one the CLI cannot tell the user it is clients-only", target.Name)
	}
	usage := stackFlagUsage()
	if !strings.Contains(usage, fmt.Sprintf("database (%s)", target.Name)) {
		t.Errorf("--stack usage should render 'database (%s)' so the id is not mistaken "+
			"for a database server; usage=%q", target.Name, usage)
	}
}
