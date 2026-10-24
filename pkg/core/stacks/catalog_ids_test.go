package stacks

import "testing"

// InstallStack records the stack only when the ID resolves as a dev stack
// (GetStack wins over GetBaseScript). A base script that shared an ID with a
// stack would therefore be treated as that stack by the startup reconcile and
// overwrite a box's recorded stack, so the shipped catalog must keep the two
// ID spaces disjoint. (An operator stacks.yaml is not checked here.)
func TestShippedCatalogStackAndBaseScriptIDsAreDisjoint(t *testing.T) {
	m := GetDefault()
	for _, bs := range m.GetAllBaseScripts() {
		if _, err := m.GetStack(bs.ID); err == nil {
			t.Errorf("base script %q shares its ID with a stack", bs.ID)
		}
	}
}
