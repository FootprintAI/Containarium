package cmd

import (
	"strings"
	"testing"
)

func resetBoxDelete(t *testing.T) *[]string {
	t.Helper()
	var calls []string
	old, oy, of := boxDeleteFn, boxDeleteYes, boxDeleteForce
	boxDeleteFn = func(username string, force bool) error {
		calls = append(calls, username)
		if force {
			calls = append(calls, "force")
		}
		return nil
	}
	t.Cleanup(func() { boxDeleteFn, boxDeleteYes, boxDeleteForce = old, oy, of })
	boxDeleteYes, boxDeleteForce = false, false
	return &calls
}

func TestBoxDelete_RefusesWithoutYesAndNeverDeletes(t *testing.T) {
	calls := resetBoxDelete(t)
	err := runBoxDelete(boxDeleteCmd, []string{"alice"})
	if err == nil || !strings.Contains(err.Error(), "--yes") || !strings.Contains(err.Error(), "alice-container") {
		t.Fatalf("want a refusal naming --yes and the box, got %v", err)
	}
	if len(*calls) != 0 {
		t.Fatalf("the delete ran without --yes: %v", *calls)
	}
}

func TestBoxDelete_YesDeletesAndForcePassesThrough(t *testing.T) {
	calls := resetBoxDelete(t)
	boxDeleteYes = true
	if err := runBoxDelete(boxDeleteCmd, []string{"alice"}); err != nil {
		t.Fatal(err)
	}
	boxDeleteForce = true
	if err := runBoxDelete(boxDeleteCmd, []string{"bob"}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(*calls, ","); got != "alice,bob,force" {
		t.Fatalf("calls = %q, want alice (no force) then bob with force", got)
	}
}

func TestBoxDelete_NeedsExactlyOneBoxAndDefaultsAreSafe(t *testing.T) {
	for _, args := range [][]string{{}, {"a", "b"}} {
		if err := boxDeleteCmd.Args(boxDeleteCmd, args); err == nil {
			t.Errorf("args %v should be rejected", args)
		}
	}
	if f := boxDeleteCmd.Flags().Lookup("yes"); f == nil || f.DefValue != "false" {
		t.Fatal("--yes must exist and default to false")
	}
	if f := boxDeleteCmd.Flags().Lookup("force"); f == nil || f.DefValue != "false" {
		t.Fatal("--force must exist and default to false")
	}
}

// The older command is untouched: it has no --yes.
func TestDelete_StillHasNoYesFlag(t *testing.T) {
	if deleteCmd.Flags().Lookup("yes") != nil {
		t.Fatal("`containarium delete` must keep its existing behavior (no --yes)")
	}
}
