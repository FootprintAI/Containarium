//go:build !windows

package cmd

import (
	"strings"
	"testing"
)

// #2759: the CLI exposes the auto-sleep opt-out and says what it is for.
func TestNoAutoSleepFlag(t *testing.T) {
	f := createCmd.Flags().Lookup("no-auto-sleep")
	if f == nil {
		t.Fatal("create has no --no-auto-sleep flag")
	}
	if f.DefValue != "false" {
		t.Errorf("--no-auto-sleep must default to false, got %q", f.DefValue)
	}
	for _, want := range []string{"seat", "--idle-stop"} {
		if !strings.Contains(f.Usage, want) {
			t.Errorf("--no-auto-sleep help should mention %q, got:\n%s", want, f.Usage)
		}
	}
}
