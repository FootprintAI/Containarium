//go:build !windows

package cmd

import (
	"strings"
	"testing"
)

// #2759: "Empty = no auto-sleep" is wrong on the hosted platform, where an org
// billed per seat defaults to a 30-minute idle-stop. The flag's help must say
// both defaults, so a user reading it is not surprised either way.
func TestIdleStopFlagHelpStatesBothDefaults(t *testing.T) {
	f := createCmd.Flags().Lookup("idle-stop")
	if f == nil {
		t.Fatal("create has no --idle-stop flag")
	}
	usage := f.Usage

	for _, want := range []string{
		"seat",       // names the seat-billed case
		"30 minutes", // and its default
		"self-hosted",
	} {
		if !strings.Contains(usage, want) {
			t.Errorf("--idle-stop help should mention %q, got:\n%s", want, usage)
		}
	}
	// The unconditional claim that was wrong on the hosted platform.
	if strings.Contains(usage, "Empty = no auto-sleep.") {
		t.Errorf("--idle-stop help still says an empty value always means no auto-sleep:\n%s", usage)
	}
	// An opt-out is not promised here: that part of #2759 is undecided.
	if strings.Contains(strings.ToLower(usage), "disable_auto_sleep") || strings.Contains(usage, "--no-auto-sleep") {
		t.Errorf("--idle-stop help promises an opt-out that does not exist yet:\n%s", usage)
	}
}
