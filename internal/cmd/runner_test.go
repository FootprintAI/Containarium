package cmd

import (
	"strings"
	"testing"
)

// TestRunRunnerProvision_RunnerGroupFlag checks --runner-group is registered
// and reaches runner.ValidateOptions: a group on a repository target is
// refused before the sentinel check or any box work.
func TestRunRunnerProvision_RunnerGroupFlag(t *testing.T) {
	if runnerProvisionCmd.Flags().Lookup("runner-group") == nil {
		t.Fatal("runner provision has no --runner-group flag")
	}

	prevPAT, prevCount, prevGroup, prevSentinel := runnerPAT, runnerCount, runnerGroup, runnerSentinelHost
	t.Cleanup(func() {
		runnerPAT, runnerCount, runnerGroup, runnerSentinelHost = prevPAT, prevCount, prevGroup, prevSentinel
	})
	runnerPAT, runnerCount, runnerGroup, runnerSentinelHost = "ghp_x", 1, "gpu", ""

	err := runRunnerProvision(nil, []string{"owner/repo"})
	if err == nil || !strings.Contains(err.Error(), "runner group requires an organization target") {
		t.Fatalf("want the organization-target refusal, got %v", err)
	}
}
