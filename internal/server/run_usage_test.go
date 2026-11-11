package server

import (
	"testing"

	"github.com/footprintai/containarium/internal/agentbox"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func requireUnavailableUsage(t *testing.T, u *pb.RunUsage) {
	t.Helper()
	if u == nil {
		t.Fatal("usage is nil, want an explicit UNAVAILABLE RunUsage")
	}
	if u.GetStatus() != pb.RunUsageStatus_RUN_USAGE_STATUS_UNAVAILABLE {
		t.Errorf("status = %v, want UNAVAILABLE", u.GetStatus())
	}
	if len(u.GetModels()) != 0 {
		t.Errorf("models = %v, want none (never zero rows)", u.GetModels())
	}
}

func TestDaemonCapabilities_IncludesRunUsage(t *testing.T) {
	for _, c := range daemonCapabilities() {
		if c == DaemonCapRunUsage {
			if DaemonCapRunUsage != "run_usage" {
				t.Fatalf("capability = %q, want run_usage", DaemonCapRunUsage)
			}
			return
		}
	}
	t.Errorf("capabilities %v missing %q", daemonCapabilities(), DaemonCapRunUsage)
}

func TestBoxRunProto_UsageUnavailable(t *testing.T) {
	for _, o := range []agentbox.RunOutcome{agentbox.RunOutcomeRunning, agentbox.RunOutcomeExited} {
		run := boxRunProto("r", "/tmp/agent-box", agentbox.RunRecord{}, o)
		requireUnavailableUsage(t, run.GetUsage())
	}
}

func TestRunUsageUnavailable_ReturnsFreshValue(t *testing.T) {
	a, b := unavailableRunUsage(), unavailableRunUsage()
	if a == b {
		t.Error("unavailableRunUsage must return a fresh message, not a shared pointer")
	}
	requireUnavailableUsage(t, a)
}
