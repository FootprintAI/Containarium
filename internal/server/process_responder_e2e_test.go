//go:build integration

// Real-Incus coverage for the process responder's actuator path (#2636):
// THROTTLE drops limits.cpu.allowance to the policy's value and release
// restores the recorded limit; FREEZE leaves the instance Frozen and release
// resumes it. Needs a running container to act on:
//
//	CONTAINARIUM_E2E_INCUS_CONTAINER=<name> go test -tags=integration -run TestProcessResponderE2E ./internal/server/
//
// Skips (does not fail) without one, because the store-integration lane has
// Postgres but no Incus; the sprint's batched verification pass on dev runs
// the full CPU-burner version from the issue's Verify-on-dev steps.
package server

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/threatdetect"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestProcessResponderE2E_ThrottleAndFreezeOnRealIncus(t *testing.T) {
	name := os.Getenv("CONTAINARIUM_E2E_INCUS_CONTAINER")
	if name == "" {
		t.Skip("CONTAINARIUM_E2E_INCUS_CONTAINER is unset; needs a running Incus container to throttle and freeze")
	}
	client, err := incus.New()
	if err != nil {
		t.Skipf("no Incus here: %v", err)
	}
	info, err := client.GetContainer(name)
	if err != nil {
		t.Fatalf("GetContainer(%s): %v", name, err)
	}
	if info.State != "Running" {
		t.Fatalf("container %s is %s, want Running", name, info.State)
	}
	act := incusActuator{c: client}
	origCount, origAllow, err := act.CPULimit(name)
	if err != nil {
		t.Fatalf("CPULimit: %v", err)
	}
	t.Cleanup(func() {
		_ = act.Unfreeze(name)
		_ = act.SetCPULimit(name, origCount, origAllow)
	})

	ctx := context.Background()
	fx := &responderFixture{
		act:      nil,
		findings: newFakeFindings(),
		actions:  threatdetect.NewMemActionStore(),
		policies: threatdetect.NewProcessPolicyStore(nil),
		audit:    &fakeAudit{},
	}
	r := NewProcessResponder(fx.policies, fx.actions, fx.findings, act, fx.audit, false)
	sink := NewActingSink(fx.findings, r)
	fire := func(subject string) {
		t.Helper()
		if _, err := sink.Upsert(ctx, &threatdetect.Finding{
			Rule: pb.ThreatRuleId(6), Severity: pb.ThreatSeverity_THREAT_SEVERITY_HIGH,
			TenantID: "e2e", Container: name, Subject: subject,
		}); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
	}

	// THROTTLE: allowance drops to 10%, limits.cpu untouched; release
	// restores exactly what was recorded.
	fx.setDefault(t, pb.ProcessAction_PROCESS_ACTION_THROTTLE, "10%", 0)
	fire("203.0.113.9:3333")
	count, allow, err := act.CPULimit(name)
	if err != nil {
		t.Fatalf("CPULimit after throttle: %v", err)
	}
	if allow != "10%" || count != origCount {
		t.Fatalf("after throttle: limits.cpu=%q allowance=%q, want %q/10%%", count, allow, origCount)
	}
	if _, err := r.Release(ctx, name); err != nil {
		t.Fatalf("Release throttle: %v", err)
	}
	count, allow, _ = act.CPULimit(name)
	if count != origCount || allow != origAllow {
		t.Fatalf("after release: limits.cpu=%q allowance=%q, want original %q/%q", count, allow, origCount, origAllow)
	}

	// FREEZE: instance reports Frozen; release resumes it.
	fx.setDefault(t, pb.ProcessAction_PROCESS_ACTION_FREEZE, "", 0)
	fire("203.0.113.10:3333")
	waitStatus := func(want string) {
		t.Helper()
		deadline := time.Now().Add(30 * time.Second)
		for {
			info, err := client.GetContainer(name)
			if err == nil && info.State == want {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("container %s status = %q (err %v), want %q", name, info.State, err, want)
			}
			time.Sleep(time.Second)
		}
	}
	waitStatus("Frozen")
	if _, err := r.Release(ctx, name); err != nil {
		t.Fatalf("Release freeze: %v", err)
	}
	waitStatus("Running")
}
