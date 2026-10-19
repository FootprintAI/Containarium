//go:build incus

// Real-Incus coverage for the process responder's actuator path (#2636):
// THROTTLE applies the policy's allowance as a HARD CFS quota (the kernel's
// cpu.max is checked when readable, #2676: a bare "N%" is only a soft share
// and left the box unthrottled) and release restores the recorded limit; FREEZE leaves the instance Frozen and release
// resumes it. Needs a running container to act on:
//
//	CONTAINARIUM_E2E_INCUS_CONTAINER=<name> go test -tags=incus -run TestProcessResponderE2E ./internal/server/
//
// Skips (does not fail) without one. It lives under the `incus` tag (the
// repo's real-Incus lane), so the store-integration lane never compiles it.
// The sprint's batched verification pass on dev runs the full CPU-burner
// version from the issue's Verify-on-dev steps.
package server

import (
	"context"
	"os"
	"path/filepath"
	"strings"
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

	// cpu.max is the kernel's view of the hard quota ("<quota> <period>" in
	// microseconds, or "max <period>" for none). Readable when this runs as
	// root on the Incus host's own cgroup tree; otherwise only the config
	// keys are checked.
	cpuMax := func() (string, bool) {
		for _, dir := range []string{"lxc.payload." + name, filepath.Join("lxc.payload."+name, "..", "lxc.payload."+name)} {
			if b, err := os.ReadFile(filepath.Join("/sys/fs/cgroup", dir, "cpu.max")); err == nil {
				return strings.TrimSpace(string(b)), true
			}
		}
		return "", false
	}
	origMax, haveMax := cpuMax()

	// THROTTLE: 10% of one core becomes the hard quota 10ms/100ms (never the
	// soft share "10%"), limits.cpu untouched; release restores exactly what
	// was recorded.
	fx.setDefault(t, pb.ProcessAction_PROCESS_ACTION_THROTTLE, "10%", 0)
	fire("203.0.113.9:3333")
	count, allow, err := act.CPULimit(name)
	if err != nil {
		t.Fatalf("CPULimit after throttle: %v", err)
	}
	if allow != "10ms/100ms" || count != origCount {
		t.Fatalf("after throttle: limits.cpu=%q allowance=%q, want %q/10ms/100ms", count, allow, origCount)
	}
	if haveMax {
		if got, _ := cpuMax(); got != "10000 100000" {
			t.Fatalf("after throttle: kernel cpu.max = %q, want a hard quota \"10000 100000\" (was %q)", got, origMax)
		}
	}
	if _, err := r.Release(ctx, name); err != nil {
		t.Fatalf("Release throttle: %v", err)
	}
	count, allow, _ = act.CPULimit(name)
	if count != origCount || allow != origAllow {
		t.Fatalf("after release: limits.cpu=%q allowance=%q, want original %q/%q", count, allow, origCount, origAllow)
	}
	if haveMax {
		if got, _ := cpuMax(); got != origMax {
			t.Fatalf("after release: kernel cpu.max = %q, want original %q", got, origMax)
		}
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
