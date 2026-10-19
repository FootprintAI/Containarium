package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/netbpf"
	"github.com/footprintai/containarium/internal/threatdetect"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// TestAsyncActingSink_StalledIncusDoesNotBlockExecConsumer (#2638 review):
// with kill_process on and the Incus init-pid read stalled, the exec ring
// consumer (ExecWatcher.OnExecEvent → engine → ActingSink) keeps returning:
// the responder works on its own queue, a full queue drops (counted), and
// the drop is audited once the worker moves again.
func TestAsyncActingSink_StalledIncusDoesNotBlockExecConsumer(t *testing.T) {
	fx := newResponderFixture(t, false)
	fx.setKill(t, "", true)
	stall := make(chan struct{})
	fx.r.SetProcessKiller(&hostProcessKiller{
		procRoot: t.TempDir(),
		initPID: func(string) (int64, error) {
			<-stall // Incus GetInstanceState hanging
			return 0, errors.New("incus timed out")
		},
		open: func(int) (pidHandle, error) { t.Error("must not reach open"); return nil, errKillProcessGone },
	})

	engine := threatdetect.NewEngine(NewAsyncActingSink(fx.findings, fx.r), "b1", false, nil, nil)
	rule, err := threatdetect.NewMinerSignatureRule(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	engine.Register(rule)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go fx.r.Run(ctx)

	w := NewExecWatcher(engine.OnExec)
	w.byCgroup[42] = execTarget{Container: "box-a", TenantID: "tenant-a"}

	const execs = processResponseQueue + 50
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < execs; i++ {
			w.OnExecEvent(ctx, netbpf.ExecEvent{HostPID: uint32(1000 + i), CgroupID: 42, Comm: "xmrig",
				Filename: "/tmp/xmrig", Argv: []string{"./xmrig", "--donate-level", "1"}})
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		close(stall)
		t.Fatal("exec consumer blocked behind a stalled Incus call")
	}
	if got := fx.findings.byRule(pb.ThreatRuleId_THREAT_RULE_ID_MINER_SIGNATURE); len(got) != 1 || got[0].Count != execs {
		t.Fatalf("findings = %d, want one with count %d (detection must not depend on the responder)", len(got), execs)
	}
	if fx.r.DroppedResponses() == 0 {
		t.Fatal("a full queue dropped nothing; it must drop, not block")
	}

	close(stall)
	deadline := time.Now().Add(5 * time.Second)
	for len(auditDetails(fx.audit, "response-dropped")) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("dropped responses were never audited")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(auditDetails(fx.audit, "kill")) != 0 {
		t.Fatal("a kill went through although the init-pid read failed")
	}
}

// TestAsyncActingSink_OnlyRespondableFindingsQueue: a finding the responder
// can never act on (posture, MEDIUM, ...) takes no queue slot.
func TestAsyncActingSink_OnlyRespondableFindingsQueue(t *testing.T) {
	fx := newResponderFixture(t, false)
	sink := NewAsyncActingSink(fx.findings, fx.r)
	for _, f := range []*threatdetect.Finding{
		{Rule: pb.ThreatRuleId_THREAT_RULE_ID_BOX_SSHD_PASSWORD_AUTH, Severity: pb.ThreatSeverity_THREAT_SEVERITY_HIGH, TenantID: "t", Container: "box-a", Subject: "a"},
		{Rule: ruleMinerSignature, Severity: pb.ThreatSeverity_THREAT_SEVERITY_MEDIUM, TenantID: "t", Container: "box-a", Subject: "b"},
		{Rule: ruleMinerSignature, Severity: pb.ThreatSeverity_THREAT_SEVERITY_HIGH, TenantID: "t", Subject: "c"},
	} {
		if _, err := sink.Upsert(context.Background(), f); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(fx.r.queue); n != 0 {
		t.Fatalf("queue holds %d jobs, want 0", n)
	}
	if _, err := sink.Upsert(context.Background(), &threatdetect.Finding{Rule: ruleMinerSignature,
		Severity: pb.ThreatSeverity_THREAT_SEVERITY_HIGH, TenantID: "t", Container: "box-a", Subject: "d"}); err != nil {
		t.Fatal(err)
	}
	if n := len(fx.r.queue); n != 1 {
		t.Fatalf("queue holds %d jobs, want 1", n)
	}
}
