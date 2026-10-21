package server

import (
	"context"
	"errors"
	"strings"
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

// queuedThrottle sets a THROTTLE default and returns a fixture plus the
// async sink, with no worker running: jobs stay in fx.r.queue until a test
// hands them to runJob.
func queuedThrottle(t *testing.T) (*responderFixture, *ActingSink) {
	t.Helper()
	fx := newResponderFixture(t, false)
	fx.setDefault(t, pb.ProcessAction_PROCESS_ACTION_THROTTLE, "10%", time.Hour)
	return fx, NewAsyncActingSink(fx.findings, fx.r)
}

func queueOne(t *testing.T, fx *responderFixture, sink *ActingSink) responseJob {
	t.Helper()
	if _, err := sink.Upsert(context.Background(), &threatdetect.Finding{Rule: ruleMinerSignature,
		Severity: pb.ThreatSeverity_THREAT_SEVERITY_HIGH, TenantID: "tenant-a", Container: "box-a", Subject: "name:xmrig"}); err != nil {
		t.Fatal(err)
	}
	select {
	case job := <-fx.r.queue:
		return job
	default:
		t.Fatal("nothing queued")
		return responseJob{}
	}
}

func setCPUCalls(fx *responderFixture) int {
	fx.act.mu.Lock()
	defer fx.act.mu.Unlock()
	n := 0
	for _, c := range fx.act.calls {
		if strings.HasPrefix(c, "SetCPULimit:") {
			n++
		}
	}
	return n
}

// TestQueuedResponse_DoesNotUndoOperatorRelease (#2638 re-review blocker): a
// response already queued when the operator releases the action must not
// re-throttle the box or write APPLIED onto the resolved finding.
func TestQueuedResponse_DoesNotUndoOperatorRelease(t *testing.T) {
	ctx := context.Background()
	fx, sink := queuedThrottle(t)
	first := queueOne(t, fx, sink)
	fx.r.runJob(ctx, first) // the throttle is applied
	if _, err := fx.actions.Open(ctx, "box-a"); err != nil {
		t.Fatalf("first job did not apply: %v", err)
	}
	stale := queueOne(t, fx, sink) // the rule re-fires while throttled
	if _, _, err := fx.r.Release(ctx, "box-a"); err != nil {
		t.Fatal(err)
	}
	before := setCPUCalls(fx)

	fx.r.runJob(ctx, stale)

	if n := setCPUCalls(fx); n != before {
		t.Fatalf("worker touched the CPU limit %d time(s) after the release", n-before)
	}
	if _, err := fx.actions.Open(ctx, "box-a"); !errors.Is(err, threatdetect.ErrNoOpenAction) {
		t.Fatalf("an action is open again after the release: %v", err)
	}
	f, _ := fx.findings.Get(ctx, stale.f.ID)
	if f.State != threatdetect.FindingStateResolved || f.Response == nil || f.Response.State != pb.ResponseState_RESPONSE_STATE_RELEASED {
		t.Fatalf("finding = state %s response %+v, want resolved with RELEASED", f.State, f.Response)
	}
	if d := auditDetails(fx.audit, "response-skipped"); len(d) != 1 || !strings.Contains(d[0], "no longer open") {
		t.Fatalf("response-skipped audit = %v", d)
	}
}

// TestQueuedResponse_SkipsFindingResolvedWhileQueued: a finding the sentry
// (or an operator) resolved while its response waited is left alone.
func TestQueuedResponse_SkipsFindingResolvedWhileQueued(t *testing.T) {
	ctx := context.Background()
	fx, sink := queuedThrottle(t)
	job := queueOne(t, fx, sink)
	if _, err := fx.findings.Resolve(ctx, job.f.ID); err != nil {
		t.Fatal(err)
	}
	fx.r.runJob(ctx, job)
	if setCPUCalls(fx) != 0 {
		t.Fatal("throttled a box whose finding was resolved while queued")
	}
	if f, _ := fx.findings.Get(ctx, job.f.ID); f.Response != nil {
		t.Fatalf("wrote response %+v onto a resolved finding", f.Response)
	}
	if len(auditDetails(fx.audit, "response-skipped")) != 1 {
		t.Fatal("skip not audited")
	}
}

// TestQueuedResponse_SkipsActionReleasedAfterQueueing: the TTL backstop
// released the box's action after the job was queued, but the finding is
// still open: the stale job must not re-apply. The release is read from the
// box's own action row (#2766).
func TestQueuedResponse_SkipsActionReleasedAfterQueueing(t *testing.T) {
	ctx := context.Background()
	fx, sink := queuedThrottle(t)
	fx.r.runJob(ctx, queueOne(t, fx, sink)) // box-a throttled
	job := queueOne(t, fx, sink)            // the rule re-fires while throttled
	if n := fx.r.SweepExpired(ctx, fx.clock.Add(2*time.Hour)); n != 1 {
		t.Fatalf("SweepExpired released %d, want 1", n)
	}
	before := setCPUCalls(fx)
	fx.r.runJob(ctx, job)
	if n := setCPUCalls(fx); n != before {
		t.Fatal("re-applied an action released after the job was queued")
	}
	if f, _ := fx.findings.Get(ctx, job.f.ID); f.State != threatdetect.FindingStateOpen {
		t.Fatalf("finding state = %s, want open (a TTL release does not resolve)", f.State)
	}
	if d := auditDetails(fx.audit, "response-skipped"); len(d) != 1 || !strings.Contains(d[0], "released by ttl") {
		t.Fatalf("response-skipped audit = %v", d)
	}
}

// queueSignature queues a miner-signature finding carrying the exec a kill
// would target (pid), with no worker running.
func queueSignature(t *testing.T, fx *responderFixture, sink *ActingSink, pid uint32) responseJob {
	t.Helper()
	if _, err := sink.Upsert(context.Background(), &threatdetect.Finding{Rule: ruleMinerSignature,
		Severity: pb.ThreatSeverity_THREAT_SEVERITY_HIGH, TenantID: "tenant-a", Container: "box-a", Subject: "name:xmrig",
		Evidence: threatdetect.Evidence{Execs: []threatdetect.ExecEvidence{{PID: pid, Comm: "xmrig", Filename: "/tmp/xmrig",
			Argv: "./xmrig --donate-level 1", Matched: "name:xmrig"}}},
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case job := <-fx.r.queue:
		if job.target == nil || job.target.PID != pid {
			t.Fatalf("queued target = %+v, want pid %d", job.target, pid)
		}
		return job
	default:
		t.Fatal("nothing queued")
		return responseJob{}
	}
}

// killerFunc adapts a function to processKiller, for a kill that does
// something mid-flight.
type killerFunc func(container string, pid uint32) error

func (k killerFunc) KillInContainer(container string, pid uint32, _ threatdetect.ProcStartTicks) error {
	return k(container, pid)
}

// TestQueuedResponse_ResolvedBeforeWorkerSkipsKill (#2638 review blocker 2):
// the finding was released or resolved after the job was queued and before
// the worker got to it. The kill must not run at all: no SIGKILL, no "kill"
// audit row, only "response-skipped". Pins the contract that a stale job
// never reaches the killer; the race the review found (a release landing
// between the worker's first look and its lock) is the next test.
func TestQueuedResponse_ResolvedBeforeWorkerSkipsKill(t *testing.T) {
	ctx := context.Background()
	fx, sink := queuedThrottle(t)
	fx.setKill(t, "", true)
	killer := &fakeKiller{}
	fx.r.SetProcessKiller(killer)

	job := queueSignature(t, fx, sink, 4242)
	if _, err := fx.findings.Resolve(ctx, job.f.ID); err != nil { // operator closes it while the job waits
		t.Fatal(err)
	}
	fx.r.runJob(ctx, job)

	if len(killer.calls) != 0 {
		t.Fatalf("killed %v for a finding resolved before the worker ran", killer.calls)
	}
	if d := auditDetails(fx.audit, "kill"); len(d) != 0 {
		t.Fatalf("kill audited %v for a finding resolved before the worker ran", d)
	}
	if setCPUCalls(fx) != 0 {
		t.Fatal("throttled a box whose finding was resolved while queued")
	}
	if d := auditDetails(fx.audit, "response-skipped"); len(d) != 1 || !strings.Contains(d[0], "no longer open") {
		t.Fatalf("response-skipped audit = %v, want exactly one (no longer open)", d)
	}
	if f, _ := fx.findings.Get(ctx, job.f.ID); f.Response != nil {
		t.Fatalf("wrote response %+v onto a resolved finding", f.Response)
	}
}

// TestQueuedResponse_ResolvedDuringKillRecordsProcessKilled: the recheck
// passed, the kill ran (outside r.mu, so a release can still land during
// its Incus read), and the finding was resolved before the worker took the
// lock again. The policy action is skipped, but the process IS dead, so
// process_killed is recorded on the response the release left behind
// rather than lost.
func TestQueuedResponse_ResolvedDuringKillRecordsProcessKilled(t *testing.T) {
	ctx := context.Background()
	fx, sink := queuedThrottle(t)
	fx.setKill(t, "", true)
	job := queueSignature(t, fx, sink, 4242)
	kills := 0
	fx.r.SetProcessKiller(killerFunc(func(string, uint32) error {
		kills++
		if _, err := fx.findings.Resolve(ctx, job.f.ID); err != nil { // lands while the kill is in flight
			t.Fatal(err)
		}
		return nil
	}))

	fx.r.runJob(ctx, job)

	if kills != 1 || len(auditDetails(fx.audit, "kill")) != 1 {
		t.Fatalf("kills = %d, kill audits = %v; want one of each", kills, auditDetails(fx.audit, "kill"))
	}
	if setCPUCalls(fx) != 0 {
		t.Fatal("throttled a box whose finding was resolved during the kill")
	}
	if _, err := fx.actions.Open(ctx, "box-a"); !errors.Is(err, threatdetect.ErrNoOpenAction) {
		t.Fatalf("an action is open on a resolved finding: %v", err)
	}
	if len(auditDetails(fx.audit, "response-skipped")) != 1 {
		t.Fatal("skipped policy action not audited")
	}
	f, _ := fx.findings.Get(ctx, job.f.ID)
	if f.State != threatdetect.FindingStateResolved || f.Response == nil || !f.Response.ProcessKilled {
		t.Fatalf("finding = state %s response %+v, want resolved with process_killed=true", f.State, f.Response)
	}
	if f.Response.State != pb.ResponseState_RESPONSE_STATE_NONE || f.Response.Action != pb.ProcessAction_PROCESS_ACTION_ALERT {
		t.Fatalf("response = %+v, want ALERT/NONE (no policy action was applied)", f.Response)
	}
}

// TestQueuedResponse_StillOpenIsActedOn: the re-check does not swallow a
// current job.
func TestQueuedResponse_StillOpenIsActedOn(t *testing.T) {
	ctx := context.Background()
	fx, sink := queuedThrottle(t)
	job := queueOne(t, fx, sink)
	fx.r.runJob(ctx, job)
	row, err := fx.actions.Open(ctx, "box-a")
	if err != nil || row.Action != pb.ProcessAction_PROCESS_ACTION_THROTTLE {
		t.Fatalf("open action = %+v, %v; want THROTTLE", row, err)
	}
	f, _ := fx.findings.Get(ctx, job.f.ID)
	if f.Response == nil || f.Response.State != pb.ResponseState_RESPONSE_STATE_APPLIED {
		t.Fatalf("response = %+v, want APPLIED", f.Response)
	}
	if len(auditDetails(fx.audit, "response-skipped")) != 0 {
		t.Fatal("a current job was skipped")
	}
}
