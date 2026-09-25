package server

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/tracker"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// A panic in a dispatched run's background half (#2050) must not skip
// the lease end, the JWT revocation or the completion report, and must
// not take the daemon down with it.

// panicPayload stands in for anything a panicking agent seam could carry
// (a token, a prompt). It must never reach the outcome or the row.
const panicPayload = "secret-in-panic-payload"

func panickingAgent(string, string) (string, error) { panic(panicPayload) }

// TestFinishDispatchedRun_AgentPanicEndsLeaseAndFailsRun: the panic is
// recovered inside finishDispatchedRun. The lease still ends first (both
// JTIs revoked, run unregistered), then the run is reported failed — the
// same order as the normal path — and the payload is not in the outcome.
func TestFinishDispatchedRun_AgentPanicEndsLeaseAndFailsRun(t *testing.T) {
	const runID = "run-hook-panic"
	s, registry, store := newFinishHarness(t, runID)
	lc := newRecordingLifecycle()
	lc.registry, lc.runID = registry, runID

	var escaped any
	func() {
		defer func() { escaped = recover() }()
		s.finishDispatchedRun(ctxAs("alice", true), &startedSkillRun{runID: runID, lease: testLease(runID)}, panickingAgent, lc)
	}()
	if escaped != nil {
		t.Fatalf("the agent's panic escaped finishDispatchedRun (%v): in its goroutine that kills the daemon", escaped)
	}

	events, outcome, _ := lc.snapshot()
	if strings.Join(events, ",") != "ended" {
		t.Fatalf("events = %v, want exactly one end report", events)
	}
	if outcome.Err == nil {
		t.Fatal("outcome = success, want a failed run")
	}
	if strings.Contains(outcome.Err.Error(), panicPayload) {
		t.Errorf("outcome %q carries the panic payload", outcome.Err)
	}
	if lc.liveAtEnd {
		t.Error("run still live when its end was reported; the lease must end first")
	}
	if registry.Live(runID) {
		t.Error("run still registered after the panic")
	}
	for _, jti := range []string{"jti-platform", "jti-gateway"} {
		if revoked, err := store.IsRevoked(context.Background(), jti); err != nil || !revoked {
			t.Errorf("%s revoked = %v (err %v), want true after the panicking run", jti, revoked, err)
		}
	}
}

// TestLaunchDispatchedRun_AgentPanicDoesNotKillDaemon goes through the
// real background goroutine. Without a recover there this test binary
// dies, which is what the daemon would do.
func TestLaunchDispatchedRun_AgentPanicDoesNotKillDaemon(t *testing.T) {
	const runID = "run-hook-panic-goroutine"
	s, registry, _ := newFinishHarness(t, runID)
	lc := newRecordingLifecycle()
	s.launchDispatchedRun(ctxAs("alice", true), &startedSkillRun{runID: runID, lease: testLease(runID)}, lc, panickingAgent)
	select {
	case <-lc.ended:
	case <-time.After(10 * time.Second):
		t.Fatal("the run's end was never reported after the agent panicked")
	}
	events, outcome, _ := lc.snapshot()
	if strings.Join(events, ",") != "started,ended" || outcome.Err == nil {
		t.Fatalf("events = %v, outcome = %v; want started then a failed end", events, outcome.Err)
	}
	if registry.Live(runID) {
		t.Error("run still registered after the panic")
	}
}

// lifecycleCapture is a RunStarter that accepts every run and hands its
// lifecycle to the test, which then drives the run itself.
type lifecycleCapture func(req tracker.StartRunRequest)

func (f lifecycleCapture) StartRun(_ context.Context, req tracker.StartRunRequest) error {
	f(req)
	return nil
}

// goexitRevoker ends the calling goroutine with runtime.Goexit inside
// the lease end's first revocation.
type goexitRevoker struct{ *fakeRevocationStore }

func (goexitRevoker) Revoke(context.Context, string, time.Time, string) error {
	runtime.Goexit()
	return nil
}

// TestLaunchDispatchedRun_GoexitIsNotSuccess: runtime.Goexit is not a
// panic (recover returns nil) but the run never completed. Whether it
// happens in the agent seam or inside the lease end, the run's end must
// be reported FAILED with a generic reason, never done, and a Goexit in
// the agent still ends the lease first.
func TestLaunchDispatchedRun_GoexitIsNotSuccess(t *testing.T) {
	for _, tc := range []struct {
		name         string
		agent        func(string, string) (string, error)
		goexitRevoke bool
	}{
		{name: "in the agent", agent: func(string, string) (string, error) { runtime.Goexit(); return `{"summary":"ok"}`, nil }},
		{name: "in the lease end", agent: func(string, string) (string, error) { return `{"summary":"ok"}`, nil }, goexitRevoke: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const runID = "run-hook-goexit"
			s, registry, store := newFinishHarness(t, runID)
			if tc.goexitRevoke {
				s.SetRevocationStore(goexitRevoker{store})
			}
			lc := newRecordingLifecycle()
			lc.registry, lc.runID = registry, runID
			s.launchDispatchedRun(ctxAs("alice", true), &startedSkillRun{runID: runID, lease: testLease(runID)}, lc, tc.agent)
			select {
			case <-lc.ended:
			case <-time.After(10 * time.Second):
				t.Fatal("the run's end was never reported after runtime.Goexit")
			}
			events, outcome, _ := lc.snapshot()
			if strings.Join(events, ",") != "started,ended" {
				t.Fatalf("events = %v, want started then ended", events)
			}
			if outcome.Err == nil {
				t.Fatal("outcome = success for a run that never completed")
			}
			if outcome.Err.Error() != errDispatchedRunDidNotComplete.Error() {
				t.Errorf("outcome = %q, want the generic %q", outcome.Err, errDispatchedRunDidNotComplete)
			}
			if lc.liveAtEnd || registry.Live(runID) {
				t.Error("run still registered; the lease end must run before the end is reported")
			}
			if tc.goexitRevoke {
				return // the revocation itself was cut short
			}
			for _, jti := range []string{"jti-platform", "jti-gateway"} {
				if revoked, err := store.IsRevoked(context.Background(), jti); err != nil || !revoked {
					t.Errorf("%s revoked = %v (err %v), want true", jti, revoked, err)
				}
			}
		})
	}
}

// TestFinishDispatchedRun_AgentPanicMarksDispatchFailed: with the real
// completion hook and Postgres, a panicking run's dispatch row ends
// FAILED instead of staying RUNNING forever.
func TestFinishDispatchedRun_AgentPanicMarksDispatchFailed(t *testing.T) {
	const user = "tracker-dispatch-panic"
	issue := tracker.Issue{Number: 42, Title: "idea", State: pb.TrackerIssueState_TRACKER_ISSUE_STATE_OPEN, Labels: []string{"scope:product"}}
	provider := &fakeWriterProvider{fakeReaderProvider: fakeReaderProvider{issues: []tracker.Issue{issue}, issue: issue}}
	ctx := context.Background()
	_ = mustTestTrackerStore(t).Delete(ctx, user, "default")
	cs, _ := setUpWriterConnection(t, user, provider)
	if _, err := cs.trackerStore.SetRoute(ctx, tracker.Route{Username: user, Connection: "default", Scope: "product", SkillID: "product-define"}); err != nil {
		t.Fatalf("SetRoute: %v", err)
	}
	const runID = "run-dispatch-panic"
	agents, registry, _ := newFinishHarness(t, runID)
	var lc tracker.RunLifecycle
	cs.SetTrackerRunStarter(lifecycleCapture(func(req tracker.StartRunRequest) { lc = req.Lifecycle }))
	admin := kmsKeyTestCtx(user, "member", "tracker:admin,agents:run")
	if resp, err := cs.DispatchTrackerIssues(admin, &pb.DispatchTrackerIssuesRequest{Username: user, Connection: "default"}); err != nil || len(resp.GetStarted()) != 1 {
		t.Fatalf("DispatchTrackerIssues = (%+v, %v), want one started", resp, err)
	}
	if lc == nil {
		t.Fatal("the starter was not handed a lifecycle")
	}

	agents.launchDispatchedRun(admin, &startedSkillRun{runID: runID, lease: testLease(runID)}, lc, panickingAgent)
	deadline := time.Now().Add(10 * time.Second)
	for {
		rows, err := cs.trackerStore.ListDispatches(ctx, user, "default", pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_FAILED)
		if err != nil {
			t.Fatalf("ListDispatches: %v", err)
		}
		if len(rows) == 1 {
			if strings.Contains(rows[0].FailureReason, panicPayload) {
				t.Errorf("failure_reason %q carries the panic payload", rows[0].FailureReason)
			}
			break
		}
		if time.Now().After(deadline) {
			all, _ := cs.trackerStore.ListDispatches(ctx, user, "default", pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_UNSPECIFIED)
			t.Fatalf("dispatch rows = %+v, want the panicking run's row FAILED", all)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if registry.Live(runID) {
		t.Error("run still registered after the panic")
	}
}
