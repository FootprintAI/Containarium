package server

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/tracker"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// Timeout / lease-lost sweep, server half (#2026): the production
// RunStarter is also the dispatcher's view of live runs. A dispatched
// run is live from StartRun until its end has been reported — not just
// until its lease ended — so the sweep never mistakes a run that is
// finishing for a lost one; the sweep can end a live run's lease, and
// the run's own end then does not end it a second time; and a panic or
// runtime.Goexit in the run's background half still stops it being
// live.

// countingRevoker counts every revocation call.
type countingRevoker struct {
	*fakeRevocationStore
	mu sync.Mutex
	n  int
}

func (c *countingRevoker) Revoke(ctx context.Context, jti string, exp time.Time, reason string) error {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
	return c.fakeRevocationStore.Revoke(ctx, jti, exp, reason)
}

func (c *countingRevoker) calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

var _ tracker.RunLeases = trackerRunStarter{}

func waitNotLive(t *testing.T, leases tracker.RunLeases, runID string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for leases.Live(runID) {
		if time.Now().After(deadline) {
			t.Fatalf("run %s still live after its end was reported", runID)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The sweep ends a live run's lease (both JWTs revoked); when the run's
// agent finally returns, its lease is not ended again, its end is still
// reported, and only then does it stop being live.
func TestTrackerRunLeases_SweepEndsLeaseOnce(t *testing.T) {
	const runID = "run-sweep-once"
	s, _, store := newFinishHarness(t, runID)
	rev := &countingRevoker{fakeRevocationStore: store}
	s.SetRevocationStore(rev)
	leases := trackerRunStarter{s}

	release := make(chan struct{})
	lc := newRecordingLifecycle()
	s.launchDispatchedRun(ctxAs("alice", true), &startedSkillRun{runID: runID, lease: testLease(runID)}, lc,
		func(string, string) (string, error) { <-release; return "{}", nil })
	if !leases.Live(runID) {
		t.Fatal("a launched run is not live")
	}

	leases.End(context.Background(), runID) // the timeout sweep
	if got := rev.calls(); got != 2 {
		t.Fatalf("revocations after the sweep's End = %d, want 2 (both JWTs)", got)
	}
	if !leases.Live(runID) {
		t.Error("run stopped being live before its end was reported")
	}

	close(release)
	<-lc.ended
	waitNotLive(t, leases, runID)
	if got := rev.calls(); got != 2 {
		t.Errorf("revocations after the run ended = %d, want still 2 (the lease ends once)", got)
	}
	leases.End(context.Background(), runID) // a late sweep: a no-op
	if got := rev.calls(); got != 2 {
		t.Errorf("revocations after a late End = %d, want still 2", got)
	}
}

// The other ordering: the run's own end comes first and the sweep's End
// arrives while that end is still being reported (the run is still
// live). The lease was already ended by the run, so the sweep's End must
// not revoke again.
func TestTrackerRunLeases_RunEndFirstThenSweepEndsOnce(t *testing.T) {
	const runID = "run-end-first"
	s, _, store := newFinishHarness(t, runID)
	rev := &countingRevoker{fakeRevocationStore: store}
	s.SetRevocationStore(rev)
	leases := trackerRunStarter{s}

	var liveAtSweep bool
	lc := &callbackLifecycle{onEnd: func() {
		liveAtSweep = leases.Live(runID)
		leases.End(context.Background(), runID) // the sweep lands mid-report
	}}
	done := make(chan struct{})
	lc.after = func() { close(done) }
	s.launchDispatchedRun(ctxAs("alice", true), &startedSkillRun{runID: runID, lease: testLease(runID)}, lc,
		func(string, string) (string, error) { return "{}", nil })
	<-done
	if !liveAtSweep {
		t.Fatal("run not live while its end was reported; the sweep's End took the not-live path and the ordering is untested")
	}
	waitNotLive(t, leases, runID)
	if got := rev.calls(); got != 2 {
		t.Errorf("revocations = %d, want 2 (the run's own end only; the sweep's End is a no-op)", got)
	}
}

// Security (#2026): a run the sweep timed out while it was still
// provisioning must not run on with live credentials. The sweep's End
// finds no lease yet; when provisioning returns and the start report
// says the dispatch already ended, the run's lease is ended on the spot
// (both JWTs revoked, run unregistered), its agent is never launched,
// and it stops being live.
func TestLaunchDispatchedRun_EndedBeforeLaunchIsTornDown(t *testing.T) {
	const runID = "run-ended-before-launch"
	s, registry, store := newFinishHarness(t, runID)
	rev := &countingRevoker{fakeRevocationStore: store}
	s.SetRevocationStore(rev)
	leases := trackerRunStarter{s}

	// StartRun has begun (the run is held) but it is still provisioning
	// when the timeout sweep fails its row and tries to end its lease.
	s.dispatched.track(runID)
	leases.End(context.Background(), runID)
	if got := rev.calls(); got != 0 {
		t.Fatalf("revocations while provisioning = %d, want 0 (no lease yet)", got)
	}

	// Provisioning succeeds after all; the start report loses its CAS.
	lc := newRecordingLifecycle()
	lc.rejectStart = true
	agentRan := make(chan struct{}, 1)
	launched := s.launchDispatchedRun(ctxAs("alice", true), &startedSkillRun{runID: runID, lease: testLease(runID)}, lc,
		func(string, string) (string, error) { agentRan <- struct{}{}; return "{}", nil })
	if launched {
		t.Fatal("launchDispatchedRun = true for a dispatch that already ended")
	}
	if got := rev.calls(); got != 2 {
		t.Errorf("revocations = %d, want 2 (both JWTs revoked at once)", got)
	}
	for _, jti := range []string{"jti-platform", "jti-gateway"} {
		if revoked, _ := store.IsRevoked(context.Background(), jti); !revoked {
			t.Errorf("%s not revoked", jti)
		}
	}
	if registry.Live(runID) {
		t.Error("run still registered after the teardown")
	}
	if leases.Live(runID) {
		t.Error("run still live to the sweep after the teardown")
	}
	select {
	case <-agentRan:
		t.Error("the in-box agent was launched for a dispatch that already ended")
	case <-time.After(100 * time.Millisecond):
	}
	if events, _, _ := lc.snapshot(); len(events) != 1 || events[0] != "started" {
		t.Errorf("lifecycle events = %v, want only the rejected start report", events)
	}
}

// A run is still live while its end is being reported, so a sweep
// racing the normal completion cannot fail it as lease-lost.
func TestTrackerRunLeases_LiveUntilEndReported(t *testing.T) {
	const runID = "run-sweep-live"
	s, _, _ := newFinishHarness(t, runID)
	leases := trackerRunStarter{s}
	var liveDuringReport bool
	lc := &callbackLifecycle{onEnd: func() { liveDuringReport = leases.Live(runID) }}
	done := make(chan struct{})
	lc.after = func() { close(done) }
	s.launchDispatchedRun(ctxAs("alice", true), &startedSkillRun{runID: runID, lease: testLease(runID)}, lc,
		func(string, string) (string, error) { return "{}", nil })
	<-done
	if !liveDuringReport {
		t.Error("run was not live while its end was being reported")
	}
	waitNotLive(t, leases, runID)
}

// A panic or runtime.Goexit in the run's background half still stops
// the run being live — a run stuck "live" would never be swept as
// lease-lost, and a Goexit must not leak the entry.
func TestTrackerRunLeases_PanicAndGoexitStopBeingLive(t *testing.T) {
	for _, tc := range []struct {
		name  string
		agent func(string, string) (string, error)
	}{
		{"panic", panickingAgent},
		{"goexit", func(string, string) (string, error) { runtime.Goexit(); return "{}", nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const runID = "run-sweep-abnormal"
			s, _, _ := newFinishHarness(t, runID)
			leases := trackerRunStarter{s}
			lc := newRecordingLifecycle()
			s.launchDispatchedRun(ctxAs("alice", true), &startedSkillRun{runID: runID, lease: testLease(runID)}, lc, tc.agent)
			select {
			case <-lc.ended:
			case <-time.After(10 * time.Second):
				t.Fatal("end never reported")
			}
			waitNotLive(t, leases, runID)
		})
	}
}

// End for an unknown run is a no-op, and a run whose StartRun failed is
// never left live.
func TestTrackerRunLeases_UnknownAndFailedStart(t *testing.T) {
	s, skill := newSkillBoxHarness(t, newFakeRevocationStore())
	s.trackerConnections = &fakeTrackerConnectionChecker{conn: &tracker.Connection{Username: "alice", Name: "default"}}
	leases := trackerRunStarter{s}
	leases.End(context.Background(), "run-never-seen")
	if leases.Live("run-never-seen") {
		t.Fatal("an unknown run is live")
	}
	if err := leases.StartRun(ctxAs("alice", true), tracker.StartRunRequest{
		Username: "alice", Connection: "default", SkillID: skill.Id, RunID: "run-start-fails",
	}); err == nil {
		t.Fatal("StartRun = nil, want the harness's provisioning error")
	}
	if leases.Live("run-start-fails") {
		t.Error("a run whose start failed is live")
	}
}

// callbackLifecycle runs hooks inside RunEnded.
type callbackLifecycle struct {
	onEnd func()
	after func()
}

func (c *callbackLifecycle) RunStarted(context.Context) bool { return true }

func (c *callbackLifecycle) RunEnded(context.Context, tracker.RunOutcome) {
	c.onEnd()
	c.after()
}

// The OTel observer emits the PRD's success metrics: one terminal-state
// count per ended dispatch, by state and failure cause, and the
// label-applied -> result latency.
func TestTrackerDispatchObserver_EmitsTerminalCountsAndLatency(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	obs, err := newTrackerDispatchObserver(mp.Meter("containarium"))
	if err != nil {
		t.Fatalf("newTrackerDispatchObserver: %v", err)
	}
	obs.DispatchEnded(tracker.DispatchEnded{Scope: "product", State: pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_DONE, Latency: 2 * time.Minute})
	for i := 0; i < 2; i++ {
		obs.DispatchEnded(tracker.DispatchEnded{Scope: "product", State: pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_FAILED,
			Failure: pb.TrackerDispatchFailure_TRACKER_DISPATCH_FAILURE_TIMEOUT, Latency: time.Hour})
	}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	counts := map[string]int64{}
	var latencyCount uint64
	var latencySum float64
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			switch m.Name {
			case trackerDispatchTerminalMetric:
				for _, dp := range m.Data.(metricdata.Sum[int64]).DataPoints {
					state, _ := dp.Attributes.Value("state")
					failure, _ := dp.Attributes.Value("failure")
					counts[state.AsString()+"/"+failure.AsString()] += dp.Value
				}
			case trackerDispatchLatencyMetric:
				for _, dp := range m.Data.(metricdata.Histogram[float64]).DataPoints {
					latencyCount += dp.Count
					latencySum += dp.Sum
				}
			}
		}
	}
	if counts["done/none"] != 1 || counts["failed/timeout"] != 2 || len(counts) != 2 {
		t.Errorf("terminal counts = %v, want done/none=1 failed/timeout=2", counts)
	}
	wantSum := (2*time.Minute + 2*time.Hour).Seconds()
	if latencyCount != 3 || latencySum != wantSum {
		t.Errorf("latency count/sum = %d/%v, want 3/%v", latencyCount, latencySum, wantSum)
	}
}

// The typed failure cause reaches the API (ListTrackerDispatches and the
// tick's timed_out rows).
func TestToProtoTrackerDispatch_CarriesFailure(t *testing.T) {
	got := toProtoTrackerDispatch(&tracker.Dispatch{ID: "d1", State: pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_FAILED,
		Failure: pb.TrackerDispatchFailure_TRACKER_DISPATCH_FAILURE_LEASE_LOST})
	if got.GetFailure() != pb.TrackerDispatchFailure_TRACKER_DISPATCH_FAILURE_LEASE_LOST {
		t.Fatalf("failure = %v, want LEASE_LOST", got.GetFailure())
	}
}
