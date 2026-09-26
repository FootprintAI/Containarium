package tracker

import (
	"context"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Failure visibility (#2026): a run that errors, loses its lease, or
// outlives the connection policy's run timeout ends FAILED with a typed
// cause, agent:failed, and one comment naming the run and the reason;
// every terminal transition is observed once for the PRD's metrics.
// Real Postgres store, fake forge, fake leases, injected clock.

// fakeLeases is the daemon's live-run view: a run is live until ended.
type fakeLeases struct {
	mu    sync.Mutex
	live  map[string]bool
	ended []string
	// onEnd runs inside End, before it returns (a test hook: cancel the
	// tick, panic, or record ordering).
	onEnd func(runID string)
}

func newFakeLeases() *fakeLeases { return &fakeLeases{live: map[string]bool{}} }

func (f *fakeLeases) Live(runID string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.live[runID]
}

func (f *fakeLeases) End(_ context.Context, runID string) {
	f.mu.Lock()
	f.ended = append(f.ended, runID)
	delete(f.live, runID)
	hook := f.onEnd
	f.mu.Unlock()
	if hook != nil {
		hook(runID)
	}
}

func (f *fakeLeases) setLive(runID string, live bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.live[runID] = live
}

func (f *fakeLeases) endedRuns() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.ended...)
}

// fakeObserver records every terminal event.
type fakeObserver struct {
	mu     sync.Mutex
	events []DispatchEnded
}

func (f *fakeObserver) DispatchEnded(ev DispatchEnded) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, ev)
}

func (f *fakeObserver) all() []DispatchEnded {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]DispatchEnded(nil), f.events...)
}

// ctxProvider makes every forge write honour its context, so a test can
// prove the bookkeeping runs on a detached one.
type ctxProvider struct{ *fakeDispatchProvider }

func (c ctxProvider) SetLabels(ctx context.Context, conn Conn, n int64, add, remove []string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.fakeDispatchProvider.SetLabels(ctx, conn, n, add, remove)
}

func (c ctxProvider) Comment(ctx context.Context, conn Conn, n int64, body string) (Comment, error) {
	if err := ctx.Err(); err != nil {
		return Comment{}, err
	}
	return c.fakeDispatchProvider.Comment(ctx, conn, n, body)
}

const sweepTimeout = time.Hour

// newSweepFixture: one routed issue, dispatched and RUNNING, its run
// live in fakeLeases.
func newSweepFixture(t *testing.T, user string) (*Dispatcher, *Store, *fakeDispatchProvider, *lifecycleRunStarter, *fakeLeases, *fakeObserver, context.Context) {
	t.Helper()
	d, store, provider, runs, ctx := newLifecycleFixture(t, user, Issue{Number: 7, Labels: []string{"scope:product"}})
	leases, obs := newFakeLeases(), &fakeObserver{}
	d.Policy = &Policy{RunTimeout: sweepTimeout}
	d.Leases, d.Observer = leases, obs
	res, err := d.Tick(ctx, user, "default")
	if err != nil || len(res.Started) != 1 {
		t.Fatalf("Tick = (%+v, %v), want one started", res, err)
	}
	leases.setLive(res.Started[0].RunID, true)
	return d, store, provider, runs, leases, obs, ctx
}

func clockOf(t *testing.T, d *Dispatcher) *fakeClock {
	t.Helper()
	c, ok := d.Clock.(*fakeClock)
	if !ok {
		t.Fatalf("clock is %T, want *fakeClock", d.Clock)
	}
	return c
}

// assertFailedOnce checks the row is FAILED with the given cause, the
// issue carries only agent:failed among state labels, and exactly one
// dispatcher comment names the run and says why.
func assertFailedOnce(t *testing.T, store *Store, provider *fakeDispatchProvider, ctx context.Context, user string, issue int64, want pb.TrackerDispatchFailure, reasonText string) Dispatch {
	t.Helper()
	row := onlyRow(t, store, ctx, user)
	if row.State != pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_FAILED || row.Failure != want || row.EndedAt.IsZero() {
		t.Fatalf("row = %+v, want FAILED with failure %v and ended_at", row, want)
	}
	labels := provider.labels(issue)
	if !containsString(labels, LabelAgentFailed) || containsString(labels, LabelAgentRunning) || containsString(labels, LabelAgentQueued) {
		t.Errorf("labels = %v, want %s only among state labels", labels, LabelAgentFailed)
	}
	comments := provider.commentsOn(issue)
	if len(comments) != 1 {
		t.Fatalf("comments = %q, want exactly one failure comment", comments)
	}
	for _, want := range []string{row.RunID, row.ID, reasonText} {
		if !strings.Contains(comments[0], want) {
			t.Errorf("comment = %q, want it to contain %q", comments[0], want)
		}
	}
	if _, _, kind, ok := ParseMarker(comments[0]); !ok || kind != KindComment {
		t.Errorf("comment = %q, want a platform identity stamp", comments[0])
	}
	return row
}

// A RUNNING row past the run timeout is failed by the next tick: lease
// ended, agent:failed, one comment with the run id and "timed out", one
// TIMEOUT event. The run's own late RunEnded and later ticks change
// nothing — no double report.
func TestDispatchSweep_TimeoutFailsRunningRowOnce(t *testing.T) {
	const user = "tracker-sweep-timeout"
	d, store, provider, runs, leases, obs, ctx := newSweepFixture(t, user)
	clock := clockOf(t, d)

	// Just inside the timeout: untouched.
	clock.Advance(sweepTimeout - time.Second)
	res, err := d.Tick(ctx, user, "default")
	if err != nil || len(res.TimedOut) != 0 {
		t.Fatalf("Tick inside timeout = (%+v, %v), want nothing timed out", res, err)
	}

	// Labels must follow the lease end, never precede it: the issue may
	// not say agent:failed while the run's credentials are still live.
	leases.onEnd = func(string) {
		if containsString(provider.labels(7), LabelAgentFailed) {
			t.Errorf("agent:failed projected before the lease was ended")
		}
	}
	clock.Advance(2 * time.Second)
	res, err = d.Tick(ctx, user, "default")
	if err != nil {
		t.Fatalf("Tick past timeout: %v", err)
	}
	if len(res.TimedOut) != 1 || res.TimedOut[0].Failure != pb.TrackerDispatchFailure_TRACKER_DISPATCH_FAILURE_TIMEOUT {
		t.Fatalf("TimedOut = %+v, want one TIMEOUT row", res.TimedOut)
	}
	row := assertFailedOnce(t, store, provider, ctx, user, 7, pb.TrackerDispatchFailure_TRACKER_DISPATCH_FAILURE_TIMEOUT, "timed out after 1h0m0s")
	if got := leases.endedRuns(); len(got) != 1 || got[0] != row.RunID {
		t.Errorf("leases ended = %v, want exactly [%s]", got, row.RunID)
	}

	// The run finally returns: its RunEnded loses the compare-and-set.
	runs.lifecycle(t, 0).RunEnded(ctx, RunOutcome{})
	// And later ticks do not sweep a terminal row again.
	for i := 0; i < 2; i++ {
		clock.Advance(sweepTimeout)
		if res, err := d.Tick(ctx, user, "default"); err != nil || len(res.TimedOut) != 0 {
			t.Fatalf("later Tick %d = (%+v, %v), want nothing timed out", i, res, err)
		}
	}
	assertFailedOnce(t, store, provider, ctx, user, 7, pb.TrackerDispatchFailure_TRACKER_DISPATCH_FAILURE_TIMEOUT, "timed out")
	if got := leases.endedRuns(); len(got) != 1 {
		t.Errorf("leases ended = %v, want exactly one End", got)
	}

	evs := obs.all()
	if len(evs) != 1 {
		t.Fatalf("observer events = %+v, want exactly one", evs)
	}
	ev := evs[0]
	if ev.State != pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_FAILED || ev.Failure != pb.TrackerDispatchFailure_TRACKER_DISPATCH_FAILURE_TIMEOUT || ev.Scope != "product" {
		t.Errorf("event = %+v, want FAILED/TIMEOUT for scope product", ev)
	}
	if want := sweepTimeout + time.Second; ev.Latency != want {
		t.Errorf("latency = %v, want %v (label applied -> result)", ev.Latency, want)
	}
}

// A RUNNING row whose run has no live lease (the daemon restarted) is
// failed LEASE_LOST once the grace period is over — not before, and not
// while the lease is live.
func TestDispatchSweep_LeaseLostAfterGrace(t *testing.T) {
	const user = "tracker-sweep-leaselost"
	d, store, provider, _, leases, obs, ctx := newSweepFixture(t, user)
	clock := clockOf(t, d)
	row := onlyRow(t, store, ctx, user)

	// Live run, well past the grace: untouched.
	clock.Advance(DefaultLeaseLostGrace + time.Minute)
	if res, err := d.Tick(ctx, user, "default"); err != nil || len(res.TimedOut) != 0 {
		t.Fatalf("Tick with live lease = (%+v, %v), want nothing swept", res, err)
	}

	// The daemon "restarts": the lease is gone. The grace is measured
	// from the start, which is already past it.
	leases.setLive(row.RunID, false)
	res, err := d.Tick(ctx, user, "default")
	if err != nil || len(res.TimedOut) != 1 {
		t.Fatalf("Tick after lease loss = (%+v, %v), want one swept", res, err)
	}
	assertFailedOnce(t, store, provider, ctx, user, 7, pb.TrackerDispatchFailure_TRACKER_DISPATCH_FAILURE_LEASE_LOST, "no live lease")
	if evs := obs.all(); len(evs) != 1 || evs[0].Failure != pb.TrackerDispatchFailure_TRACKER_DISPATCH_FAILURE_LEASE_LOST {
		t.Errorf("observer events = %+v, want one LEASE_LOST", evs)
	}
}

// A QUEUED row with no run behind it (a daemon that died mid-tick) is
// swept after the grace period instead of locking the issue forever,
// and a human can then re-run the issue.
func TestDispatchSweep_StrandedQueuedRowIsFreed(t *testing.T) {
	const user = "tracker-sweep-queued"
	provider := newFakeDispatchProvider(Issue{Number: 3, Labels: []string{"scope:product", LabelAgentQueued}})
	runs := &lifecycleRunStarter{}
	d, store, ctx := newDispatchFixture(t, user, provider, &fakeRunStarter{})
	d.Runs, d.Leases = runs, newFakeLeases()
	d.Policy = &Policy{RunTimeout: sweepTimeout}
	clock := clockOf(t, d)
	if _, err := store.InsertDispatch(ctx, Dispatch{
		Username: user, Connection: "default", IssueNumber: 3, Scope: "product", SkillID: "product-define",
		RunID: "run-stranded", CreatedAt: clock.Now(),
	}); err != nil {
		t.Fatalf("InsertDispatch: %v", err)
	}

	// Within the grace: a peer's tick may still be starting it.
	clock.Advance(DefaultLeaseLostGrace - time.Second)
	if res, err := d.Tick(ctx, user, "default"); err != nil || len(res.TimedOut) != 0 {
		t.Fatalf("Tick within grace = (%+v, %v), want nothing swept", res, err)
	}
	clock.Advance(2 * time.Second)
	if res, err := d.Tick(ctx, user, "default"); err != nil || len(res.TimedOut) != 1 {
		t.Fatalf("Tick past grace = (%+v, %v), want the stranded row swept", res, err)
	}
	assertFailedOnce(t, store, provider, ctx, user, 3, pb.TrackerDispatchFailure_TRACKER_DISPATCH_FAILURE_LEASE_LOST, "run-stranded")

	// The issue is no longer locked: a human retries, the next tick runs it.
	provider.relabel(3, "scope:product")
	res, err := d.Tick(ctx, user, "default")
	if err != nil || len(res.Started) != 1 {
		t.Fatalf("Tick after retry = (%+v, %v), want the issue dispatched again", res, err)
	}
}

// listBarrierStore holds every caller of the first `parties`
// ListDispatches(RUNNING) calls until all of them have listed, so
// concurrent sweeps are guaranteed to have read the same active rows
// before either one fails them — the race the compare-and-set decides.
type listBarrierStore struct {
	DispatchStore
	parties int

	mu      sync.Mutex
	arrived int
	release chan struct{}
}

func newListBarrierStore(s DispatchStore, parties int) *listBarrierStore {
	return &listBarrierStore{DispatchStore: s, parties: parties, release: make(chan struct{})}
}

func (b *listBarrierStore) ListDispatches(ctx context.Context, username, connection string, state pb.TrackerDispatchState) ([]Dispatch, error) {
	rows, err := b.DispatchStore.ListDispatches(ctx, username, connection, state)
	if state != pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_RUNNING {
		return rows, err
	}
	b.mu.Lock()
	b.arrived++
	if b.arrived == b.parties {
		close(b.release)
	}
	wait := b.arrived <= b.parties
	b.mu.Unlock()
	if wait {
		select {
		case <-b.release:
		case <-time.After(10 * time.Second):
			return nil, context.DeadlineExceeded // the other sweep never listed
		}
	}
	return rows, err
}

// Two dispatchers sweeping the same timed-out row at once report it
// once: one lease end, one comment, one event (the CAS picks the winner).
// The barrier guarantees both have listed the row as RUNNING before
// either fails it, so both really attempt the transition.
func TestDispatchSweep_ConcurrentSweepsReportOnce(t *testing.T) {
	const user = "tracker-sweep-concurrent"
	d, store, provider, _, leases, obs, ctx := newSweepFixture(t, user)
	clockOf(t, d).Advance(sweepTimeout + time.Minute)
	d.Store = newListBarrierStore(d.Store, 2)
	peer := *d

	var wg sync.WaitGroup
	for _, disp := range []*Dispatcher{d, &peer} {
		wg.Add(1)
		go func(disp *Dispatcher) {
			defer wg.Done()
			if _, err := disp.Tick(ctx, user, "default"); err != nil {
				t.Errorf("Tick: %v", err)
			}
		}(disp)
	}
	wg.Wait()

	assertFailedOnce(t, store, provider, ctx, user, 7, pb.TrackerDispatchFailure_TRACKER_DISPATCH_FAILURE_TIMEOUT, "timed out")
	if got := leases.endedRuns(); len(got) != 1 {
		t.Errorf("leases ended = %v, want exactly one End", got)
	}
	if evs := obs.all(); len(evs) != 1 {
		t.Errorf("observer events = %+v, want exactly one", evs)
	}
}

// A tick cancelled after the sweep won the transition still finishes the
// bookkeeping (labels and comment) on a detached, bounded context — the
// row is FAILED and the issue must say so.
func TestDispatchSweep_CancelledTickStillProjects(t *testing.T) {
	const user = "tracker-sweep-cancel"
	d, store, provider, _, leases, _, ctx := newSweepFixture(t, user)
	d.Provider = ctxProvider{provider}
	clockOf(t, d).Advance(sweepTimeout + time.Minute)

	tickCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	leases.onEnd = func(string) { cancel() } // the client gives up mid-sweep
	_, _ = d.Tick(tickCtx, user, "default")

	row := assertFailedOnce(t, store, provider, ctx, user, 7, pb.TrackerDispatchFailure_TRACKER_DISPATCH_FAILURE_TIMEOUT, "timed out")
	if row.LabelsPending {
		t.Errorf("row = %+v, want labels projected (not pending) despite the cancel", row)
	}
}

// A panic while ending the lease does not crash the tick or strand the
// projection: the row is already FAILED, so the issue must say so.
func TestDispatchSweep_LeaseEndPanicStillProjects(t *testing.T) {
	const user = "tracker-sweep-panic"
	d, store, provider, _, leases, obs, ctx := newSweepFixture(t, user)
	clockOf(t, d).Advance(sweepTimeout + time.Minute)
	leases.onEnd = func(string) { panic("boom") }

	res, err := d.Tick(ctx, user, "default")
	if err != nil || len(res.TimedOut) != 1 {
		t.Fatalf("Tick = (%+v, %v), want one timed out despite the panic", res, err)
	}
	assertFailedOnce(t, store, provider, ctx, user, 7, pb.TrackerDispatchFailure_TRACKER_DISPATCH_FAILURE_TIMEOUT, "timed out")
	if evs := obs.all(); len(evs) != 1 {
		t.Errorf("observer events = %+v, want exactly one", evs)
	}
}

// runtime.Goexit inside the lease end is not a panic (recover sees
// nil) and would end the tick's goroutine; it must still leave the tick
// alive and the failure projected.
func TestDispatchSweep_LeaseEndGoexitStillProjects(t *testing.T) {
	const user = "tracker-sweep-goexit"
	d, store, provider, _, leases, _, ctx := newSweepFixture(t, user)
	clockOf(t, d).Advance(sweepTimeout + time.Minute)
	leases.onEnd = func(string) { runtime.Goexit() }

	done := make(chan struct{})
	var res TickResult
	var err error
	go func() {
		defer close(done)
		res, err = d.Tick(ctx, user, "default")
		done <- struct{}{} // only reached if Tick itself returned
	}()
	returned := false
	select {
	case _, returned = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("tick never finished")
	}
	if !returned {
		t.Fatal("runtime.Goexit in the lease end ended the tick's goroutine")
	}
	if err != nil || len(res.TimedOut) != 1 {
		t.Fatalf("Tick = (%+v, %v), want one timed out", res, err)
	}
	assertFailedOnce(t, store, provider, ctx, user, 7, pb.TrackerDispatchFailure_TRACKER_DISPATCH_FAILURE_TIMEOUT, "timed out")
}

// A lease end that never returns must not swallow the failure report:
// the lease end has its own budget and the projection a fresh one after
// it, so the issue still gets agent:failed and the comment (and nothing
// is left pending) rather than a terminal row the issue never shows.
func TestDispatchSweep_HungLeaseEndStillProjects(t *testing.T) {
	const user = "tracker-sweep-hung"
	d, store, provider, _, leases, obs, ctx := newSweepFixture(t, user)
	d.Provider = ctxProvider{provider} // forge writes fail on an expired ctx
	d.leaseEndBudget = 50 * time.Millisecond
	clockOf(t, d).Advance(sweepTimeout + time.Minute)
	hang := make(chan struct{})
	t.Cleanup(func() { close(hang) })
	leases.onEnd = func(string) { <-hang } // never returns during the tick

	res, err := d.Tick(ctx, user, "default")
	if err != nil || len(res.TimedOut) != 1 {
		t.Fatalf("Tick = (%+v, %v), want one timed out despite the hung lease end", res, err)
	}
	row := assertFailedOnce(t, store, provider, ctx, user, 7, pb.TrackerDispatchFailure_TRACKER_DISPATCH_FAILURE_TIMEOUT, "timed out")
	if row.LabelsPending {
		t.Errorf("row = %+v, want labels projected, not pending", row)
	}
	if evs := obs.all(); len(evs) != 1 {
		t.Errorf("observer events = %+v, want exactly one", evs)
	}
}

// provisioningSweptStarter simulates the race a timeout can hit while a
// run is still provisioning: during StartRun a peer tick's sweep fails
// the QUEUED row TIMEOUT (and projects it). Provisioning then succeeds,
// and the start report must come back "do not proceed" — the starter
// returns ErrDispatchEnded instead of launching the agent.
type provisioningSweptStarter struct {
	t       *testing.T
	peer    func() *Dispatcher
	user    string
	proceed []bool
}

func (p *provisioningSweptStarter) StartRun(ctx context.Context, req StartRunRequest) error {
	peer := p.peer()
	clockOf(p.t, peer).Advance(sweepTimeout + time.Minute) // provisioning takes too long
	res, err := peer.Tick(ctx, p.user, "default")
	if err != nil || len(res.TimedOut) != 1 {
		p.t.Errorf("peer Tick during provisioning = (%+v, %v), want the row swept", res, err)
	}
	proceed := req.Lifecycle.RunStarted(ctx) // provisioning succeeded after all
	p.proceed = append(p.proceed, proceed)
	if !proceed {
		return ErrDispatchEnded
	}
	return nil
}

// A dispatch swept while its run was still provisioning: the late start
// report loses the compare-and-set and says the run must not proceed,
// the tick does not report the row a second time, and the issue carries
// exactly the sweep's one failure comment.
func TestDispatchSweep_TimeoutWhileProvisioningStopsTheRun(t *testing.T) {
	const user = "tracker-sweep-provisioning"
	d, store, provider, _, ctx := newLifecycleFixture(t, user, Issue{Number: 7, Labels: []string{"scope:product"}})
	d.Policy = &Policy{RunTimeout: sweepTimeout}
	obs := &fakeObserver{}
	d.Observer = obs
	starter := &provisioningSweptStarter{t: t, user: user}
	starter.peer = func() *Dispatcher { peer := *d; peer.Runs = &fakeRunStarter{}; return &peer }
	d.Runs = starter

	res, err := d.Tick(ctx, user, "default")
	if err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if len(starter.proceed) != 1 || starter.proceed[0] {
		t.Fatalf("RunStarted results = %v, want exactly one false (the row already ended)", starter.proceed)
	}
	if len(res.Failed) != 0 || len(res.Started) != 0 {
		t.Errorf("Tick result = %+v, want the run neither started nor failed a second time", res)
	}
	assertFailedOnce(t, store, provider, ctx, user, 7, pb.TrackerDispatchFailure_TRACKER_DISPATCH_FAILURE_TIMEOUT, "timed out")
	if evs := obs.all(); len(evs) != 1 {
		t.Errorf("observer events = %+v, want exactly one", evs)
	}
}

// A start report repeated after a recorded start still says proceed:
// only a row that ended without this run's start stops the run.
func TestDispatchLifecycle_RepeatedStartStillProceeds(t *testing.T) {
	const user = "tracker-lifecycle-restart"
	d, _, _, runs, ctx := newLifecycleFixture(t, user, Issue{Number: 7, Labels: []string{"scope:product"}})
	if res, err := d.Tick(ctx, user, "default"); err != nil || len(res.Started) != 1 {
		t.Fatalf("Tick = (%+v, %v), want one started", res, err)
	}
	if !runs.lifecycle(t, 0).RunStarted(ctx) {
		t.Error("a repeated start report said stop; the run's own start was recorded")
	}
}

// Every terminal path is observed exactly once with its state, cause
// and label-applied -> result latency: a clean end, a run error (whose
// comment names the run and the reason), and a start error.
func TestDispatchObserver_TerminalStates(t *testing.T) {
	t.Run("done", func(t *testing.T) {
		const user = "tracker-observe-done"
		d, _, _, runs, _, obs, ctx := newSweepFixture(t, user)
		clockOf(t, d).Advance(90 * time.Second)
		runs.lifecycle(t, 0).RunEnded(ctx, RunOutcome{})
		runs.lifecycle(t, 0).RunEnded(ctx, RunOutcome{}) // a repeat is a lost CAS
		evs := obs.all()
		if len(evs) != 1 || evs[0].State != pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_DONE ||
			evs[0].Failure != pb.TrackerDispatchFailure_TRACKER_DISPATCH_FAILURE_UNSPECIFIED || evs[0].Latency != 90*time.Second {
			t.Fatalf("events = %+v, want one DONE after 90s", evs)
		}
	})
	t.Run("run error", func(t *testing.T) {
		const user = "tracker-observe-runerr"
		d, store, provider, runs, _, obs, ctx := newSweepFixture(t, user)
		clockOf(t, d).Advance(time.Minute)
		runs.lifecycle(t, 0).RunEnded(ctx, RunOutcome{Err: context.DeadlineExceeded})
		assertFailedOnce(t, store, provider, ctx, user, 7, pb.TrackerDispatchFailure_TRACKER_DISPATCH_FAILURE_RUN_ERROR, "ended with an error")
		if evs := obs.all(); len(evs) != 1 || evs[0].Failure != pb.TrackerDispatchFailure_TRACKER_DISPATCH_FAILURE_RUN_ERROR || evs[0].Latency != time.Minute {
			t.Fatalf("events = %+v, want one RUN_ERROR after 1m", evs)
		}
	})
	t.Run("start error", func(t *testing.T) {
		const user = "tracker-observe-starterr"
		provider := newFakeDispatchProvider(Issue{Number: 2, Labels: []string{"scope:product"}})
		d, store, ctx := newDispatchFixture(t, user, provider, &fakeRunStarter{err: context.Canceled})
		obs := &fakeObserver{}
		d.Observer = obs
		if _, err := d.Tick(ctx, user, "default"); err != nil {
			t.Fatalf("Tick: %v", err)
		}
		assertFailedOnce(t, store, provider, ctx, user, 2, pb.TrackerDispatchFailure_TRACKER_DISPATCH_FAILURE_START_ERROR, "could not be started")
		if evs := obs.all(); len(evs) != 1 || evs[0].Failure != pb.TrackerDispatchFailure_TRACKER_DISPATCH_FAILURE_START_ERROR {
			t.Fatalf("events = %+v, want one START_ERROR", evs)
		}
	})
}

// FailDispatch is a compare-and-set that records the typed cause; a
// lost race is a no-op and a terminal row cannot be failed again.
func TestDispatchStore_FailDispatchRecordsCause(t *testing.T) {
	store, ctx := newTrackerTestStore(t)
	const user = "tracker-store-faildispatch"
	seedDispatchConnection(t, store, ctx, user)
	row, err := store.InsertDispatch(ctx, Dispatch{Username: user, Connection: "default", IssueNumber: 1, Scope: "product", SkillID: "s", RunID: "r"})
	if err != nil {
		t.Fatalf("InsertDispatch: %v", err)
	}
	at := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	ok, err := store.FailDispatch(ctx, row.ID, pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_QUEUED,
		pb.TrackerDispatchFailure_TRACKER_DISPATCH_FAILURE_LEASE_LOST, "no live lease", at)
	if err != nil || !ok {
		t.Fatalf("FailDispatch = (%v, %v), want (true, nil)", ok, err)
	}
	got, err := store.GetDispatch(ctx, row.ID)
	if err != nil {
		t.Fatalf("GetDispatch: %v", err)
	}
	if got.State != pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_FAILED || got.Failure != pb.TrackerDispatchFailure_TRACKER_DISPATCH_FAILURE_LEASE_LOST ||
		got.FailureReason != "no live lease" || !got.EndedAt.Equal(at) {
		t.Fatalf("row = %+v, want FAILED/LEASE_LOST ended at %v", got, at)
	}
	ok, err = store.FailDispatch(ctx, row.ID, pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_QUEUED,
		pb.TrackerDispatchFailure_TRACKER_DISPATCH_FAILURE_TIMEOUT, "late", at)
	if err != nil || ok {
		t.Fatalf("second FailDispatch = (%v, %v), want (false, nil): a lost race", ok, err)
	}
	if _, err := store.FailDispatch(ctx, row.ID, pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_QUEUED,
		pb.TrackerDispatchFailure_TRACKER_DISPATCH_FAILURE_UNSPECIFIED, "x", at); err == nil {
		t.Fatal("FailDispatch with UNSPECIFIED cause succeeded, want an error")
	}
}
