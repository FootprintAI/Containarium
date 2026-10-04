package tracker

import (
	"context"
	"errors"
	"sync"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// A terminal dispatch row whose label projection did not land (#2047,
// #2052). The row is authoritative: an issue whose latest row is
// terminal with labels_pending is not dispatched again, the projection
// is retried every tick until it lands (or a human puts the state label
// on the issue), and the failure comment is posted once per dispatch
// id, never once per tick. Real Postgres store, fake forge whose
// SetLabels always fails (a token that can comment but not label).

const pendingTicks = 5

func allRows(t *testing.T, store *Store, ctx context.Context, user string) []Dispatch {
	t.Helper()
	rows, err := store.ListDispatches(ctx, user, "default", pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_UNSPECIFIED)
	if err != nil {
		t.Fatalf("ListDispatches: %v", err)
	}
	return rows
}

func setLabelErr(p *fakeDispatchProvider, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.labelErr = err
}

// TestDispatch_StartErrorWithPersistentLabelFailureDispatchesOnce is
// #2047's probe: StartRun fails AND the agent:failed write fails, every
// tick. Before the fix each tick re-dispatched the label-less issue —
// one FAILED row and one public failure comment per tick.
func TestDispatch_StartErrorWithPersistentLabelFailureDispatchesOnce(t *testing.T) {
	const user = "tracker-pending-starterr"
	provider := newFakeDispatchProvider(Issue{Number: 21, Labels: []string{"scope:product"}})
	provider.labelErr = errors.New("token may comment but not label")
	runs := &fakeRunStarter{err: errors.New("provisioning failed")}
	d, store, ctx := newDispatchFixture(t, user, provider, runs)

	for i := 0; i < pendingTicks; i++ {
		if _, err := d.Tick(ctx, user, "default"); err != nil {
			t.Fatalf("Tick %d: %v", i, err)
		}
	}
	if n := len(runs.started()); n != 1 {
		t.Fatalf("StartRun calls = %d across %d ticks, want 1", n, pendingTicks)
	}
	rows := allRows(t, store, ctx, user)
	if len(rows) != 1 || rows[0].State != pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_FAILED || !rows[0].LabelsPending {
		t.Fatalf("rows = %+v, want exactly one FAILED row with labels_pending", rows)
	}
	if c := provider.commentsOn(21); len(c) != 1 {
		t.Fatalf("failure comments = %d across %d ticks, want 1 (one per dispatch id)", len(c), pendingTicks)
	}

	// The forge recovers: the retry lands agent:failed and clears the
	// flag — without posting the failure comment a second time.
	setLabelErr(provider, nil)
	res, err := d.Tick(ctx, user, "default")
	if err != nil {
		t.Fatalf("Tick after recovery: %v", err)
	}
	if len(res.Started) != 0 || len(res.Failed) != 0 {
		t.Fatalf("Tick after recovery = %+v, want nothing dispatched", res)
	}
	if labels := provider.labels(21); !containsString(labels, LabelAgentFailed) {
		t.Fatalf("labels = %v, want the retried %s", labels, LabelAgentFailed)
	}
	if row := allRows(t, store, ctx, user)[0]; row.LabelsPending {
		t.Fatalf("row = %+v, want labels_pending cleared once the projection landed", row)
	}
	if c := provider.commentsOn(21); len(c) != 1 {
		t.Fatalf("failure comments = %d, want still 1: the retry re-projects labels, never the comment", len(c))
	}

	// The ordinary re-run protocol now works: a human removes agent:failed.
	runs.mu.Lock()
	runs.err = nil
	runs.mu.Unlock()
	provider.relabel(21, "scope:product")
	if res, err := d.Tick(ctx, user, "default"); err != nil || len(res.Started) != 1 {
		t.Fatalf("Tick after re-label = (%+v, %v), want a new generation", res, err)
	}
}

// TestDispatch_HumanStateLabelReleasesPendingRow: with the forge refusing
// the dispatcher's label writes for good, a human applying the state
// label by hand counts as the projection landing; removing it then
// re-runs the issue as usual.
func TestDispatch_HumanStateLabelReleasesPendingRow(t *testing.T) {
	const user = "tracker-pending-human"
	provider := newFakeDispatchProvider(Issue{Number: 22, Labels: []string{"scope:product"}})
	provider.labelErr = errors.New("token may comment but not label")
	runs := &fakeRunStarter{err: errors.New("provisioning failed")}
	d, store, ctx := newDispatchFixture(t, user, provider, runs)

	for i := 0; i < 2; i++ {
		if _, err := d.Tick(ctx, user, "default"); err != nil {
			t.Fatalf("Tick %d: %v", i, err)
		}
	}
	// A human puts agent:failed on the issue themselves.
	provider.relabel(22, "scope:product", LabelAgentFailed)
	if _, err := d.Tick(ctx, user, "default"); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if row := allRows(t, store, ctx, user)[0]; row.LabelsPending {
		t.Fatalf("row = %+v, want labels_pending cleared: the issue carries %s", row, LabelAgentFailed)
	}
	// ...and removes it to ask for a new generation.
	runs.mu.Lock()
	runs.err = nil
	runs.mu.Unlock()
	provider.relabel(22, "scope:product")
	if res, err := d.Tick(ctx, user, "default"); err != nil || len(res.Started) != 1 {
		t.Fatalf("Tick after re-label = (%+v, %v), want a new generation", res, err)
	}
	if n := len(runs.started()); n != 2 {
		t.Fatalf("StartRun calls = %d, want 2", n)
	}
	if c := provider.commentsOn(22); len(c) != 1 {
		t.Fatalf("failure comments = %d, want 1", len(c))
	}
}

// TestDispatch_DoneWithPendingLabelsRunsOnce is #2052's probe: the run
// succeeds but every label projection fails, so the row ends DONE with
// labels_pending and the issue keeps scope:product with no agent:*
// label. Before the fix the next tick started a second run.
func TestDispatch_DoneWithPendingLabelsRunsOnce(t *testing.T) {
	const user = "tracker-pending-done"
	provider := newFakeDispatchProvider(Issue{Number: 23, Labels: []string{"scope:product"}})
	provider.labelErr = errors.New("forge refuses label writes")
	runs := &lifecycleRunStarter{endWith: &RunOutcome{}}
	d, store, ctx := newDispatchFixture(t, user, provider, &fakeRunStarter{})
	d.Runs = runs

	for i := 0; i < pendingTicks; i++ {
		if _, err := d.Tick(ctx, user, "default"); err != nil {
			t.Fatalf("Tick %d: %v", i, err)
		}
	}
	if n := len(runs.started()); n != 1 {
		t.Fatalf("StartRun calls = %d across %d ticks, want 1", n, pendingTicks)
	}
	rows := allRows(t, store, ctx, user)
	if len(rows) != 1 || rows[0].State != pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_DONE || !rows[0].LabelsPending {
		t.Fatalf("rows = %+v, want exactly one DONE row with labels_pending", rows)
	}
	if c := provider.commentsOn(23); len(c) != 0 {
		t.Fatalf("dispatcher comments = %q, want none on success", c)
	}

	// The forge recovers: the retry projects done (agent:done on, the
	// trigger scope label off) and clears the flag.
	setLabelErr(provider, nil)
	if res, err := d.Tick(ctx, user, "default"); err != nil || len(res.Started) != 0 {
		t.Fatalf("Tick after recovery = (%+v, %v), want nothing started", res, err)
	}
	labels := provider.labels(23)
	if !containsString(labels, LabelAgentDone) || containsString(labels, "scope:product") {
		t.Fatalf("labels = %v, want %s and the scope label removed", labels, LabelAgentDone)
	}
	if row := allRows(t, store, ctx, user)[0]; row.LabelsPending {
		t.Fatalf("row = %+v, want labels_pending cleared", row)
	}

	// Re-run after done (#2023): a human removes agent:done and re-adds
	// the scope label; exactly one new generation runs.
	provider.relabel(23, "scope:product")
	for i := 0; i < 2; i++ {
		if _, err := d.Tick(ctx, user, "default"); err != nil {
			t.Fatalf("re-run Tick %d: %v", i, err)
		}
	}
	if n := len(runs.started()); n != 2 {
		t.Fatalf("StartRun calls = %d, want 2 (one re-run generation)", n)
	}
}

// hookProvider runs onSetLabels before each forge label write, so a test
// can run a second tick while a projection is in flight.
type hookProvider struct {
	*fakeDispatchProvider
	mu          sync.Mutex
	onSetLabels func(add []string)
}

func (h *hookProvider) SetLabels(ctx context.Context, c Conn, n int64, add, remove []string) error {
	h.mu.Lock()
	hook := h.onSetLabels
	h.mu.Unlock()
	if hook != nil {
		hook(add)
	}
	return h.fakeDispatchProvider.SetLabels(ctx, c, n, add, remove)
}

// TestDispatch_TickDuringTerminalProjectionDoesNotRerun: a peer tick
// that runs while the done projection is still in flight (the row is
// already DONE, the forge write has not returned yet and is about to
// fail) must not start a second run. labels_pending is set in the same
// write as the terminal transition, so there is no window in which the
// row is terminal, unprojected and not pending.
func TestDispatch_TickDuringTerminalProjectionDoesNotRerun(t *testing.T) {
	const user = "tracker-pending-inflight"
	base := newFakeDispatchProvider(Issue{Number: 24, Labels: []string{"scope:product"}})
	provider := &hookProvider{fakeDispatchProvider: base}
	runs := &lifecycleRunStarter{}
	d, store, ctx := newDispatchFixture(t, user, base, &fakeRunStarter{})
	d.Runs, d.Provider = runs, provider

	// Every projection so far lands: the RUNNING row is not pending.
	if res, err := d.Tick(ctx, user, "default"); err != nil || len(res.Started) != 1 {
		t.Fatalf("Tick 1 = (%+v, %v)", res, err)
	}
	if row := allRows(t, store, ctx, user)[0]; row.LabelsPending {
		t.Fatalf("row = %+v, want nothing pending before the run ends", row)
	}
	// The forge stops taking labels just as the run ends: the done
	// write is the first to fail, and the peer tick runs while it is in
	// flight (the row already DONE). The issue's agent:running is
	// stripped (by a human, or a forge list that lags) so only the row
	// can tell the peer the issue was handled.
	var peer TickResult
	var peerErr error
	provider.onSetLabels = func(add []string) {
		if !containsString(add, LabelAgentDone) {
			return
		}
		provider.mu.Lock()
		provider.onSetLabels = nil // once
		provider.mu.Unlock()
		setLabelErr(base, errors.New("forge refuses label writes"))
		base.relabel(24, "scope:product")
		peer, peerErr = d.Tick(ctx, user, "default")
	}
	runs.lifecycle(t, 0).RunEnded(ctx, RunOutcome{})

	if peerErr != nil {
		t.Fatalf("peer Tick: %v", peerErr)
	}
	if len(peer.Started) != 0 {
		t.Fatalf("peer tick started %+v while the done projection was in flight, want nothing", peer.Started)
	}
	if n := len(runs.started()); n != 1 {
		t.Fatalf("StartRun calls = %d, want 1", n)
	}
	if rows := allRows(t, store, ctx, user); len(rows) != 1 {
		t.Fatalf("rows = %+v, want one", rows)
	}
}

// TestDispatch_SupersededPendingRowIsNotReprojected: only an issue's
// latest row is projected. An older generation's pending FAILED row
// must not put agent:failed back on an issue a newer generation owns.
func TestDispatch_SupersededPendingRowIsNotReprojected(t *testing.T) {
	const user = "tracker-pending-superseded"
	provider := newFakeDispatchProvider(Issue{Number: 25, Labels: []string{"scope:product"}})
	provider.labelErr = errors.New("token may comment but not label")
	runs := &fakeRunStarter{err: errors.New("provisioning failed")}
	d, store, ctx := newDispatchFixture(t, user, provider, runs)

	if _, err := d.Tick(ctx, user, "default"); err != nil {
		t.Fatalf("Tick 1: %v", err)
	}
	// A human releases it (state label on, then off) and the forge
	// recovers; generation 2 starts and is running.
	provider.relabel(25, "scope:product", LabelAgentFailed)
	if _, err := d.Tick(ctx, user, "default"); err != nil {
		t.Fatalf("Tick 2: %v", err)
	}
	provider.relabel(25, "scope:product")
	runs.mu.Lock()
	runs.err = nil
	runs.mu.Unlock()
	setLabelErr(provider, nil)
	if res, err := d.Tick(ctx, user, "default"); err != nil || len(res.Started) != 1 {
		t.Fatalf("Tick 3 = (%+v, %v), want generation 2", res, err)
	}
	// Force the old row back to pending, as a row from before this fix
	// could be; it is superseded and must be left alone.
	rows := allRows(t, store, ctx, user)
	if len(rows) != 2 {
		t.Fatalf("rows = %+v, want two generations", rows)
	}
	if err := store.SetDispatchLabelsPending(ctx, rows[1].ID, true); err != nil {
		t.Fatalf("SetDispatchLabelsPending: %v", err)
	}
	if _, err := d.Tick(ctx, user, "default"); err != nil {
		t.Fatalf("Tick 4: %v", err)
	}
	if labels := provider.labels(25); containsString(labels, LabelAgentFailed) {
		t.Fatalf("labels = %v, an old generation's failure was projected over generation 2", labels)
	}
}

// listHookProvider runs onList once, just before the tick's issue list
// is taken — after the tick's labels_pending retry has already run.
type listHookProvider struct {
	*fakeDispatchProvider
	once   sync.Once
	onList func()
}

func (l *listHookProvider) ListIssues(ctx context.Context, c Conn, f IssueFilter) ([]Issue, error) {
	if l.onList != nil {
		l.once.Do(l.onList)
	}
	return l.fakeDispatchProvider.ListIssues(ctx, c, f)
}

// TestDispatch_RunEndsAfterRetryBeforeInsertDoesNotRerun: the previous
// generation goes DONE (its projection failing) after this tick's retry
// pass and before its list, so the tick wins the insert — no active row
// — and the issue shows no state label. The post-insert check reads the
// prior row and abandons the insert instead of starting a second run.
func TestDispatch_RunEndsAfterRetryBeforeInsertDoesNotRerun(t *testing.T) {
	const user = "tracker-pending-postinsert"
	base := newFakeDispatchProvider(Issue{Number: 26, Labels: []string{"scope:product"}})
	base.labelErr = errors.New("forge refuses label writes")
	runs := &lifecycleRunStarter{}
	d, store, ctx := newDispatchFixture(t, user, base, &fakeRunStarter{})
	d.Runs = runs

	if res, err := d.Tick(ctx, user, "default"); err != nil || len(res.Started) != 1 {
		t.Fatalf("Tick 1 = (%+v, %v)", res, err)
	}
	d.Provider = &listHookProvider{fakeDispatchProvider: base, onList: func() {
		runs.lifecycle(t, 0).RunEnded(ctx, RunOutcome{})
	}}
	res, err := d.Tick(ctx, user, "default")
	if err != nil {
		t.Fatalf("Tick 2: %v", err)
	}
	if len(res.Started) != 0 || res.SkippedActive != 1 {
		t.Fatalf("Tick 2 = %+v, want the handled issue skipped", res)
	}
	if n := len(runs.started()); n != 1 {
		t.Fatalf("StartRun calls = %d, want 1", n)
	}
	rows := allRows(t, store, ctx, user)
	if len(rows) != 1 || rows[0].State != pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_DONE || !rows[0].LabelsPending {
		t.Fatalf("rows = %+v, want the one DONE pending row (the abandoned insert removed)", rows)
	}
}
