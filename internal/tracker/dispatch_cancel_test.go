package tracker

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// A cancelled tick must never strand a row (#2049): between winning the
// insert and a successful StartRun, every cancellation point ends with
// the row removed (nothing on the forge yet) or FAILED (projected), and
// a later tick can dispatch the issue again. After a successful start
// the row stays with its live run and no later tick starts a second one.

// cancelPoint names where in the tick the context is cancelled.
type cancelPoint int

const (
	cancelAfterInsert       cancelPoint = iota + 1 // the insert has returned
	cancelInsideReread                             // inside the post-insert GetIssue
	cancelInsideQueuedLabel                        // inside the agent:queued SetLabels
	cancelAfterQueuedLabel                         // the label write has returned
	cancelInsideStartRun                           // StartRun sees the cancel and fails
	cancelAfterStart                               // StartRun succeeded, then the tick is cancelled
)

// cancellingProvider cancels the tick once, at the chosen point. A real
// forge client honours its context, so a call that saw the cancel fails
// with it; forgeErr additionally makes the label write fail on its own.
type cancellingProvider struct {
	*fakeDispatchProvider
	cancel   context.CancelFunc
	at       cancelPoint
	forgeErr error

	mu    sync.Mutex
	fired bool
}

func (p *cancellingProvider) fire(at cancelPoint) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.fired || p.at != at {
		return false
	}
	p.fired = true
	p.cancel()
	return true
}

func (p *cancellingProvider) GetIssue(ctx context.Context, c Conn, number int64) (Issue, error) {
	if p.fire(cancelInsideReread) {
		if err := ctx.Err(); err != nil {
			return Issue{}, err
		}
	}
	return p.fakeDispatchProvider.GetIssue(ctx, c, number)
}

func (p *cancellingProvider) SetLabels(ctx context.Context, c Conn, number int64, add, remove []string) error {
	if !containsString(add, LabelAgentQueued) {
		return p.fakeDispatchProvider.SetLabels(ctx, c, number, add, remove)
	}
	if p.fire(cancelInsideQueuedLabel) {
		if p.forgeErr != nil {
			return p.forgeErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	err := p.fakeDispatchProvider.SetLabels(ctx, c, number, add, remove)
	p.fire(cancelAfterQueuedLabel)
	return err
}

// cancelAfterInsertStore cancels the tick as the insert returns.
type cancelAfterInsertStore struct {
	DispatchStore
	p *cancellingProvider
}

func (s cancelAfterInsertStore) InsertDispatch(ctx context.Context, d Dispatch) (*Dispatch, error) {
	row, err := s.DispatchStore.InsertDispatch(ctx, d)
	s.p.fire(cancelAfterInsert)
	return row, err
}

// ctxRunStarter honours its context the way provisioning does, records
// every call and which runs really started, and can cancel the tick
// inside the call (before failing) or after a successful start.
type ctxRunStarter struct {
	p           *cancellingProvider
	reportStart bool

	mu      sync.Mutex
	calls   int
	started map[string]bool
}

func (s *ctxRunStarter) StartRun(ctx context.Context, req StartRunRequest) error {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	if s.p != nil {
		s.p.fire(cancelInsideStartRun)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	if s.started == nil {
		s.started = map[string]bool{}
	}
	s.started[req.RunID] = true
	s.mu.Unlock()
	if s.p != nil && s.p.fire(cancelAfterStart) && s.reportStart {
		// Production reports the start on the tick's own (now cancelled)
		// context: launchDispatchedRun calls RunStarted(ctx).
		req.Lifecycle.RunStarted(ctx)
	}
	return nil
}

func (s *ctxRunStarter) snapshot() (int, map[string]bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]bool{}
	for k, v := range s.started {
		out[k] = v
	}
	return s.calls, out
}

// requireNoStrandedRow fails if any active row has no live run behind it.
func requireNoStrandedRow(t *testing.T, store *Store, ctx context.Context, user string, live map[string]bool) {
	t.Helper()
	rows, err := store.ListDispatches(ctx, user, "default", pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_UNSPECIFIED)
	if err != nil {
		t.Fatalf("ListDispatches: %v", err)
	}
	for _, r := range rows {
		active := r.State == pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_QUEUED ||
			r.State == pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_RUNNING
		if active && !live[r.RunID] {
			t.Fatalf("row %s is %v with no run behind it: the issue is locked forever", r.ID, r.State)
		}
	}
}

func TestDispatch_CancelledTickNeverStrandsRow(t *testing.T) {
	const noRow = pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_UNSPECIFIED
	for i, tc := range []struct {
		name        string
		at          cancelPoint
		forgeErr    error
		reportStart bool
		wantState   pb.TrackerDispatchState // noRow: the row was removed
		wantCalls   int                     // StartRun calls on the cancelled tick
		wantLabel   string                  // state label on the issue afterwards ("" = none)
	}{
		{name: "after insert", at: cancelAfterInsert, wantState: noRow},
		{name: "inside re-read", at: cancelInsideReread, wantState: noRow},
		{name: "inside queued label write", at: cancelInsideQueuedLabel,
			wantState: pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_FAILED, wantLabel: LabelAgentFailed},
		{name: "inside queued label write, forge also fails", at: cancelInsideQueuedLabel, forgeErr: errors.New("forge unreachable"),
			wantState: pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_FAILED, wantLabel: LabelAgentFailed},
		{name: "after queued label, before start", at: cancelAfterQueuedLabel,
			wantState: pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_FAILED, wantLabel: LabelAgentFailed},
		{name: "inside StartRun", at: cancelInsideStartRun, wantCalls: 1,
			wantState: pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_FAILED, wantLabel: LabelAgentFailed},
		{name: "after a successful start, start reported", at: cancelAfterStart, reportStart: true, wantCalls: 1,
			wantState: pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_RUNNING, wantLabel: LabelAgentRunning},
		{name: "after a successful start, start not yet reported", at: cancelAfterStart, wantCalls: 1,
			wantState: pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_QUEUED, wantLabel: LabelAgentQueued},
	} {
		t.Run(tc.name, func(t *testing.T) {
			user := fmt.Sprintf("tracker-dispatch-cancel-%d", i)
			base := newFakeDispatchProvider(Issue{Number: 9, Labels: []string{"scope:product"}})
			d, store, ctx := newDispatchFixture(t, user, base, &fakeRunStarter{})
			tickCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			p := &cancellingProvider{fakeDispatchProvider: base, cancel: cancel, at: tc.at, forgeErr: tc.forgeErr}
			runs := &ctxRunStarter{p: p, reportStart: tc.reportStart}
			d.Provider, d.Runs = p, runs
			d.Store = cancelAfterInsertStore{DispatchStore: store, p: p}

			_, _ = d.Tick(tickCtx, user, "default")

			calls, live := runs.snapshot()
			if calls != tc.wantCalls {
				t.Errorf("StartRun calls = %d, want %d", calls, tc.wantCalls)
			}
			requireNoStrandedRow(t, store, ctx, user, live)
			rows, err := store.ListDispatches(ctx, user, "default", noRow)
			if err != nil {
				t.Fatalf("ListDispatches: %v", err)
			}
			switch {
			case tc.wantState == noRow && len(rows) != 0:
				t.Fatalf("rows = %+v, want the never-started row removed", rows)
			case tc.wantState != noRow && (len(rows) != 1 || rows[0].State != tc.wantState):
				t.Fatalf("rows = %+v, want one %v row", rows, tc.wantState)
			}
			labels := base.labels(9)
			for _, l := range ReservedStateLabels {
				if has := containsString(labels, l); has != (l == tc.wantLabel) {
					t.Errorf("labels = %v, want state label %q only", labels, tc.wantLabel)
					break
				}
			}

			// A later, healthy tick.
			if tc.wantState == pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_FAILED {
				base.relabel(9, "scope:product") // a human retries a failed start
			}
			res, err := d.Tick(ctx, user, "default")
			if err != nil {
				t.Fatalf("later tick: %v", err)
			}
			total, _ := runs.snapshot()
			if tc.wantState == pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_QUEUED || tc.wantState == pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_RUNNING {
				if len(res.Started) != 0 || total != tc.wantCalls {
					t.Fatalf("later tick = %+v (StartRun calls %d), want no second run while the first is live", res, total)
				}
				return
			}
			if len(res.Started) != 1 || total != tc.wantCalls+1 {
				t.Fatalf("later tick = %+v (StartRun calls %d), want the issue dispatched", res, total)
			}
		})
	}
}

// failingPendingStore fails the labels_pending write, as a store outage
// between the insert and the start would.
type failingPendingStore struct {
	DispatchStore
	failed bool
}

func (s *failingPendingStore) SetDispatchLabelsPending(ctx context.Context, id string, pending bool) error {
	if !s.failed {
		s.failed = true
		return errors.New("store unavailable")
	}
	return s.DispatchStore.SetDispatchLabelsPending(ctx, id, pending)
}

// TestDispatch_PreStartBookkeepingFailureFailsRow: the label write fails
// and so does recording labels_pending. The tick reports the store
// error, but the row it inserted must not be left QUEUED with no run.
func TestDispatch_PreStartBookkeepingFailureFailsRow(t *testing.T) {
	const user = "tracker-dispatch-prestart-store"
	provider := newFakeDispatchProvider(Issue{Number: 4, Labels: []string{"scope:product"}})
	runs := &ctxRunStarter{}
	d, store, ctx := newDispatchFixture(t, user, provider, &fakeRunStarter{})
	d.Runs = runs
	d.Store = &failingPendingStore{DispatchStore: store}
	provider.labelErr = errors.New("forge unreachable")

	if _, err := d.Tick(ctx, user, "default"); err == nil {
		t.Fatal("Tick succeeded, want the store error reported")
	}
	calls, live := runs.snapshot()
	if calls != 0 {
		t.Fatalf("StartRun calls = %d, want 0", calls)
	}
	requireNoStrandedRow(t, store, ctx, user, live)
}
