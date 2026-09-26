package tracker

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync/atomic"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Completion hook (#2023): the half of the dispatch state machine that
// runs after the tick. The run starter reports the run's start and end
// through a RunLifecycle bound to the dispatch row; each report is a
// compare-and-set on the row followed by the label projection, so the
// dispatcher's code path stays the only writer of the agent:* state
// labels (they are reserved from run tokens, see policy.go). See
// docs/architecture/issue-triggered-agents.md ("Dispatch state
// machine").

// RunOutcome is how a dispatched run ended. A nil Err is success; the
// run starter maps an agent error or an empty artifact to a non-nil
// Err.
type RunOutcome struct {
	Err error
}

func (o RunOutcome) failed() bool { return o.Err != nil }

// RunLifecycle is handed to the RunStarter with each dispatched run.
// RunStarted must be called once the run is registered and BEFORE the
// in-box agent is launched, so the RUNNING projection can never land
// after the terminal one. RunEnded is called once when the run ends.
// Both are safe to call on a cancelled context and are no-ops when the
// row has already moved on (a lost compare-and-set).
//
// RunStarted reports whether the run may proceed. false means the row
// reached a terminal state before this run's start could be recorded:
// the sweep timed it out while it was still provisioning and has already
// put agent:failed on the issue. The starter must then NOT launch the
// agent, must end the run's lease at once (revoke its credentials, wipe
// its seed) and return ErrDispatchEnded: the issue says the run is over,
// so nothing it holds may stay live (#2026). A store error returns true:
// the row is still QUEUED, so RunEnded (or the sweep) settles it later.
type RunLifecycle interface {
	RunStarted(ctx context.Context) (proceed bool)
	RunEnded(ctx context.Context, outcome RunOutcome)
}

// ErrDispatchEnded is what a RunStarter returns when RunStarted said the
// dispatch had already ended: the run was torn down before its agent was
// launched. The tick does not fail the row again — whoever ended it
// already reported it.
var ErrDispatchEnded = errors.New("the dispatch ended before its run was launched")

// lifecycleBookkeepingBudget bounds each hook's store and forge writes
// once detached from the caller's context.
const lifecycleBookkeepingBudget = 30 * time.Second

// dispatchRun is the RunLifecycle for one dispatch row.
type dispatchRun struct {
	d       *Dispatcher
	row     Dispatch
	started atomic.Bool
}

var _ RunLifecycle = (*dispatchRun)(nil)

// detached returns a context that survives the caller's cancellation
// (the tick RPC that started the run is long gone when it ends) but is
// still bounded.
func detached(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), lifecycleBookkeepingBudget)
}

// RunStarted moves the row QUEUED -> RUNNING and the issue from
// agent:queued to agent:running. It returns false when the row moved on
// without this start (see RunLifecycle): the caller must tear the run
// down. A repeated report after a recorded start returns true.
func (r *dispatchRun) RunStarted(ctx context.Context) bool {
	ctx, cancel := detached(ctx)
	defer cancel()
	ok, err := r.d.Store.TransitionDispatch(ctx, r.row.ID,
		pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_QUEUED, pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_RUNNING, "", r.d.Clock.Now())
	if err != nil {
		log.Printf("[tracker] dispatch %s: mark running: %v", r.row.ID, err)
		return true
	}
	if !ok {
		// Already moved on; whoever moved it owns the labels. Unless this
		// run's own start was recorded earlier, the row went terminal
		// under a run that never got to start: it must not launch.
		if r.started.Load() {
			return true
		}
		log.Printf("[tracker] dispatch %s: ended before run %s started; the run must not launch", r.row.ID, r.row.RunID)
		return false
	}
	r.started.Store(true)
	r.d.projectLabels(ctx, r.row, []string{LabelAgentRunning}, []string{LabelAgentQueued})
	return true
}

// RunEnded moves the row to DONE or FAILED — from RUNNING, or from
// QUEUED for a run that ended before its start was reported — and
// projects it: agent:done with the trigger scope label removed, or
// agent:failed plus one generic, stamped comment naming the run. The
// raw error stays in failure_reason (`tracker dispatches`), never on a
// possibly public issue.
func (r *dispatchRun) RunEnded(ctx context.Context, outcome RunOutcome) {
	ctx, cancel := detached(ctx)
	defer cancel()
	now := r.d.Clock.Now()
	row := r.row
	row.EndedAt = now
	row.State = pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_DONE
	if outcome.failed() {
		row.State = pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_FAILED
		row.Failure = pb.TrackerDispatchFailure_TRACKER_DISPATCH_FAILURE_RUN_ERROR
		row.FailureReason = fmt.Sprintf("run failed: %v", outcome.Err)
	}
	moved := false
	for _, from := range []pb.TrackerDispatchState{
		pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_RUNNING,
		pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_QUEUED,
	} {
		var ok bool
		var err error
		if outcome.failed() {
			ok, err = r.d.Store.FailDispatch(ctx, row.ID, from, row.Failure, row.FailureReason, now)
		} else {
			ok, err = r.d.Store.TransitionDispatch(ctx, row.ID, from, row.State, "", now)
		}
		if err != nil {
			log.Printf("[tracker] dispatch %s: mark %v: %v", row.ID, row.State, err)
			return
		}
		if ok {
			moved = true
			break
		}
	}
	if !moved {
		return // already terminal (e.g. failed by a timeout sweep)
	}
	r.d.observeEnd(row)

	if !outcome.failed() {
		r.d.projectLabels(ctx, row, []string{LabelAgentDone}, []string{LabelAgentQueued, LabelAgentRunning, ScopeLabelPrefix + row.Scope})
		return
	}
	if _, err := r.d.projectFailure(ctx, row, 0); err != nil {
		log.Printf("[tracker] dispatch %s: %v", row.ID, err)
	}
}

// projectLabels writes the row's state onto the issue. The row is
// authoritative: a forge failure leaves labels_pending for the retry
// (#2026) rather than losing the state.
func (d *Dispatcher) projectLabels(ctx context.Context, row Dispatch, add, remove []string) {
	if err := d.Provider.SetLabels(ctx, d.Conn, row.IssueNumber, add, remove); err != nil {
		log.Printf("[tracker] dispatch %s: label #%d: %v", row.ID, row.IssueNumber, err)
		d.markLabelsPending(ctx, row)
	}
}

func (d *Dispatcher) markLabelsPending(ctx context.Context, row Dispatch) {
	if err := d.Store.SetDispatchLabelsPending(ctx, row.ID, true); err != nil {
		log.Printf("[tracker] dispatch %s: mark labels pending: %v", row.ID, err)
	}
}
