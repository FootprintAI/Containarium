package tracker

import (
	"context"
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
type RunLifecycle interface {
	RunStarted(ctx context.Context)
	RunEnded(ctx context.Context, outcome RunOutcome)
}

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
// agent:queued to agent:running.
func (r *dispatchRun) RunStarted(ctx context.Context) {
	ctx, cancel := detached(ctx)
	defer cancel()
	ok, err := r.d.Store.TransitionDispatch(ctx, r.row.ID,
		pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_QUEUED, pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_RUNNING, "", r.d.Clock.Now())
	if err != nil {
		log.Printf("[tracker] dispatch %s: mark running: %v", r.row.ID, err)
		return
	}
	if !ok {
		return // already moved on; whoever moved it owns the labels
	}
	r.started.Store(true)
	r.d.projectLabels(ctx, r.row, []string{LabelAgentRunning}, []string{LabelAgentQueued})
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
	to, reason := pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_DONE, ""
	if outcome.failed() {
		to, reason = pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_FAILED, fmt.Sprintf("run failed: %v", outcome.Err)
	}
	now := r.d.Clock.Now()
	moved := false
	for _, from := range []pb.TrackerDispatchState{
		pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_RUNNING,
		pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_QUEUED,
	} {
		ok, err := r.d.Store.TransitionDispatch(ctx, r.row.ID, from, to, reason, now)
		if err != nil {
			log.Printf("[tracker] dispatch %s: mark %v: %v", r.row.ID, to, err)
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

	stale := []string{LabelAgentQueued, LabelAgentRunning}
	if !outcome.failed() {
		r.d.projectLabels(ctx, r.row, []string{LabelAgentDone}, append(stale, ScopeLabelPrefix+r.row.Scope))
		return
	}
	r.d.projectLabels(ctx, r.row, []string{LabelAgentFailed}, stale)
	body := Sanitize(fmt.Sprintf("The agent run `%s` for `%s%s` failed (dispatch `%s`). "+
		"An operator can see the reason with `containarium tracker dispatches <username> <connection> --state failed`. "+
		"To retry, remove `%s`.",
		r.row.RunID, ScopeLabelPrefix, r.row.Scope, r.row.ID, LabelAgentFailed)) +
		"\n\n" + Stamp(dispatcherIdentity(r.row.Username, r.row.RunID), KindComment)
	if _, err := r.d.Provider.Comment(ctx, r.d.Conn, r.row.IssueNumber, body); err != nil {
		r.d.markLabelsPending(ctx, r.row)
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
