package tracker

import (
	"context"
	"fmt"
	"log"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Failure visibility (#2026): the part of the dispatch state machine
// that makes a failed or stuck run say so on the issue. Every tick first
// sweeps the connection's active rows — a row past the policy's run
// timeout, or with no live lease past a grace period, is failed with a
// typed cause — and every terminal transition (sweep, run end, start
// error) projects the same way: agent:failed plus one comment naming the
// run and the reason, and one DispatchEnded event for the PRD's success
// metrics. Each transition is a compare-and-set on the row, so of any
// number of concurrent failers exactly one reports. See
// docs/architecture/issue-triggered-agents.md ("Failure paths").

// DefaultLeaseLostGrace is how long an active row may go without a live
// lease on this daemon before the sweep fails it LEASE_LOST. It covers
// the window between a peer tick's insert and its run registering, and
// a daemon restart's in-flight runs.
const DefaultLeaseLostGrace = 5 * time.Minute

// RunLeases is the dispatcher's view of the daemon's dispatched runs.
// The production RunStarter implements it.
type RunLeases interface {
	// Live reports whether runID is a dispatched run this daemon still
	// owns: from StartRun until its end has been reported.
	Live(runID string) bool
	// End ends runID's lease (revokes its credentials, wipes its seed)
	// if it is live; a no-op otherwise. Safe to call more than once.
	End(ctx context.Context, runID string)
}

// DispatchEnded is one terminal transition, for the PRD's success
// metrics: terminal-state counts and label-applied -> result latency.
type DispatchEnded struct {
	Scope   string
	State   pb.TrackerDispatchState   // DONE or FAILED
	Failure pb.TrackerDispatchFailure // UNSPECIFIED unless FAILED
	// Latency is from the row's insert (the agent:queued label is applied
	// right after it) to the terminal transition.
	Latency time.Duration
}

// DispatchObserver receives every terminal transition exactly once per
// row (the transition's compare-and-set winner reports it).
type DispatchObserver interface {
	DispatchEnded(ev DispatchEnded)
}

// sweep fails the connection's active rows that exceeded the run
// timeout or lost their lease, and returns them. Only a store read error
// is returned; each row's bookkeeping runs detached from ctx.
//
// Age is measured from started_at for a RUNNING row and from created_at
// for a QUEUED one (it never reported a start). The timeout applies
// whether or not the run is live; the lease-lost rule only to a run this
// daemon does not hold. Runs are per-process (runlease), so this assumes
// one dispatching daemon per store — the design's 10x note.
func (d *Dispatcher) sweep(ctx context.Context, username, connection string) ([]Dispatch, error) {
	timeout := d.effectivePolicy().RunTimeout
	if timeout <= 0 {
		timeout = DefaultRunTimeout
	}
	grace := d.LeaseGrace
	if grace <= 0 {
		grace = DefaultLeaseLostGrace
	}
	var swept []Dispatch
	for _, state := range []pb.TrackerDispatchState{
		pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_RUNNING,
		pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_QUEUED,
	} {
		rows, err := d.Store.ListDispatches(ctx, username, connection, state)
		if err != nil {
			return swept, fmt.Errorf("list %v dispatches: %w", state, err)
		}
		for _, row := range rows {
			if err := ctx.Err(); err != nil {
				return swept, err
			}
			since := row.CreatedAt
			if state == pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_RUNNING && !row.StartedAt.IsZero() {
				since = row.StartedAt
			}
			age := d.Clock.Now().Sub(since)
			var failure pb.TrackerDispatchFailure
			var reason string
			switch {
			case age >= timeout:
				failure = pb.TrackerDispatchFailure_TRACKER_DISPATCH_FAILURE_TIMEOUT
				reason = fmt.Sprintf("run exceeded the run timeout of %s", timeout)
			case d.Leases != nil && age >= grace && !d.Leases.Live(row.RunID):
				failure = pb.TrackerDispatchFailure_TRACKER_DISPATCH_FAILURE_LEASE_LOST
				reason = fmt.Sprintf("no live lease on this daemon after %s", age)
			default:
				continue
			}
			out, ok, err := d.failSwept(ctx, row, state, failure, reason, timeout)
			if err != nil {
				return swept, err
			}
			if ok {
				swept = append(swept, out)
			}
		}
	}
	return swept, nil
}

// DefaultLeaseEndBudget bounds how long the sweep waits for one swept
// run's lease end (revocation, seed wipe, audit) before it moves on to
// the projection. The production lease end caps its revocation half at
// 6s; this leaves room for the wipe and the audit row.
const DefaultLeaseEndBudget = 20 * time.Second

// failSwept moves one stuck row to FAILED and, only if this call won the
// compare-and-set, ends the run's lease and then projects the failure —
// in that order, so the issue never says agent:failed while the run's
// credentials are still live. All of it runs detached from the tick: a
// tick cancelled after the transition must still leave the issue saying
// so.
//
// The three steps get independent budgets. The lease end in particular
// has its own, and the projection starts a fresh one only after it: a
// lease end that hangs must not use up the projection's budget, or the
// row would be terminal with the issue still saying agent:running, no
// comment and no labels_pending — silent, and never retried.
func (d *Dispatcher) failSwept(tickCtx context.Context, row Dispatch, from pb.TrackerDispatchState, failure pb.TrackerDispatchFailure, reason string, timeout time.Duration) (Dispatch, bool, error) {
	now := d.Clock.Now()
	casCtx, casCancel := bookkeepingContext(tickCtx)
	won, err := d.Store.FailDispatch(casCtx, row.ID, from, failure, reason, now)
	casCancel()
	if err != nil {
		return row, false, fmt.Errorf("fail stuck dispatch for #%d: %w", row.IssueNumber, err)
	}
	if !won {
		return row, false, nil // the run ended, or a peer swept it, first
	}
	row.State = pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_FAILED
	row.Failure, row.FailureReason, row.EndedAt = failure, reason, now
	d.endLease(tickCtx, row.RunID)
	d.observeEnd(row)
	projCtx, projCancel := bookkeepingContext(tickCtx)
	defer projCancel()
	pending, err := d.projectFailure(projCtx, row, timeout)
	if err != nil {
		return row, true, err
	}
	row.LabelsPending = row.LabelsPending || pending
	return row, true, nil
}

// endLease ends a swept run's lease on its own goroutine, detached from
// the tick and bounded by its own budget (leaseEndBudget): a panic or
// runtime.Goexit inside it (the lease end calls into the revocation
// store and the box) ends only that goroutine, and a hung one is
// abandoned once the budget is spent. The row is already FAILED either
// way; the projection, on its own fresh budget, must still happen.
func (d *Dispatcher) endLease(tickCtx context.Context, runID string) {
	if d.Leases == nil {
		return
	}
	budget := d.leaseEndBudget
	if budget <= 0 {
		budget = DefaultLeaseEndBudget
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(tickCtx), budget)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			if recover() != nil {
				log.Printf("[tracker] dispatch run %s: ending the lease panicked (value withheld)", runID)
			}
		}()
		d.Leases.End(ctx, runID)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		log.Printf("[tracker] dispatch run %s: ending the lease did not finish: %v", runID, ctx.Err())
	}
}

// observeEnd reports a row that just reached a terminal state.
func (d *Dispatcher) observeEnd(row Dispatch) {
	if d.Observer == nil {
		return
	}
	latency := row.EndedAt.Sub(row.CreatedAt)
	if latency < 0 {
		latency = 0
	}
	d.Observer.DispatchEnded(DispatchEnded{Scope: row.Scope, State: row.State, Failure: row.Failure, Latency: latency})
}

// projectFailure puts a FAILED row onto the issue: agent:failed (the
// active state labels removed) and one stamped comment naming the run
// and the reason. The raw error stays in failure_reason. It runs once per
// row — only the terminal transition's compare-and-set winner calls it —
// so the comment is posted at most once per dispatch id; the
// labels_pending retry re-projects the labels, never the comment
// (#2047). A forge label failure leaves labels_pending set and reports
// it; only that store write's error is returned.
func (d *Dispatcher) projectFailure(ctx context.Context, row Dispatch, timeout time.Duration) (pending bool, err error) {
	add, remove := terminalLabels(row)
	// Each write resolves its own credential (#2269).
	conn, labelErr := d.forgeConn(ctx, row.Username)
	if labelErr == nil {
		labelErr = d.Provider.SetLabels(ctx, conn, row.IssueNumber, add, remove)
	}
	conn, commentErr := d.forgeConn(ctx, row.Username)
	if commentErr == nil {
		_, commentErr = d.Provider.Comment(ctx, conn, row.IssueNumber, failureComment(row, timeout))
	}
	if commentErr != nil {
		log.Printf("[tracker] dispatch %s: failure comment on #%d: %v", row.ID, row.IssueNumber, commentErr)
	}
	if labelErr == nil {
		return !d.labelsLanded(ctx, row), nil
	}
	log.Printf("[tracker] dispatch %s: project failure onto #%d: %v", row.ID, row.IssueNumber, labelErr)
	if err := d.Store.SetDispatchLabelsPending(ctx, row.ID, true); err != nil {
		return false, fmt.Errorf("mark labels pending for #%d: %w", row.IssueNumber, err)
	}
	return true, nil
}

// terminalLabels is a terminal row's projection: agent:done with the
// trigger scope label removed, or agent:failed (the scope label kept,
// so a human retries by removing agent:failed). Either way the active
// state labels go.
func terminalLabels(row Dispatch) (add, remove []string) {
	if row.State == pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_DONE {
		return []string{LabelAgentDone}, []string{LabelAgentQueued, LabelAgentRunning, ScopeLabelPrefix + row.Scope}
	}
	return []string{LabelAgentFailed}, []string{LabelAgentQueued, LabelAgentRunning}
}

// labelsLanded clears labels_pending once a projection reached the
// forge, and reports whether it did. A failed clear only leaves the row
// pending: the next tick re-projects (idempotently) and clears it then.
func (d *Dispatcher) labelsLanded(ctx context.Context, row Dispatch) bool {
	if err := d.Store.SetDispatchLabelsPending(ctx, row.ID, false); err != nil {
		log.Printf("[tracker] dispatch %s: clear labels pending: %v", row.ID, err)
		return false
	}
	return true
}

// retryPendingLabels re-projects every terminal row whose labels never
// reached the forge (#2026's labels_pending retry, #2047, #2052) and
// returns the issues whose projection still has not landed: the tick
// must not dispatch them again, because their row — not their labels —
// says they were handled. Only the latest row per issue is retried, and
// only its labels: the failure comment was posted (or attempted) once,
// by the terminal transition.
//
// The projection counts as landed when the write succeeds, or when the
// issue already carries the row's state label — a human who cannot get
// the dispatcher's writes through (a token that may comment but not
// label) applies it by hand, then removes it to ask for a new
// generation, the ordinary re-run protocol. Only a store error is
// returned.
func (d *Dispatcher) retryPendingLabels(ctx context.Context, username, connection string) (map[int64]bool, error) {
	rows, err := d.Store.ListLabelsPendingDispatches(ctx, username, connection)
	if err != nil {
		return nil, fmt.Errorf("list labels-pending dispatches: %w", err)
	}
	held := make(map[int64]bool, len(rows))
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return held, err
		}
		add, remove := terminalLabels(row)
		conn, err := d.forgeConn(ctx, row.Username)
		if err == nil {
			err = d.Provider.SetLabels(ctx, conn, row.IssueNumber, add, remove)
		}
		if err != nil {
			var issue Issue
			conn, gerr := d.forgeConn(ctx, row.Username)
			if gerr == nil {
				issue, gerr = d.Provider.GetIssue(ctx, conn, row.IssueNumber)
			}
			if gerr != nil || !hasAnyLabel(issue.Labels, add...) {
				log.Printf("[tracker] dispatch %s: retry labels on #%d: %v", row.ID, row.IssueNumber, err)
				held[row.IssueNumber] = true
				continue
			}
		}
		if err := d.Store.SetDispatchLabelsPending(ctx, row.ID, false); err != nil {
			return held, fmt.Errorf("clear labels pending for #%d: %w", row.IssueNumber, err)
		}
	}
	return held, nil
}

// failureComment is the dispatcher's comment on a failed dispatch: the
// run id, the dispatch id and a reason derived from the typed cause —
// never the raw error, which may carry backend details onto a possibly
// public issue.
func failureComment(row Dispatch, timeout time.Duration) string {
	var why string
	switch row.Failure {
	case pb.TrackerDispatchFailure_TRACKER_DISPATCH_FAILURE_START_ERROR:
		why = "could not be started"
	case pb.TrackerDispatchFailure_TRACKER_DISPATCH_FAILURE_RUN_ERROR:
		why = "ended with an error"
	case pb.TrackerDispatchFailure_TRACKER_DISPATCH_FAILURE_TIMEOUT:
		// Not "its credentials were revoked": that is not yet true for a
		// run still provisioning (it is torn down once provisioning
		// returns), and not guaranteed when the lease end fails.
		why = fmt.Sprintf("timed out after %s (the connection's run timeout) and was marked failed; any result it reports later is ignored", timeout)
	case pb.TrackerDispatchFailure_TRACKER_DISPATCH_FAILURE_LEASE_LOST:
		why = "was marked failed because it has no live lease on the daemon (the daemon restarted, or the run never reported a start)"
	default:
		why = "failed"
	}
	return Sanitize(fmt.Sprintf("The agent run `%s` for `%s%s` %s (dispatch `%s`). "+
		"An operator can see the details with `containarium tracker dispatches <username> <connection> --state failed`. "+
		"To retry, remove `%s`.",
		row.RunID, ScopeLabelPrefix, row.Scope, why, row.ID, LabelAgentFailed)) +
		"\n\n" + Stamp(dispatcherIdentity(row.Username, row.RunID), KindComment)
}
