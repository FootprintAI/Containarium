package tracker

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
)

// Dispatcher core (#2022): one pure tick that turns routed
// `scope:<role>` labels into runs, exactly once per issue. Everything it
// touches is injected — the forge (DispatchProvider), the run launcher
// (RunStarter), the clock, and the store — so the tick is testable with
// fakes and a real Postgres. See docs/architecture/issue-triggered-agents.md
// ("Dispatch state machine", "Exactly-once", "Data flow of the run input").

// The label names (LabelNeedsApproval, LabelAgent*) and the
// ReservedStateLabels set live in policy.go (#2024): an issue carrying
// any state label is skipped, and a human re-runs a finished issue by
// removing agent:done|failed. Only this code path writes them.

// DispatchProvider is the slice of the forge adapter a tick needs.
// Every WriterProvider satisfies it.
type DispatchProvider interface {
	ListIssues(ctx context.Context, c Conn, f IssueFilter) ([]Issue, error)
	GetIssue(ctx context.Context, c Conn, number int64) (Issue, error)
	SetLabels(ctx context.Context, c Conn, number int64, add, remove []string) error
	Comment(ctx context.Context, c Conn, number int64, body string) (Comment, error)
}

// StartRunRequest is what the dispatcher hands the run launcher.
// InputJSON is exactly the protojson of a TrackerDispatchInput — the
// issue reference, never its body.
type StartRunRequest struct {
	Username   string
	Connection string
	SkillID    string
	RunID      string
	InputJSON  string
	// RepoURL is the connection's repository (credential-free HTTPS
	// clone URL), so the run has a workspace to submit a doc change
	// from (#2023). Empty when the caller did not resolve one.
	RepoURL string
	// Lifecycle reports the run's start and end back to the dispatch
	// row (#2023). Never nil from Tick.
	Lifecycle RunLifecycle
}

// RunStarter starts a skill run bound to the connection. It returns once
// the run has started (or failed to); it does not wait for the run to
// finish. The production implementation goes through the same internal
// path as RunAgentSkill. At 10x this is the seam a durable pull queue
// slots in behind.
//
// A starter that accepts a run must call req.Lifecycle.RunStarted once
// the run is registered and before its agent is launched, and
// req.Lifecycle.RunEnded exactly once when the run ends.
type RunStarter interface {
	StartRun(ctx context.Context, req StartRunRequest) error
}

// DispatchStore is the persistence a tick needs. *Store satisfies it.
type DispatchStore interface {
	ListRoutes(ctx context.Context, username, connection string) ([]Route, error)
	InsertDispatch(ctx context.Context, d Dispatch) (*Dispatch, error)
	TransitionDispatch(ctx context.Context, id string, from, to pb.TrackerDispatchState, reason string, at time.Time) (bool, error)
	SetDispatchLabelsPending(ctx context.Context, id string, pending bool) error
	DeleteQueuedDispatch(ctx context.Context, id string) (bool, error)
	RecordDispatchWarning(ctx context.Context, username, connection string, issue int64, scope string) (bool, error)
	ForgetDispatchWarning(ctx context.Context, username, connection string, issue int64, scope string) error
}

var _ DispatchStore = (*Store)(nil)

// Dispatcher runs ticks for one connection's forge.
type Dispatcher struct {
	Store    DispatchStore
	Provider DispatchProvider
	// Conn is the resolved forge connection (base URL, project,
	// credential) the provider calls use.
	Conn  Conn
	Runs  RunStarter
	Clock Clock
	// RepoURL is the connection's repository clone URL, handed to every
	// run this dispatcher starts (StartRunRequest.RepoURL).
	RepoURL string
	// NewRunID mints the run id recorded on the row before the run
	// starts. nil uses a random UUID.
	NewRunID func() string
}

// TickResult is one tick's outcome.
type TickResult struct {
	Started []Dispatch
	Failed  []Dispatch
	// Counters are int32 to match DispatchTrackerIssuesResponse.
	SkippedNeedsApproval int32
	SkippedActive        int32
	SkippedUnrouted      int32
}

// Tick lists the connection's open issues and, for each one with a
// routed scope label, no state label and no approval gate: inserts a
// dispatch row (the exactly-once index decides the winner), starts the
// routed skill with the issue reference as input, and labels the issue
// agent:queued. A start error fails the row, labels agent:failed and
// comments the reason. An unrouted scope label gets one stamped warning
// comment, ever.
//
// A forge list error or a store error aborts the tick; per-issue forge
// write failures do not (they are recorded and the tick moves on).
func (d *Dispatcher) Tick(ctx context.Context, username, connection string) (TickResult, error) {
	var res TickResult
	routes, err := d.Store.ListRoutes(ctx, username, connection)
	if err != nil {
		return res, fmt.Errorf("list routes: %w", err)
	}
	skillFor := make(map[string]string, len(routes))
	for _, r := range routes {
		skillFor[r.Scope] = r.SkillID
	}

	issues, err := d.Provider.ListIssues(ctx, d.Conn, IssueFilter{State: pb.TrackerIssueState_TRACKER_ISSUE_STATE_OPEN})
	if err != nil {
		return res, fmt.Errorf("list issues: %w", err)
	}

	for _, issue := range issues {
		// A cancelled tick stops here rather than failing every remaining
		// issue's start for a reason that has nothing to do with it.
		if err := ctx.Err(); err != nil {
			return res, err
		}
		scopes := scopeLabels(issue.Labels)
		if len(scopes) == 0 {
			continue // not addressed to any role
		}
		if hasAnyLabel(issue.Labels, LabelNeedsApproval) {
			res.SkippedNeedsApproval++
			continue
		}
		if hasAnyLabel(issue.Labels, ReservedStateLabels...) {
			res.SkippedActive++
			continue
		}

		scope, skillID := "", ""
		for _, sc := range scopes {
			if sk, ok := skillFor[sc]; ok {
				if scope == "" {
					scope, skillID = sc, sk
				}
				continue
			}
			if err := d.warnUnrouted(ctx, username, connection, issue.Number, sc); err != nil {
				return res, err
			}
		}
		if scope == "" {
			res.SkippedUnrouted++
			continue
		}

		// From the insert until StartRun has succeeded, no cancellation
		// point may leave the row QUEUED with no run behind it (#2049):
		// the active-row index would skip the issue on every later tick,
		// and nothing sweeps queued rows. So the writes in this window run
		// on a detached, bounded context, and a tick cancelled inside it
		// removes the row (nothing is on the forge yet) or fails it
		// (agent:queued is, or may be, on the issue) — never leaves it.
		//
		// The insert itself is detached: a cancel landing while it is in
		// flight could commit the row yet report an error.
		ictx, icancel := bookkeepingContext(ctx)
		row, err := d.Store.InsertDispatch(ictx, Dispatch{
			Username: username, Connection: connection, IssueNumber: issue.Number,
			Scope: scope, SkillID: skillID, RunID: d.newRunID(),
		})
		icancel()
		if errors.Is(err, ErrDispatchActive) {
			res.SkippedActive++ // another dispatcher (or a live run) holds it
			continue
		}
		if err != nil {
			return res, fmt.Errorf("insert dispatch for #%d: %w", issue.Number, err)
		}
		if cerr := ctx.Err(); cerr != nil {
			if err := d.abandon(ctx, row); err != nil {
				return res, err
			}
			return res, cerr
		}

		// Re-read before starting anything (#2023): the list above can be
		// stale. A peer may have dispatched this issue AND finished it
		// between our list and our insert — its row is terminal, so the
		// insert succeeded, but the issue now carries agent:done and no
		// scope label. Starting here would be a second run.
		if keep, err := d.stillDispatchable(ctx, row, scope); err != nil {
			return res, err
		} else if !keep {
			res.SkippedActive++
			continue
		}

		// The row is authoritative; the label is its projection. It goes
		// on before the start (provisioning can take minutes) and a forge
		// failure leaves labels_pending for the retry (#2026). Detached, so
		// a cancel mid-write cannot leave the row with neither the label
		// nor labels_pending; the tick's cancellation is checked after.
		if err := d.labelQueued(ctx, row); err != nil {
			return res, d.failBeforeStart(ctx, row, err)
		}
		if cerr := ctx.Err(); cerr != nil {
			// A cancelled tick starts no new run.
			failed, err := d.failStart(ctx, row, cerr)
			if err != nil {
				return res, err
			}
			res.Failed = append(res.Failed, *failed)
			return res, cerr
		}

		input, err := dispatchInputJSON(row)
		if err != nil {
			return res, d.failBeforeStart(ctx, row, err)
		}
		lc := &dispatchRun{d: d, row: *row}
		if startErr := d.Runs.StartRun(ctx, StartRunRequest{
			Username: username, Connection: connection, SkillID: skillID, RunID: row.RunID, InputJSON: input,
			RepoURL: d.RepoURL, Lifecycle: lc,
		}); startErr != nil {
			failed, err := d.failStart(ctx, row, startErr)
			if err != nil {
				return res, err
			}
			res.Failed = append(res.Failed, *failed)
			continue
		}
		if lc.started.Load() {
			row.State = pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_RUNNING
		}
		res.Started = append(res.Started, *row)
	}
	return res, nil
}

// stillDispatchable re-reads the issue after this tick won the insert
// and reports whether it is still open, still carries the routed scope
// label, and carries no state or gate label. When it is not — or the
// re-read fails — the never-started row is removed so the issue is
// neither double-run nor locked, and the caller skips it this tick.
// The only error returned is a store error.
func (d *Dispatcher) stillDispatchable(ctx context.Context, row *Dispatch, scope string) (bool, error) {
	fresh, err := d.Provider.GetIssue(ctx, d.Conn, row.IssueNumber)
	keep := err == nil &&
		fresh.State != pb.TrackerIssueState_TRACKER_ISSUE_STATE_CLOSED &&
		containsExact(fresh.Labels, ScopeLabelPrefix+scope) &&
		!hasAnyLabel(fresh.Labels, LabelNeedsApproval) &&
		!hasAnyLabel(fresh.Labels, ReservedStateLabels...)
	if keep {
		return true, nil
	}
	// A cancelled tick (the re-read fails with it) must not leave a
	// QUEUED row behind that locks the issue: abandon is detached.
	return false, d.abandon(ctx, row)
}

// abandon deletes a row whose run was never started and whose issue was
// never labelled, on a detached context, so the next tick can dispatch
// the issue again.
func (d *Dispatcher) abandon(ctx context.Context, row *Dispatch) error {
	dctx, cancel := bookkeepingContext(ctx)
	defer cancel()
	if _, err := d.Store.DeleteQueuedDispatch(dctx, row.ID); err != nil {
		return fmt.Errorf("abandon dispatch for #%d: %w", row.IssueNumber, err)
	}
	return nil
}

// labelQueued projects the new row onto the issue as agent:queued, or
// records labels_pending when the forge write fails, detached from the
// tick. The only error returned is the labels_pending write failing.
func (d *Dispatcher) labelQueued(ctx context.Context, row *Dispatch) error {
	lctx, cancel := bookkeepingContext(ctx)
	defer cancel()
	if err := d.Provider.SetLabels(lctx, d.Conn, row.IssueNumber, []string{LabelAgentQueued}, nil); err == nil {
		return nil
	}
	if err := d.Store.SetDispatchLabelsPending(lctx, row.ID, true); err != nil {
		return fmt.Errorf("mark labels pending for #%d: %w", row.IssueNumber, err)
	}
	row.LabelsPending = true
	return nil
}

// failBeforeStart fails a row the tick must give up on before starting
// its run, so the tick's error return does not leave it QUEUED, and
// returns cause (joined with the bookkeeping error, if that failed too).
func (d *Dispatcher) failBeforeStart(ctx context.Context, row *Dispatch, cause error) error {
	if _, err := d.failStart(ctx, row, cause); err != nil {
		return errors.Join(cause, err)
	}
	return cause
}

func containsExact(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// failureBookkeepingBudget bounds the tick's pre-start and failStart
// store and forge writes once detached from the tick's context.
const failureBookkeepingBudget = 30 * time.Second

// bookkeepingContext detaches ctx from the tick's cancellation (keeping
// its values) and bounds it by failureBookkeepingBudget.
func bookkeepingContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), failureBookkeepingBudget)
}

// failStart moves a row whose run never started to FAILED, then projects
// that onto the issue (agent:failed + a comment), best-effort.
//
// The bookkeeping runs on a context detached from the tick's: the start
// most often fails BECAUSE the tick was cancelled or timed out (a client
// deadline landing mid-provision), and leaving the row QUEUED would lock
// the issue forever — nothing sweeps queued rows. Same idiom as
// endRunLease. The forge comment is generic and names the dispatch id;
// the raw error stays in failure_reason, readable via `tracker
// dispatches`, never on a possibly public issue.
func (d *Dispatcher) failStart(tickCtx context.Context, row *Dispatch, startErr error) (*Dispatch, error) {
	ctx, cancel := bookkeepingContext(tickCtx)
	defer cancel()
	reason := fmt.Sprintf("run did not start: %v", startErr)
	now := d.Clock.Now()
	if _, err := d.Store.TransitionDispatch(ctx, row.ID,
		pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_QUEUED, pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_FAILED, reason, now); err != nil {
		return nil, fmt.Errorf("fail dispatch for #%d: %w", row.IssueNumber, err)
	}
	out := *row
	out.State = pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_FAILED
	out.FailureReason = reason
	out.EndedAt = now

	labelErr := d.Provider.SetLabels(ctx, d.Conn, row.IssueNumber, []string{LabelAgentFailed}, []string{LabelAgentQueued})
	body := Sanitize(fmt.Sprintf("The agent run for `%s%s` could not be started (dispatch `%s`). "+
		"An operator can see the reason with `containarium tracker dispatches <username> <connection> --state failed`. "+
		"To retry, remove `%s` and re-add the scope label.",
		ScopeLabelPrefix, row.Scope, row.ID, LabelAgentFailed)) +
		"\n\n" + Stamp(dispatcherIdentity(row.Username, row.RunID), KindComment)
	_, commentErr := d.Provider.Comment(ctx, d.Conn, row.IssueNumber, body)
	if labelErr != nil || commentErr != nil {
		if err := d.Store.SetDispatchLabelsPending(ctx, row.ID, true); err != nil {
			return nil, fmt.Errorf("mark labels pending for #%d: %w", row.IssueNumber, err)
		}
		out.LabelsPending = true
	}
	return &out, nil
}

// warnUnrouted posts the one-time warning for an unrouted scope label.
// The warning row is recorded first so concurrent dispatchers post it
// once; a failed post forgets the row so the next tick retries.
func (d *Dispatcher) warnUnrouted(ctx context.Context, username, connection string, issue int64, scope string) error {
	first, err := d.Store.RecordDispatchWarning(ctx, username, connection, issue, scope)
	if err != nil {
		return fmt.Errorf("record unrouted warning for #%d: %w", issue, err)
	}
	if !first {
		return nil
	}
	// Label names are issue metadata anyone with triage rights controls.
	// Only a suffix that could be a route scope is echoed; anything else
	// gets generic text. Sanitize runs BEFORE the stamp is appended so a
	// forged marker in a label is stripped and the real one kept.
	text := "No agent is routed for this issue's `scope:` label on this tracker connection, so it will not start a run; " +
		"the label is not a valid route scope (letters, digits, `.`, `_`, `-`; max 64)."
	if ValidateRouteScope(scope) == nil {
		text = fmt.Sprintf("No agent is routed for `%s%s` on this tracker connection, so this label will not start a run. "+
			"An operator can route it with `containarium tracker route set <username> <connection> --scope %s --skill <skill-id>`.",
			ScopeLabelPrefix, scope, scope)
	}
	body := Sanitize(text) + "\n\n" + Stamp(dispatcherIdentity(username, ""), KindComment)
	if _, err := d.Provider.Comment(ctx, d.Conn, issue, body); err != nil {
		if ferr := d.Store.ForgetDispatchWarning(ctx, username, connection, issue, scope); ferr != nil {
			return fmt.Errorf("forget unrouted warning for #%d: %w", issue, ferr)
		}
	}
	return nil
}

// dispatcherIdentity is the stamp on the dispatcher's own comments: the
// daemon acting for the operator's tenant, not any run. runID, when
// known, names the run the comment is about.
func dispatcherIdentity(username, runID string) Identity {
	if runID == "" {
		runID = username
	}
	return Identity{RunID: runID, SkillID: "dispatcher"}
}

func (d *Dispatcher) newRunID() string {
	if d.NewRunID != nil {
		return d.NewRunID()
	}
	return uuid.NewString()
}

// dispatchInputJSON is the run's input_json: the issue reference and
// the dispatch id, never the issue body.
func dispatchInputJSON(row *Dispatch) (string, error) {
	b, err := protojson.Marshal(&pb.TrackerDispatchInput{
		Connection:  row.Connection,
		IssueNumber: row.IssueNumber,
		Scope:       row.Scope,
		DispatchId:  row.ID,
		Depth:       row.Depth,
		Username:    row.Username,
	})
	if err != nil {
		return "", fmt.Errorf("encode dispatch input: %w", err)
	}
	return string(b), nil
}

// scopeLabels returns the sorted, de-duplicated suffixes of an issue's
// `scope:<role>` labels. Sorted so a multi-scope issue picks the same
// route on every dispatcher.
func scopeLabels(labels []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range labels {
		suffix, ok := strings.CutPrefix(l, ScopeLabelPrefix)
		if !ok || suffix == "" || seen[suffix] {
			continue
		}
		seen[suffix] = true
		out = append(out, suffix)
	}
	sort.Strings(out)
	return out
}

// hasAnyLabel matches the gate and state labels case-insensitively and
// ignoring surrounding whitespace: GitHub compares label names
// case-insensitively but returns the case a label was first created
// with, so a repo whose label was created as `Agent:Needs-Approval`
// must still gate. Scope matching (scopeLabels) stays exact — a
// mismatch there fails closed (no run), a mismatch here would fail open.
func hasAnyLabel(labels []string, want ...string) bool {
	for _, l := range labels {
		l = strings.TrimSpace(l)
		for _, w := range want {
			if strings.EqualFold(l, w) {
				return true
			}
		}
	}
	return false
}
