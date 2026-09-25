package tracker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Completion hook (#2023): the dispatch row moves queued -> running when
// the run registers and running -> done|failed when it ends, each a
// compare-and-set, and the forge labels follow the row. Real Postgres
// store, fake forge, fake RunStarter that drives the lifecycle the way
// the production starter does.

// lifecycleRunStarter reports the start synchronously (as the
// production starter does before the in-box agent is launched) and
// keeps each run's lifecycle so a test can end it later — or ends it
// immediately with endWith.
type lifecycleRunStarter struct {
	mu      sync.Mutex
	calls   []StartRunRequest
	endWith *RunOutcome
}

func (l *lifecycleRunStarter) StartRun(ctx context.Context, req StartRunRequest) error {
	l.mu.Lock()
	l.calls = append(l.calls, req)
	end := l.endWith
	l.mu.Unlock()
	if req.Lifecycle != nil {
		req.Lifecycle.RunStarted(ctx)
		if end != nil {
			req.Lifecycle.RunEnded(ctx, *end)
		}
	}
	return nil
}

func (l *lifecycleRunStarter) started() []StartRunRequest {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]StartRunRequest(nil), l.calls...)
}

func (l *lifecycleRunStarter) lifecycle(t *testing.T, i int) RunLifecycle {
	t.Helper()
	calls := l.started()
	if len(calls) <= i || calls[i].Lifecycle == nil {
		t.Fatalf("StartRun call %d has no lifecycle (calls=%d)", i, len(calls))
	}
	return calls[i].Lifecycle
}

func newLifecycleFixture(t *testing.T, user string, issues ...Issue) (*Dispatcher, *Store, *fakeDispatchProvider, *lifecycleRunStarter, context.Context) {
	t.Helper()
	provider := newFakeDispatchProvider(issues...)
	runs := &lifecycleRunStarter{}
	d, store, ctx := newDispatchFixture(t, user, provider, &fakeRunStarter{})
	d.Runs = runs
	return d, store, provider, runs, ctx
}

func onlyRow(t *testing.T, store *Store, ctx context.Context, user string) Dispatch {
	t.Helper()
	rows, err := store.ListDispatches(ctx, user, "default", pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_UNSPECIFIED)
	if err != nil {
		t.Fatalf("ListDispatches: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %+v, want exactly one", rows)
	}
	return rows[0]
}

// TestDispatchLifecycle_QueuedRunningDone: the happy path. The run
// registering moves the row to RUNNING and the issue to agent:running
// (agent:queued removed); the run ending cleanly moves the row to DONE,
// the issue to agent:done, and removes the trigger scope label.
func TestDispatchLifecycle_QueuedRunningDone(t *testing.T) {
	const user = "tracker-lifecycle-done"
	d, store, provider, runs, ctx := newLifecycleFixture(t, user, Issue{Number: 42, Labels: []string{"scope:product", "bug"}})

	res, err := d.Tick(ctx, user, "default")
	if err != nil || len(res.Started) != 1 {
		t.Fatalf("Tick = (%+v, %v), want one started", res, err)
	}
	if got := res.Started[0].State; got != pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_RUNNING {
		t.Errorf("started row state = %v, want RUNNING (the run registered)", got)
	}
	row := onlyRow(t, store, ctx, user)
	if row.State != pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_RUNNING || row.StartedAt.IsZero() {
		t.Fatalf("row = %+v, want RUNNING with started_at", row)
	}
	labels := provider.labels(42)
	if !containsString(labels, LabelAgentRunning) || containsString(labels, LabelAgentQueued) {
		t.Fatalf("labels while running = %v, want %s and not %s", labels, LabelAgentRunning, LabelAgentQueued)
	}

	runs.lifecycle(t, 0).RunEnded(ctx, RunOutcome{})

	row = onlyRow(t, store, ctx, user)
	if row.State != pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_DONE || row.EndedAt.IsZero() || row.LabelsPending {
		t.Fatalf("row = %+v, want DONE with ended_at and no labels pending", row)
	}
	labels = provider.labels(42)
	if !containsString(labels, LabelAgentDone) {
		t.Errorf("labels = %v, want %s", labels, LabelAgentDone)
	}
	for _, gone := range []string{LabelAgentRunning, LabelAgentQueued, "scope:product"} {
		if containsString(labels, gone) {
			t.Errorf("labels = %v, want %s removed on done", labels, gone)
		}
	}
	if !containsString(labels, "bug") {
		t.Errorf("labels = %v, an unrelated label must survive", labels)
	}
	// The result comment is the run's own job; the dispatcher says
	// nothing on success.
	if c := provider.commentsOn(42); len(c) != 0 {
		t.Errorf("dispatcher comments on success = %q, want none", c)
	}
}

// TestDispatchLifecycle_RunningFailedWithComment: a run that ends with
// an error moves RUNNING -> FAILED, labels agent:failed, keeps the
// scope label (a human retries by removing agent:failed), and posts one
// stamped comment naming the run and dispatch — never the raw error.
func TestDispatchLifecycle_RunningFailedWithComment(t *testing.T) {
	const user = "tracker-lifecycle-failed"
	d, store, provider, runs, ctx := newLifecycleFixture(t, user, Issue{Number: 5, Labels: []string{"scope:product"}})

	if res, err := d.Tick(ctx, user, "default"); err != nil || len(res.Started) != 1 {
		t.Fatalf("Tick = (%+v, %v)", res, err)
	}
	runs.lifecycle(t, 0).RunEnded(ctx, RunOutcome{Err: errors.New("agent exploded at 10.0.0.9 for tenant secret-tenant")})

	row := onlyRow(t, store, ctx, user)
	if row.State != pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_FAILED || row.EndedAt.IsZero() ||
		!strings.Contains(row.FailureReason, "agent exploded") {
		t.Fatalf("row = %+v, want FAILED with the reason recorded on the row", row)
	}
	labels := provider.labels(5)
	if !containsString(labels, LabelAgentFailed) || containsString(labels, LabelAgentRunning) || containsString(labels, LabelAgentQueued) {
		t.Errorf("labels = %v, want %s only among state labels", labels, LabelAgentFailed)
	}
	if !containsString(labels, "scope:product") {
		t.Errorf("labels = %v, the scope label stays on failure so a retry is one label removal", labels)
	}
	comments := provider.commentsOn(5)
	if len(comments) != 1 {
		t.Fatalf("comments = %q, want exactly one failure comment", comments)
	}
	if !strings.Contains(comments[0], row.ID) || !strings.Contains(comments[0], row.RunID) {
		t.Errorf("comment = %q, want it to name dispatch %s and run %s", comments[0], row.ID, row.RunID)
	}
	if strings.Contains(comments[0], "exploded") || strings.Contains(comments[0], "10.0.0.9") || strings.Contains(comments[0], "secret-tenant") {
		t.Errorf("comment = %q, must not carry the raw run error", comments[0])
	}
	if _, _, kind, ok := ParseMarker(comments[0]); !ok || kind != KindComment {
		t.Errorf("comment = %q, want a platform identity stamp", comments[0])
	}
}

// TestDispatchLifecycle_StaleTransitionIsNoop: a hook that loses the
// compare-and-set (the row was already moved by someone else — e.g. a
// timeout sweep failed it) changes nothing: not the row, not the
// labels, no comment.
func TestDispatchLifecycle_StaleTransitionIsNoop(t *testing.T) {
	const user = "tracker-lifecycle-stale"
	d, store, provider, runs, ctx := newLifecycleFixture(t, user, Issue{Number: 9, Labels: []string{"scope:product"}})
	if res, err := d.Tick(ctx, user, "default"); err != nil || len(res.Started) != 1 {
		t.Fatalf("Tick = (%+v, %v)", res, err)
	}
	row := onlyRow(t, store, ctx, user)
	if ok, err := store.TransitionDispatch(ctx, row.ID,
		pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_RUNNING, pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_FAILED, "timed out", d.Clock.Now()); err != nil || !ok {
		t.Fatalf("simulate sweep = (%v, %v)", ok, err)
	}
	before := provider.labels(9)

	lc := runs.lifecycle(t, 0)
	lc.RunEnded(ctx, RunOutcome{}) // late success report
	lc.RunStarted(ctx)             // late (duplicate) start report
	lc.RunEnded(ctx, RunOutcome{Err: errors.New("x")})

	row = onlyRow(t, store, ctx, user)
	if row.State != pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_FAILED || row.FailureReason != "timed out" {
		t.Fatalf("row = %+v, want the sweep's FAILED untouched", row)
	}
	if after := provider.labels(9); strings.Join(after, ",") != strings.Join(before, ",") {
		t.Errorf("labels changed %v -> %v on a lost compare-and-set", before, after)
	}
	if c := provider.commentsOn(9); len(c) != 0 {
		t.Errorf("comments = %q, want none from a lost compare-and-set", c)
	}
}

// TestDispatchLifecycle_HookRunsOnCancelledContext: the hook is called
// from a goroutine whose originating context (the tick RPC) is long
// gone. A cancelled context must not strand the row RUNNING.
func TestDispatchLifecycle_HookRunsOnCancelledContext(t *testing.T) {
	const user = "tracker-lifecycle-cancelled"
	d, store, provider, runs, ctx := newLifecycleFixture(t, user, Issue{Number: 3, Labels: []string{"scope:product"}})
	if res, err := d.Tick(ctx, user, "default"); err != nil || len(res.Started) != 1 {
		t.Fatalf("Tick = (%+v, %v)", res, err)
	}
	dead, cancel := context.WithCancel(ctx)
	cancel()
	runs.lifecycle(t, 0).RunEnded(dead, RunOutcome{})

	if row := onlyRow(t, store, ctx, user); row.State != pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_DONE {
		t.Fatalf("row = %+v, want DONE even though the hook's context was cancelled", row)
	}
	if !containsString(provider.labels(3), LabelAgentDone) {
		t.Errorf("labels = %v, want %s", provider.labels(3), LabelAgentDone)
	}

	// Same for the start report.
	provider.relabel(3, "scope:product")
	if res, err := d.Tick(ctx, user, "default"); err != nil || len(res.Started) != 1 {
		t.Fatalf("Tick 2 = (%+v, %v)", res, err)
	}
	runs.lifecycle(t, 1).RunStarted(dead) // already reported once by the starter: a no-op
	runs.lifecycle(t, 1).RunEnded(dead, RunOutcome{Err: errors.New("boom")})
	rows, _ := store.ListDispatches(ctx, user, "default", pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_FAILED)
	if len(rows) != 1 {
		t.Fatalf("failed rows = %+v, want the second generation FAILED on a cancelled context", rows)
	}
}

// TestDispatchLifecycle_RunEndedBeforeStartReport: a run that ends
// before anything reported its start (queued -> done is a legal edge)
// still lands terminal, with the queued label cleared.
func TestDispatchLifecycle_RunEndedBeforeStartReport(t *testing.T) {
	const user = "tracker-lifecycle-early-end"
	provider := newFakeDispatchProvider(Issue{Number: 4, Labels: []string{"scope:product"}})
	var captured RunLifecycle
	d, store, ctx := newDispatchFixture(t, user, provider, &fakeRunStarter{})
	d.Runs = runStarterFunc(func(_ context.Context, req StartRunRequest) error {
		captured = req.Lifecycle
		return nil
	})
	if res, err := d.Tick(ctx, user, "default"); err != nil || len(res.Started) != 1 {
		t.Fatalf("Tick = (%+v, %v)", res, err)
	}
	if res := onlyRow(t, store, ctx, user); res.State != pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_QUEUED {
		t.Fatalf("row = %+v, want QUEUED (no start reported)", res)
	}
	captured.RunEnded(ctx, RunOutcome{})
	if row := onlyRow(t, store, ctx, user); row.State != pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_DONE {
		t.Fatalf("row = %+v, want DONE", row)
	}
	labels := provider.labels(4)
	if !containsString(labels, LabelAgentDone) || containsString(labels, LabelAgentQueued) || containsString(labels, "scope:product") {
		t.Errorf("labels = %v, want agent:done, no agent:queued, no scope label", labels)
	}
}

// TestDispatchLifecycle_LabelFailureMarksPending: the row is
// authoritative; a forge failure while projecting it leaves
// labels_pending for the retry (#2026) instead of losing the state.
func TestDispatchLifecycle_LabelFailureMarksPending(t *testing.T) {
	const user = "tracker-lifecycle-labelfail"
	d, store, provider, runs, ctx := newLifecycleFixture(t, user, Issue{Number: 6, Labels: []string{"scope:product"}})
	if res, err := d.Tick(ctx, user, "default"); err != nil || len(res.Started) != 1 {
		t.Fatalf("Tick = (%+v, %v)", res, err)
	}
	provider.mu.Lock()
	provider.labelErr = errors.New("forge unreachable")
	provider.mu.Unlock()
	runs.lifecycle(t, 0).RunEnded(ctx, RunOutcome{})
	row := onlyRow(t, store, ctx, user)
	if row.State != pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_DONE || !row.LabelsPending {
		t.Fatalf("row = %+v, want DONE with labels_pending", row)
	}
}

// TestDispatch_QueuedLabelBeforeStart: agent:queued is on the issue
// before the run is started (provisioning can take minutes), and a
// start failure clears it in favour of agent:failed.
func TestDispatch_QueuedLabelBeforeStart(t *testing.T) {
	const user = "tracker-dispatch-queued-first"
	provider := newFakeDispatchProvider(Issue{Number: 2, Labels: []string{"scope:product"}})
	var seen []string
	d, _, ctx := newDispatchFixture(t, user, provider, &fakeRunStarter{})
	d.Runs = runStarterFunc(func(context.Context, StartRunRequest) error {
		seen = provider.labels(2)
		return errors.New("no capacity")
	})
	if _, err := d.Tick(ctx, user, "default"); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if !containsString(seen, LabelAgentQueued) {
		t.Errorf("labels during StartRun = %v, want %s already applied", seen, LabelAgentQueued)
	}
	labels := provider.labels(2)
	if !containsString(labels, LabelAgentFailed) || containsString(labels, LabelAgentQueued) {
		t.Errorf("labels after failed start = %v, want %s and not %s", labels, LabelAgentFailed, LabelAgentQueued)
	}
}

// TestDispatch_InputCarriesTenantAndRepo: the run's input names its own
// tenant (every broker verb needs it) and the starter is handed the
// connection's repository so a doc change can be submitted.
func TestDispatch_InputCarriesTenantAndRepo(t *testing.T) {
	const user = "tracker-dispatch-input-tenant"
	d, _, _, runs, ctx := newLifecycleFixture(t, user, Issue{Number: 1, Labels: []string{"scope:product"}})
	d.RepoURL = "https://forge.example.com/acme/widgets.git"
	if _, err := d.Tick(ctx, user, "default"); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	call := runs.started()[0]
	if !strings.Contains(call.InputJSON, `"username":"`+user+`"`) {
		t.Errorf("input_json = %s, want the tenant username", call.InputJSON)
	}
	if call.RepoURL != d.RepoURL {
		t.Errorf("RepoURL = %q, want %q", call.RepoURL, d.RepoURL)
	}
}

// staleListProvider hands dispatcher A an issue list, then — before A
// gets to act on it — lets a peer finish the issue's whole run.
type staleListProvider struct {
	*fakeDispatchProvider
	afterList func()
	once      sync.Once
}

func (s *staleListProvider) ListIssues(ctx context.Context, c Conn, f IssueFilter) ([]Issue, error) {
	out, err := s.fakeDispatchProvider.ListIssues(ctx, c, f)
	s.once.Do(s.afterList)
	return out, err
}

// TestDispatch_StaleListAfterDoneNoDoubleRun is the probe from the
// #2022 review: dispatcher A lists the issue; peer B dispatches it and
// the run completes (row DONE, agent:done, scope label removed); A's
// insert then succeeds (no ACTIVE row any more). A must re-read the
// issue and not start a second run.
func TestDispatch_StaleListAfterDoneNoDoubleRun(t *testing.T) {
	const user = "tracker-dispatch-stale-list"
	base := newFakeDispatchProvider(Issue{Number: 77, Labels: []string{"scope:product"}})
	runs := &lifecycleRunStarter{endWith: &RunOutcome{}}
	dB, store, ctx := newDispatchFixture(t, user, base, &fakeRunStarter{})
	dB.Runs = runs

	stale := &staleListProvider{fakeDispatchProvider: base}
	dA := &Dispatcher{Store: store, Provider: stale, Conn: dB.Conn, Runs: runs, Clock: dB.Clock}
	stale.afterList = func() {
		if res, err := dB.Tick(ctx, user, "default"); err != nil || len(res.Started) != 1 {
			t.Errorf("peer tick = (%+v, %v), want one started", res, err)
		}
	}

	res, err := dA.Tick(ctx, user, "default")
	if err != nil {
		t.Fatalf("Tick A: %v", err)
	}
	if n := len(runs.started()); n != 1 {
		t.Fatalf("StartRun calls = %d, want exactly 1 (a stale list must not double-run a finished issue)", n)
	}
	if len(res.Started) != 0 || res.SkippedActive != 1 {
		t.Errorf("A's tick = %+v, want nothing started and the issue counted as skipped", res)
	}
	rows, err := store.ListDispatches(ctx, user, "default", pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_UNSPECIFIED)
	if err != nil {
		t.Fatalf("ListDispatches: %v", err)
	}
	if len(rows) != 1 || rows[0].State != pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_DONE {
		t.Fatalf("rows = %+v, want only B's DONE row (A's abandoned insert removed)", rows)
	}
	labels := base.labels(77)
	if !containsString(labels, LabelAgentDone) || containsString(labels, LabelAgentQueued) {
		t.Errorf("labels = %v, A must not have touched the finished issue", labels)
	}
}

// TestDispatch_RecheckReadErrorSkips: if the re-read fails the issue is
// skipped this tick (the row removed so the next tick can retry), never
// started blind.
func TestDispatch_RecheckReadErrorSkips(t *testing.T) {
	const user = "tracker-dispatch-recheck-err"
	provider := newFakeDispatchProvider(Issue{Number: 8, Labels: []string{"scope:product"}})
	provider.getErr = errors.New("forge hiccup")
	runs := &lifecycleRunStarter{}
	d, store, ctx := newDispatchFixture(t, user, provider, &fakeRunStarter{})
	d.Runs = runs
	if _, err := d.Tick(ctx, user, "default"); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if n := len(runs.started()); n != 0 {
		t.Fatalf("StartRun calls = %d, want 0 when the re-read fails", n)
	}
	rows, _ := store.ListDispatches(ctx, user, "default", pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_UNSPECIFIED)
	if len(rows) != 0 {
		t.Fatalf("rows = %+v, want the unstarted row removed", rows)
	}
	provider.mu.Lock()
	provider.getErr = nil
	provider.mu.Unlock()
	if res, err := d.Tick(ctx, user, "default"); err != nil || len(res.Started) != 1 {
		t.Fatalf("retry tick = (%+v, %v), want it dispatched", res, err)
	}
}

// TestDispatch_RerunAfterCompletionStartsNewGeneration: through the real
// completion hook, a done issue is left alone until a human re-labels
// it, and then runs again as a new generation — once.
func TestDispatch_RerunAfterCompletionStartsNewGeneration(t *testing.T) {
	const user = "tracker-dispatch-rerun-hook"
	provider := newFakeDispatchProvider(Issue{Number: 12, Labels: []string{"scope:product"}})
	runs := &lifecycleRunStarter{endWith: &RunOutcome{}}
	d, store, ctx := newDispatchFixture(t, user, provider, &fakeRunStarter{})
	d.Runs = runs

	if res, err := d.Tick(ctx, user, "default"); err != nil || len(res.Started) != 1 {
		t.Fatalf("Tick 1 = (%+v, %v)", res, err)
	}
	if res, err := d.Tick(ctx, user, "default"); err != nil || len(res.Started) != 0 {
		t.Fatalf("Tick 2 = (%+v, %v), want the done issue left alone", res, err)
	}
	// A human removes agent:done and re-adds the scope label.
	provider.relabel(12, "scope:product")
	if res, err := d.Tick(ctx, user, "default"); err != nil || len(res.Started) != 1 {
		t.Fatalf("Tick 3 = (%+v, %v), want a new generation", res, err)
	}
	if n := len(runs.started()); n != 2 {
		t.Fatalf("StartRun calls = %d, want 2", n)
	}
	rows, _ := store.ListDispatches(ctx, user, "default", pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_DONE)
	if len(rows) != 2 || rows[0].ID == rows[1].ID {
		t.Fatalf("done rows = %+v, want two distinct generations", rows)
	}
}

// TestStateLabelWriters_OnlyDispatcher: the dispatcher's code path is
// the only writer of the agent:* state labels. A source scan over the
// daemon's non-test Go files: any other file naming a state-label
// constant (or spelling one out) must be deliberately added here.
func TestStateLabelWriters_OnlyDispatcher(t *testing.T) {
	allowed := map[string]bool{
		"internal/tracker/policy.go":             true, // defines them and reserves them from run tokens
		"internal/tracker/dispatch.go":           true, // the tick: queued, failed-to-start
		"internal/tracker/dispatch_lifecycle.go": true, // the completion hook: running, done, failed
	}
	pattern := regexp.MustCompile(`LabelAgent(Queued|Running|Done|Failed)|"agent:(queued|running|done|failed)"`)
	root := filepath.Join("..", "..")
	var offenders []string
	for _, dir := range []string{"internal", "cmd", "pkg"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, de os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if de.IsDir() {
				if de.Name() == "pb" || de.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			if allowed[rel] {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if pattern.Match(b) {
				offenders = append(offenders, rel)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	if len(offenders) > 0 {
		t.Fatalf("state labels referenced outside the dispatcher: %v", offenders)
	}
}

type runStarterFunc func(ctx context.Context, req StartRunRequest) error

func (f runStarterFunc) StartRun(ctx context.Context, req StartRunRequest) error { return f(ctx, req) }
