package tracker

import (
	"context"
	"errors"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// max_starts (#2270): a caller enforcing its own budget bounds how many
// runs one tick starts. Issues past the limit get no row and no label,
// so a later tick picks them up.

func fiveEligibleIssues() []Issue {
	var out []Issue
	for n := int64(1); n <= 5; n++ {
		out = append(out, Issue{Number: n, Labels: []string{"scope:product"}})
	}
	return out
}

// dispatchedIssues is the set of issues that have any dispatch row.
func dispatchedIssues(t *testing.T, store *Store, ctx context.Context, user string) map[int64]bool {
	t.Helper()
	rows, err := store.ListDispatches(ctx, user, "default", pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_UNSPECIFIED)
	if err != nil {
		t.Fatalf("ListDispatches: %v", err)
	}
	out := map[int64]bool{}
	for _, r := range rows {
		out[r.IssueNumber] = true
	}
	return out
}

func TestDispatch_MaxStartsBoundsTheTick(t *testing.T) {
	const user = "tracker-dispatch-max-starts"
	provider := newFakeDispatchProvider(fiveEligibleIssues()...)
	runs := &fakeRunStarter{}
	d, store, ctx := newDispatchFixture(t, user, provider, runs)
	d.MaxStarts = 2

	res, err := d.Tick(ctx, user, "default")
	if err != nil {
		t.Fatalf("Tick 1: %v", err)
	}
	if len(res.Started) != 2 || len(runs.started()) != 2 {
		t.Fatalf("Tick 1 started = %d (StartRun calls %d), want exactly 2", len(res.Started), len(runs.started()))
	}
	if res.LeftUndispatched != 3 {
		t.Errorf("Tick 1 LeftUndispatched = %d, want 3", res.LeftUndispatched)
	}
	rows := dispatchedIssues(t, store, ctx, user)
	if len(rows) != 2 {
		t.Errorf("dispatch rows for issues %v, want exactly 2", rows)
	}
	for _, s := range res.Started {
		if !rows[s.IssueNumber] || !containsString(provider.labels(s.IssueNumber), LabelAgentQueued) {
			t.Errorf("started #%d: row=%v labels=%v, want a row and %s", s.IssueNumber, rows[s.IssueNumber], provider.labels(s.IssueNumber), LabelAgentQueued)
		}
	}
	for n := int64(1); n <= 5; n++ {
		if rows[n] {
			continue
		}
		if got := provider.labels(n); len(got) != 1 || got[0] != "scope:product" {
			t.Errorf("undispatched #%d labels = %v, want only scope:product (no agent:* label)", n, got)
		}
	}

	// A later tick with no limit picks up the rest.
	d.MaxStarts = 0
	res, err = d.Tick(ctx, user, "default")
	if err != nil {
		t.Fatalf("Tick 2: %v", err)
	}
	if len(res.Started) != 3 || res.LeftUndispatched != 0 {
		t.Fatalf("Tick 2 started = %d, left = %d; want the remaining 3 started and none left", len(res.Started), res.LeftUndispatched)
	}
	if rows := dispatchedIssues(t, store, ctx, user); len(rows) != 5 || len(runs.started()) != 5 {
		t.Fatalf("after tick 2: rows for %v, StartRun calls %d; want all 5 issues dispatched exactly once", rows, len(runs.started()))
	}
}

// Regression pin: 0 is unlimited — today's behaviour.
func TestDispatch_MaxStartsZeroStartsAll(t *testing.T) {
	const user = "tracker-dispatch-max-starts-zero"
	provider := newFakeDispatchProvider(fiveEligibleIssues()...)
	runs := &fakeRunStarter{}
	d, store, ctx := newDispatchFixture(t, user, provider, runs)

	res, err := d.Tick(ctx, user, "default")
	if err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if len(res.Started) != 5 || len(runs.started()) != 5 || res.LeftUndispatched != 0 {
		t.Fatalf("started = %d, calls = %d, left = %d; want all 5 started and none left", len(res.Started), len(runs.started()), res.LeftUndispatched)
	}
	if rows := dispatchedIssues(t, store, ctx, user); len(rows) != 5 {
		t.Fatalf("rows for %v, want all 5", rows)
	}
}

// Only actual starts count against the limit: skipped issues and starts
// that failed do not use it up, and a skipped issue past the limit is
// counted as skipped, not as left undispatched.
func TestDispatch_MaxStartsCountsOnlyStarts(t *testing.T) {
	const user = "tracker-dispatch-max-starts-only"
	provider := newFakeDispatchProvider(
		Issue{Number: 1, Labels: []string{"scope:product", LabelNeedsApproval}},
		Issue{Number: 2, Labels: []string{"scope:product"}}, // start fails
		Issue{Number: 3, Labels: []string{"scope:product"}},
		Issue{Number: 4, Labels: []string{"scope:product", LabelAgentDone}},
		Issue{Number: 5, Labels: []string{"scope:product"}},
		Issue{Number: 6, Labels: []string{"scope:product", LabelNeedsApproval}},
		Issue{Number: 7, Labels: []string{"scope:product"}},
	)
	runs := &failFirstRunStarter{}
	d, store, ctx := newDispatchFixture(t, user, provider, &runs.fakeRunStarter)
	d.Runs = runs
	d.MaxStarts = 2

	res, err := d.Tick(ctx, user, "default")
	if err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if len(res.Failed) != 1 || res.Failed[0].IssueNumber != 2 {
		t.Fatalf("failed = %+v, want #2", res.Failed)
	}
	if len(res.Started) != 2 || res.Started[0].IssueNumber != 3 || res.Started[1].IssueNumber != 5 {
		t.Fatalf("started = %+v, want #3 and #5 (the failed #2 and the skips do not use up the limit)", res.Started)
	}
	if res.LeftUndispatched != 1 || res.SkippedNeedsApproval != 2 || res.SkippedActive != 1 {
		t.Errorf("left = %d, approval = %d, active = %d; want 1 left (#7), 2 approval, 1 active",
			res.LeftUndispatched, res.SkippedNeedsApproval, res.SkippedActive)
	}
	if dispatchedIssues(t, store, ctx, user)[7] {
		t.Errorf("#7 has a dispatch row, want none")
	}
}

// failFirstRunStarter fails its first StartRun and accepts the rest.
type failFirstRunStarter struct{ fakeRunStarter }

func (f *failFirstRunStarter) StartRun(ctx context.Context, req StartRunRequest) error {
	_ = f.fakeRunStarter.StartRun(ctx, req)
	if len(f.started()) == 1 {
		return errors.New("provision failed")
	}
	return nil
}
