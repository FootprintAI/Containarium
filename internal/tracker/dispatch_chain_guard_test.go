package tracker

import (
	"context"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// Chain guards on the dispatcher side (#2025; design
// docs/architecture/issue-triggered-agents.md, "Chain guards": "the
// dispatcher also refuses to start a run for an issue whose depth
// exceeds the max, so a policy lowered later still holds").

// seedChain records a lineage chain #root → #root+1 → … of n children,
// one run per hop, with no caps (a policy that allowed it at the time).
func seedChain(t *testing.T, store *Store, ctx context.Context, user string, root int64, n int) {
	t.Helper()
	if _, err := store.pool.Exec(ctx, "DELETE FROM tracker_issue_lineage WHERE username = $1", user); err != nil {
		t.Fatalf("clean lineage: %v", err)
	}
	for i := 1; i <= n; i++ {
		child := root + int64(i)
		if _, err := store.RecordChild(ctx, Lineage{
			Username: user, Connection: "default", ParentNumber: child - 1, CreatedByRun: "seed-run-" + string(rune('a'+i)),
		}, 0, 0, func(context.Context) (int64, error) { return child, nil }); err != nil {
			t.Fatalf("seed lineage #%d: %v", child, err)
		}
	}
}

// TestDispatch_SkipsOverDepth: with the default policy (max_depth 3) an
// issue at depth 3 is dispatched — and its row and run input carry that
// depth — while one at depth 4 (filed under an earlier, looser policy) is
// skipped and counted, with no row, no label write and no run.
func TestDispatch_SkipsOverDepth(t *testing.T) {
	const user = "tracker-dispatch-overdepth"
	provider := newFakeDispatchProvider(
		Issue{Number: 103, Labels: []string{"scope:product"}}, // depth 3
		Issue{Number: 104, Labels: []string{"scope:product"}}, // depth 4
	)
	runs := &fakeRunStarter{}
	d, store, ctx := newDispatchFixture(t, user, provider, runs)
	seedChain(t, store, ctx, user, 100, 4)

	res, err := d.Tick(ctx, user, "default")
	if err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if res.SkippedOverDepth != 1 {
		t.Errorf("SkippedOverDepth = %d, want 1", res.SkippedOverDepth)
	}
	if len(res.Started) != 1 || res.Started[0].IssueNumber != 103 {
		t.Fatalf("started = %+v, want only #103 (depth 3 == max)", res.Started)
	}
	if res.Started[0].Depth != 3 {
		t.Errorf("started row depth = %d, want 3 (from lineage)", res.Started[0].Depth)
	}
	calls := runs.started()
	if len(calls) != 1 {
		t.Fatalf("StartRun calls = %d, want 1", len(calls))
	}
	var in pb.TrackerDispatchInput
	if err := protojson.Unmarshal([]byte(calls[0].InputJSON), &in); err != nil {
		t.Fatalf("decode input: %v", err)
	}
	if in.GetDepth() != 3 {
		t.Errorf("input depth = %d, want 3", in.GetDepth())
	}
	if got := provider.labels(104); len(got) != 1 || got[0] != "scope:product" {
		t.Errorf("over-depth issue labels = %v, want untouched [scope:product]", got)
	}
	if c := provider.commentsOn(104); len(c) != 0 {
		t.Errorf("over-depth issue got comments %v, want none", c)
	}
	rows, err := store.ListDispatches(ctx, user, "default", pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_UNSPECIFIED)
	if err != nil {
		t.Fatalf("ListDispatches: %v", err)
	}
	for _, r := range rows {
		if r.IssueNumber == 104 {
			t.Errorf("over-depth issue has a dispatch row %+v, want none", r)
		}
	}
}

// TestDispatch_LoweredPolicyStillHolds: the connection's policy is read
// per tick, so lowering max_depth after a chain was filed stops the
// deeper issues from dispatching; a human-created issue (no lineage row,
// depth 0) is always within bounds.
func TestDispatch_LoweredPolicyStillHolds(t *testing.T) {
	const user = "tracker-dispatch-lowered"
	provider := newFakeDispatchProvider(
		Issue{Number: 200, Labels: []string{"scope:product"}}, // human, depth 0
		Issue{Number: 201, Labels: []string{"scope:product"}}, // depth 1
		Issue{Number: 202, Labels: []string{"scope:product"}}, // depth 2
	)
	runs := &fakeRunStarter{}
	d, store, ctx := newDispatchFixture(t, user, provider, runs)
	seedChain(t, store, ctx, user, 200, 2)
	lowered := PolicyFromProto(&pb.TrackerPolicy{MaxDepth: 1})
	d.Policy = &lowered

	res, err := d.Tick(ctx, user, "default")
	if err != nil {
		t.Fatalf("Tick: %v", err)
	}
	var started []int64
	for _, r := range res.Started {
		started = append(started, r.IssueNumber)
	}
	if len(started) != 2 || started[0] != 200 || started[1] != 201 {
		t.Errorf("started = %v, want [200 201]", started)
	}
	if res.SkippedOverDepth != 1 {
		t.Errorf("SkippedOverDepth = %d, want 1 (#202)", res.SkippedOverDepth)
	}
}

// TestDispatch_NilPolicyUsesDefaults: a Dispatcher built without a
// policy enforces the documented default max_depth (3), never
// "unlimited" — a wiring mistake must fail closed.
func TestDispatch_NilPolicyUsesDefaults(t *testing.T) {
	const user = "tracker-dispatch-nilpolicy"
	provider := newFakeDispatchProvider(Issue{Number: 304, Labels: []string{"scope:product"}}) // depth 4
	runs := &fakeRunStarter{}
	d, store, ctx := newDispatchFixture(t, user, provider, runs)
	seedChain(t, store, ctx, user, 300, 4)
	d.Policy = nil

	res, err := d.Tick(ctx, user, "default")
	if err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if res.SkippedOverDepth != 1 || len(runs.started()) != 0 {
		t.Fatalf("result = %+v, runs = %d; want the depth-4 issue skipped under the default max_depth", res, len(runs.started()))
	}
}

// TestDispatch_GatedFollowUpIgnoredUntilHumanReleases pins criterion 1
// end to end on the dispatcher side: an agent-filed follow-up (lineage
// depth 1, gate label on it as CreateTrackerIssue forces) is skipped on
// every tick; once a human removes agent:needs-approval it dispatches,
// carrying its depth.
func TestDispatch_GatedFollowUpIgnoredUntilHumanReleases(t *testing.T) {
	const user = "tracker-dispatch-gated-child"
	provider := newFakeDispatchProvider(Issue{Number: 401, Labels: []string{"scope:product", LabelNeedsApproval}})
	runs := &fakeRunStarter{}
	d, store, ctx := newDispatchFixture(t, user, provider, runs)
	seedChain(t, store, ctx, user, 400, 1)

	for i := 0; i < 3; i++ {
		res, err := d.Tick(ctx, user, "default")
		if err != nil {
			t.Fatalf("Tick %d: %v", i, err)
		}
		if res.SkippedNeedsApproval != 1 || len(res.Started) != 0 {
			t.Fatalf("Tick %d = %+v, want the gated follow-up skipped", i, res)
		}
	}
	if n := len(runs.started()); n != 0 {
		t.Fatalf("StartRun calls while gated = %d, want 0", n)
	}

	provider.relabel(401, "scope:product") // the human's one action per hop
	res, err := d.Tick(ctx, user, "default")
	if err != nil {
		t.Fatalf("Tick after release: %v", err)
	}
	if len(res.Started) != 1 || res.Started[0].Depth != 1 {
		t.Fatalf("started after release = %+v, want #401 at depth 1", res.Started)
	}
}
