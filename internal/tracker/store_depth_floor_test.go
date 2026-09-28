package tracker

import (
	"context"
	"errors"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// TestRecordChild_DepthFloorsAtTheRunsOwnDispatchDepth pins the #2073 fix
// at the store: a child's depth is max(parent's recorded depth, the
// calling run's own dispatch depth) + 1. The run's dispatch depth is what
// the dispatcher wrote on its tracker_dispatches row from the lineage
// table when it started the run — never anything the caller supplies —
// so a run cannot lower its effective depth by naming a shallower
// parent_number. A run with no dispatch row (started by a human, not the
// dispatcher) has no floor above the parent's depth, as before.
func TestRecordChild_DepthFloorsAtTheRunsOwnDispatchDepth(t *testing.T) {
	store, ctx := newTrackerTestStore(t)
	const user = "tracker-store-depth-floor"
	// Dispatch rows hang off the connection by foreign key; recreating it
	// cascades any rows left over from an earlier run of this test.
	_, _ = store.pool.Exec(ctx, "DELETE FROM tracker_connections WHERE username = $1", user)
	_, _ = store.pool.Exec(ctx, "DELETE FROM tracker_issue_lineage WHERE username = $1", user)
	if _, err := store.Set(ctx, Connection{
		Username: user, Name: "default", Provider: pb.TrackerProvider_TRACKER_PROVIDER_GITHUB,
		Project: "acme/widgets", CredentialSecret: "GH_TOKEN",
	}); err != nil {
		t.Fatalf("Set connection: %v", err)
	}
	// #10 (human) → #11 at depth 1, filed by an earlier run.
	if _, err := store.RecordChild(ctx, Lineage{Username: user, Connection: "default", ParentNumber: 10, CreatedByRun: "earlier-run"},
		0, 0, func(context.Context) (int64, error) { return 11, nil }); err != nil {
		t.Fatalf("seed lineage #11: %v", err)
	}
	// The dispatcher started "deep-run" for #11: its row carries depth 1.
	if _, err := store.InsertDispatch(ctx, Dispatch{
		Username: user, Connection: "default", IssueNumber: 11, Scope: "product", SkillID: "product-define",
		RunID: "deep-run", Depth: 1,
	}); err != nil {
		t.Fatalf("seed dispatch row: %v", err)
	}

	next := int64(12)
	file := func(t *testing.T, run string, parent int64, maxDepth int32) (Lineage, error) {
		t.Helper()
		child := next
		next++
		return store.RecordChild(ctx, Lineage{Username: user, Connection: "default", ParentNumber: parent, CreatedByRun: run},
			maxDepth, 0, func(context.Context) (int64, error) { return child, nil })
	}

	// Unrelated depth-0 parent: the floor is the run's own depth, not 0.
	rec, err := file(t, "deep-run", 10, 0)
	if err != nil || rec.Depth != 2 {
		t.Fatalf("deep-run under unrelated #10: depth = %d, %v; want 2 (its own dispatch depth 1, +1)", rec.Depth, err)
	}
	if d, err := store.IssueDepth(ctx, user, "default", rec.ChildNumber); err != nil || d != 2 {
		t.Fatalf("recorded depth of #%d = %d, %v; want 2", rec.ChildNumber, d, err)
	}
	ownChild := rec.ChildNumber

	// Its own dispatched issue: parent depth 1 == run depth 1.
	if rec, err := file(t, "deep-run", 11, 0); err != nil || rec.Depth != 2 {
		t.Fatalf("deep-run under its dispatched #11: depth = %d, %v; want 2", rec.Depth, err)
	}
	// Its own child (depth 2): the parent's real depth wins over the floor.
	if rec, err := file(t, "deep-run", ownChild, 0); err != nil || rec.Depth != 3 {
		t.Fatalf("deep-run under its own child #%d: depth = %d, %v; want 3", ownChild, rec.Depth, err)
	}
	// A human-started run (no dispatch row) keeps parent depth + 1.
	if rec, err := file(t, "manual-run", 10, 0); err != nil || rec.Depth != 1 {
		t.Fatalf("manual run under #10: depth = %d, %v; want 1", rec.Depth, err)
	}

	// The floor is what max_depth bites on: with max_depth 1 the deep run
	// cannot file anything, whatever parent it names, and create never runs.
	created := false
	_, err = store.RecordChild(ctx, Lineage{Username: user, Connection: "default", ParentNumber: 10, CreatedByRun: "deep-run"},
		1, 0, func(context.Context) (int64, error) { created = true; return 99, nil })
	if !errors.Is(err, ErrDepthExceeded) {
		t.Fatalf("deep-run under #10 with max_depth 1: err = %v, want ErrDepthExceeded", err)
	}
	if created {
		t.Fatal("create ran for a child refused on depth")
	}
	if n, err := store.ChildrenCount(ctx, user, "default", "deep-run"); err != nil || n != 3 {
		t.Fatalf("deep-run children = %d, %v; want 3 (the refused one left no row)", n, err)
	}
}
