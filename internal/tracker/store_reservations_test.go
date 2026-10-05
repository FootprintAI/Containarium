package tracker

import (
	"context"
	"errors"
	"testing"
)

// Stale lineage reservations (#2062): a reservation RecordChild could not
// clear keeps counting against its run's fan-out. They are listed for an
// operator (ListLineageReservations) and swept when the run's lease ends
// (ReleaseRunReservations), scoped to that run alone.

// leaveStaleReservation drives RecordChild down the one path that
// deliberately leaves its reservation behind — the upstream create
// succeeded but the lineage row could not be recorded — so the row under
// test is a real leftover, not one inserted by hand.
func leaveStaleReservation(t *testing.T, store *Store, ctx context.Context, user, connection, runID string, child int64) {
	t.Helper()
	// Occupy child's primary key so the post-create insert conflicts.
	if _, err := store.pool.Exec(ctx, `INSERT INTO tracker_issue_lineage (username, connection, child_number, parent_number, created_by_run, depth)
		VALUES ($1, $2, $3, 1, 'run-occupier', 1)`, user, connection, child); err != nil {
		t.Fatalf("seed conflicting lineage row: %v", err)
	}
	_, err := store.RecordChild(ctx, Lineage{Username: user, Connection: connection, ParentNumber: 10, CreatedByRun: runID}, 0, 0,
		func(context.Context) (int64, error) { return child, nil })
	var recErr *LineageRecordError
	if !errors.As(err, &recErr) {
		t.Fatalf("setup: RecordChild err = %v, want a *LineageRecordError (which leaves the reservation)", err)
	}
}

func resetReservationFixture(t *testing.T, store *Store, ctx context.Context, users ...string) {
	t.Helper()
	for _, u := range users {
		_, _ = store.pool.Exec(ctx, "DELETE FROM tracker_issue_lineage WHERE username = $1", u)
		_, _ = store.pool.Exec(ctx, "DELETE FROM tracker_lineage_reservations WHERE username = $1", u)
	}
}

func TestReleaseRunReservations_ClearsTheEndedRunsLeftovers(t *testing.T) {
	store, ctx := newTrackerTestStore(t)
	const user = "tracker-store-resv-sweep"
	resetReservationFixture(t, store, ctx, user)

	leaveStaleReservation(t, store, ctx, user, "default", "run-ended", 501)
	leaveStaleReservation(t, store, ctx, user, "other", "run-ended", 502)

	_, reserved, err := claimedCount(ctx, store.pool, user, "default", "run-ended")
	if err != nil {
		t.Fatalf("claimedCount: %v", err)
	}
	if reserved != 1 {
		t.Fatalf("setup: reserved = %d, want 1 stale reservation", reserved)
	}

	n, err := store.ReleaseRunReservations(ctx, user, "run-ended")
	if err != nil {
		t.Fatalf("ReleaseRunReservations: %v", err)
	}
	if n != 2 {
		t.Errorf("released = %d, want 2 (the run's reservations on both connections)", n)
	}
	for _, conn := range []string{"default", "other"} {
		rows, err := store.ListLineageReservations(ctx, user, conn)
		if err != nil {
			t.Fatalf("ListLineageReservations(%s): %v", conn, err)
		}
		if len(rows) != 0 {
			t.Errorf("%s: %d reservation(s) left after the run's lease ended, want 0: %+v", conn, len(rows), rows)
		}
	}

	// Idempotent: a second end (a crew's members share a run id, and the
	// sweep and the run's own end can both reach it) releases nothing.
	if n, err := store.ReleaseRunReservations(ctx, user, "run-ended"); err != nil || n != 0 {
		t.Errorf("second ReleaseRunReservations = %d, %v; want 0, nil", n, err)
	}
}

func TestReleaseRunReservations_LeavesOtherRunsAlone(t *testing.T) {
	store, ctx := newTrackerTestStore(t)
	const user, otherUser = "tracker-store-resv-scope", "tracker-store-resv-scope-other"
	resetReservationFixture(t, store, ctx, user, otherUser)

	leaveStaleReservation(t, store, ctx, user, "default", "run-ended", 601)
	// A different run of the same tenant on the same connection.
	leaveStaleReservation(t, store, ctx, user, "default", "run-still-going", 602)
	// The SAME run id under another tenant: run ids can be caller-chosen,
	// so one tenant's lease end must never reach another tenant's rows.
	leaveStaleReservation(t, store, ctx, otherUser, "default", "run-ended", 603)

	if _, err := store.ReleaseRunReservations(ctx, user, "run-ended"); err != nil {
		t.Fatalf("ReleaseRunReservations: %v", err)
	}

	rows, err := store.ListLineageReservations(ctx, user, "default")
	if err != nil {
		t.Fatalf("ListLineageReservations: %v", err)
	}
	if len(rows) != 1 || rows[0].CreatedByRun != "run-still-going" {
		t.Errorf("tenant's reservations = %+v, want only run-still-going's", rows)
	}
	rows, err = store.ListLineageReservations(ctx, otherUser, "default")
	if err != nil {
		t.Fatalf("ListLineageReservations(other tenant): %v", err)
	}
	if len(rows) != 1 || rows[0].CreatedByRun != "run-ended" {
		t.Errorf("other tenant's reservations = %+v, want its own run-ended row untouched", rows)
	}
}

func TestReleaseRunReservations_RequiresUsernameAndRun(t *testing.T) {
	store, ctx := newTrackerTestStore(t)
	for _, tc := range []struct{ user, run string }{{"", "run-x"}, {"someone", ""}} {
		if _, err := store.ReleaseRunReservations(ctx, tc.user, tc.run); err == nil {
			t.Errorf("ReleaseRunReservations(%q, %q) = nil error, want a refusal (an empty key would widen the delete)", tc.user, tc.run)
		}
	}
}

func TestListLineageReservations_ReportsTheConnectionsRows(t *testing.T) {
	store, ctx := newTrackerTestStore(t)
	const user = "tracker-store-resv-list"
	resetReservationFixture(t, store, ctx, user)

	leaveStaleReservation(t, store, ctx, user, "default", "run-a", 701)
	leaveStaleReservation(t, store, ctx, user, "default", "run-a", 702)
	leaveStaleReservation(t, store, ctx, user, "default", "run-b", 703)
	leaveStaleReservation(t, store, ctx, user, "elsewhere", "run-a", 704)

	rows, err := store.ListLineageReservations(ctx, user, "default")
	if err != nil {
		t.Fatalf("ListLineageReservations: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want 3 (only this connection's): %+v", len(rows), rows)
	}
	perRun := map[string]int{}
	for i, r := range rows {
		if r.Username != user || r.Connection != "default" {
			t.Errorf("row %d = %+v, want it scoped to %s/default", i, r, user)
		}
		if r.ID == 0 || r.CreatedAt.IsZero() {
			t.Errorf("row %d = %+v, want its id and created_at", i, r)
		}
		if i > 0 && r.CreatedAt.Before(rows[i-1].CreatedAt) {
			t.Errorf("rows not oldest-first: %+v", rows)
		}
		perRun[r.CreatedByRun]++
	}
	if perRun["run-a"] != 2 || perRun["run-b"] != 1 {
		t.Errorf("per-run counts = %v, want run-a=2 run-b=1", perRun)
	}

	if _, err := store.ListLineageReservations(ctx, "", "default"); err == nil {
		t.Error("ListLineageReservations with no username = nil error, want a refusal")
	}
}
