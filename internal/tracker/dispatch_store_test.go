package tracker

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Dispatch store (#2022) — real Postgres, same convention as
// store_test.go. Exactly-once is the partial unique index on active
// rows, so these tests run against the real thing, never a mock.

// seedDispatchConnection wipes and recreates a connection for user so
// each test starts from no dispatch rows and no warnings (both cascade
// from the connection).
func seedDispatchConnection(t *testing.T, store *Store, ctx context.Context, user string) {
	t.Helper()
	_, _ = store.pool.Exec(ctx, "DELETE FROM tracker_connections WHERE username = $1", user)
	if _, err := store.Set(ctx, Connection{
		Username: user, Name: "default", Provider: pb.TrackerProvider_TRACKER_PROVIDER_GITHUB,
		Project: "acme/widgets", CredentialSecret: "GH_TOKEN",
	}); err != nil {
		t.Fatalf("seed connection: %v", err)
	}
}

func newDispatch(user string, issue int64) Dispatch {
	return Dispatch{
		Username: user, Connection: "default", IssueNumber: issue,
		Scope: "product", SkillID: "product-define",
	}
}

// TestDispatchStore_ActiveUniqueRace is #2022's exactly-once proof: N
// concurrent inserters for the same issue, exactly one wins, every
// loser gets ErrDispatchActive. Run with -race.
func TestDispatchStore_ActiveUniqueRace(t *testing.T) {
	store, ctx := newTrackerTestStore(t)
	const user = "tracker-dispatch-race"
	seedDispatchConnection(t, store, ctx, user)

	const n = 8
	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, results[i] = store.InsertDispatch(ctx, newDispatch(user, 7))
		}(i)
	}
	close(start)
	wg.Wait()

	wins, losses := 0, 0
	for i, err := range results {
		switch {
		case err == nil:
			wins++
		case errors.Is(err, ErrDispatchActive):
			losses++
		default:
			t.Errorf("inserter %d: unexpected error %v", i, err)
		}
	}
	if wins != 1 || losses != n-1 {
		t.Fatalf("wins = %d, losses = %d, want exactly 1 win and %d ErrDispatchActive", wins, losses, n-1)
	}
	rows, err := store.ListDispatches(ctx, user, "default", pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_UNSPECIFIED)
	if err != nil {
		t.Fatalf("ListDispatches: %v", err)
	}
	if len(rows) != 1 || rows[0].State != pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_QUEUED {
		t.Fatalf("rows = %+v, want exactly one QUEUED row", rows)
	}
}

func TestDispatchStore_InsertValidation(t *testing.T) {
	store, ctx := newTrackerTestStore(t)
	const user = "tracker-dispatch-validate"
	seedDispatchConnection(t, store, ctx, user)

	tests := []struct {
		name string
		mut  func(d *Dispatch)
		want string
	}{
		{"missing username", func(d *Dispatch) { d.Username = "" }, "username is required"},
		{"missing connection", func(d *Dispatch) { d.Connection = "" }, "connection is required"},
		{"missing issue", func(d *Dispatch) { d.IssueNumber = 0 }, "issue_number"},
		{"missing scope", func(d *Dispatch) { d.Scope = "" }, "scope is required"},
		{"missing skill", func(d *Dispatch) { d.SkillID = "" }, "skill_id is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := newDispatch(user, 1)
			tt.mut(&d)
			if _, err := store.InsertDispatch(ctx, d); err == nil || !containsFold(err.Error(), tt.want) {
				t.Fatalf("err = %v, want one containing %q", err, tt.want)
			}
		})
	}

	// A connection that does not exist is the connection's error.
	d := newDispatch(user, 1)
	d.Connection = "nope"
	if _, err := store.InsertDispatch(ctx, d); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown connection err = %v, want ErrNotFound", err)
	}
}

func TestDispatchStore_CompareAndSetTransitions(t *testing.T) {
	store, ctx := newTrackerTestStore(t)
	const user = "tracker-dispatch-cas"
	seedDispatchConnection(t, store, ctx, user)
	now := time.Date(2027, 1, 1, 12, 0, 0, 0, time.UTC)

	queued := pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_QUEUED
	running := pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_RUNNING
	done := pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_DONE
	failed := pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_FAILED

	row, err := store.InsertDispatch(ctx, newDispatch(user, 1))
	if err != nil {
		t.Fatalf("InsertDispatch: %v", err)
	}
	if row.ID == "" || row.State != queued || row.CreatedAt.IsZero() {
		t.Fatalf("inserted row = %+v, want id, QUEUED, created_at", row)
	}

	// queued -> running.
	ok, err := store.TransitionDispatch(ctx, row.ID, queued, running, "", now)
	if err != nil || !ok {
		t.Fatalf("queued->running = (%v, %v), want (true, nil)", ok, err)
	}
	got, err := store.GetDispatch(ctx, row.ID)
	if err != nil {
		t.Fatalf("GetDispatch: %v", err)
	}
	if got.State != running || !got.StartedAt.Equal(now) {
		t.Fatalf("after queued->running = %+v, want RUNNING started_at=%v", got, now)
	}

	// A stale queued->done is a no-op: the row is already running.
	ok, err = store.TransitionDispatch(ctx, row.ID, queued, done, "", now)
	if err != nil || ok {
		t.Fatalf("stale queued->done = (%v, %v), want (false, nil)", ok, err)
	}
	if got, _ = store.GetDispatch(ctx, row.ID); got.State != running {
		t.Fatalf("stale transition changed state to %v", got.State)
	}

	// running -> done.
	ended := now.Add(time.Minute)
	ok, err = store.TransitionDispatch(ctx, row.ID, running, done, "", ended)
	if err != nil || !ok {
		t.Fatalf("running->done = (%v, %v), want (true, nil)", ok, err)
	}
	if got, _ = store.GetDispatch(ctx, row.ID); got.State != done || !got.EndedAt.Equal(ended) {
		t.Fatalf("after running->done = %+v, want DONE ended_at=%v", got, ended)
	}
	// Terminal: nothing moves it again.
	if ok, _ = store.TransitionDispatch(ctx, row.ID, done, failed, "x", ended); ok {
		t.Fatal("done->failed succeeded, want no-op (terminal)")
	}

	// running -> failed with a reason, on a second row.
	row2, err := store.InsertDispatch(ctx, newDispatch(user, 2))
	if err != nil {
		t.Fatalf("InsertDispatch #2: %v", err)
	}
	if ok, err = store.TransitionDispatch(ctx, row2.ID, queued, running, "", now); err != nil || !ok {
		t.Fatalf("#2 queued->running = (%v, %v)", ok, err)
	}
	if ok, err = store.TransitionDispatch(ctx, row2.ID, running, failed, "box exploded", ended); err != nil || !ok {
		t.Fatalf("#2 running->failed = (%v, %v)", ok, err)
	}
	if got, _ = store.GetDispatch(ctx, row2.ID); got.State != failed || got.FailureReason != "box exploded" || !got.EndedAt.Equal(ended) {
		t.Fatalf("after running->failed = %+v", got)
	}

	// queued -> failed (start-run error path) on a third row.
	row3, err := store.InsertDispatch(ctx, newDispatch(user, 3))
	if err != nil {
		t.Fatalf("InsertDispatch #3: %v", err)
	}
	if ok, err = store.TransitionDispatch(ctx, row3.ID, queued, failed, "no such skill", ended); err != nil || !ok {
		t.Fatalf("#3 queued->failed = (%v, %v)", ok, err)
	}

	// Unknown id: no-op, not an error.
	if ok, err = store.TransitionDispatch(ctx, "00000000-0000-0000-0000-000000000000", queued, running, "", now); err != nil || ok {
		t.Fatalf("unknown id = (%v, %v), want (false, nil)", ok, err)
	}

	// The state filter on List works and rows come newest first.
	failedRows, err := store.ListDispatches(ctx, user, "default", failed)
	if err != nil {
		t.Fatalf("ListDispatches(failed): %v", err)
	}
	if len(failedRows) != 2 || failedRows[0].IssueNumber != 3 || failedRows[1].IssueNumber != 2 {
		t.Fatalf("ListDispatches(failed) = %+v, want issues 3 then 2", failedRows)
	}
}

func TestDispatchStore_RerunAfterTerminal(t *testing.T) {
	store, ctx := newTrackerTestStore(t)
	const user = "tracker-dispatch-rerun"
	seedDispatchConnection(t, store, ctx, user)
	now := time.Now().UTC().Truncate(time.Microsecond)

	first, err := store.InsertDispatch(ctx, newDispatch(user, 5))
	if err != nil {
		t.Fatalf("InsertDispatch: %v", err)
	}
	if _, err := store.InsertDispatch(ctx, newDispatch(user, 5)); !errors.Is(err, ErrDispatchActive) {
		t.Fatalf("second insert while queued err = %v, want ErrDispatchActive", err)
	}
	if _, err := store.TransitionDispatch(ctx, first.ID,
		pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_QUEUED, pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_RUNNING, "", now); err != nil {
		t.Fatalf("queued->running: %v", err)
	}
	if _, err := store.InsertDispatch(ctx, newDispatch(user, 5)); !errors.Is(err, ErrDispatchActive) {
		t.Fatalf("second insert while running err = %v, want ErrDispatchActive", err)
	}
	if _, err := store.TransitionDispatch(ctx, first.ID,
		pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_RUNNING, pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_DONE, "", now); err != nil {
		t.Fatalf("running->done: %v", err)
	}

	// Terminal row: a new generation inserts fine.
	second, err := store.InsertDispatch(ctx, newDispatch(user, 5))
	if err != nil {
		t.Fatalf("insert after done: %v", err)
	}
	if second.ID == first.ID {
		t.Fatal("re-run reused the terminal row's id; want a new row")
	}
	rows, err := store.ListDispatches(ctx, user, "default", pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_UNSPECIFIED)
	if err != nil {
		t.Fatalf("ListDispatches: %v", err)
	}
	if len(rows) != 2 || rows[0].ID != second.ID || rows[1].ID != first.ID {
		t.Fatalf("ListDispatches = %+v, want [second, first]", rows)
	}

	// labels_pending is a flag the tick sets when the forge write fails.
	if err := store.SetDispatchLabelsPending(ctx, second.ID, true); err != nil {
		t.Fatalf("SetDispatchLabelsPending: %v", err)
	}
	if got, _ := store.GetDispatch(ctx, second.ID); !got.LabelsPending {
		t.Fatal("labels_pending not persisted")
	}
	if _, err := store.GetDispatch(ctx, "00000000-0000-0000-0000-000000000000"); !errors.Is(err, ErrDispatchNotFound) {
		t.Fatalf("GetDispatch(unknown) err = %v, want ErrDispatchNotFound", err)
	}
}

func TestDispatchStore_WarningRecordedOnce(t *testing.T) {
	store, ctx := newTrackerTestStore(t)
	const user = "tracker-dispatch-warn"
	seedDispatchConnection(t, store, ctx, user)

	first, err := store.RecordDispatchWarning(ctx, user, "default", 9, "unknown")
	if err != nil || !first {
		t.Fatalf("first RecordDispatchWarning = (%v, %v), want (true, nil)", first, err)
	}
	again, err := store.RecordDispatchWarning(ctx, user, "default", 9, "unknown")
	if err != nil || again {
		t.Fatalf("second RecordDispatchWarning = (%v, %v), want (false, nil)", again, err)
	}
	// A different scope on the same issue is its own warning.
	other, err := store.RecordDispatchWarning(ctx, user, "default", 9, "other")
	if err != nil || !other {
		t.Fatalf("other-scope RecordDispatchWarning = (%v, %v), want (true, nil)", other, err)
	}
	// Forgetting it (the comment failed to post) lets the next tick retry.
	if err := store.ForgetDispatchWarning(ctx, user, "default", 9, "unknown"); err != nil {
		t.Fatalf("ForgetDispatchWarning: %v", err)
	}
	if retry, err := store.RecordDispatchWarning(ctx, user, "default", 9, "unknown"); err != nil || !retry {
		t.Fatalf("after forget RecordDispatchWarning = (%v, %v), want (true, nil)", retry, err)
	}
}

// containsFold is a case-insensitive substring check for error text.
func containsFold(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}

// TestDispatchStore_DeleteQueuedOnly: an abandoned (never started) row
// can be removed while QUEUED; a row that moved on cannot.
func TestDispatchStore_DeleteQueuedOnly(t *testing.T) {
	store, ctx := newTrackerTestStore(t)
	const user = "tracker-dispatch-delete-queued"
	seedDispatchConnection(t, store, ctx, user)

	row, err := store.InsertDispatch(ctx, newDispatch(user, 1))
	if err != nil {
		t.Fatalf("InsertDispatch: %v", err)
	}
	if ok, err := store.DeleteQueuedDispatch(ctx, row.ID); err != nil || !ok {
		t.Fatalf("DeleteQueuedDispatch(queued) = (%v, %v), want (true, nil)", ok, err)
	}
	if _, err := store.GetDispatch(ctx, row.ID); !errors.Is(err, ErrDispatchNotFound) {
		t.Fatalf("GetDispatch after delete = %v, want ErrDispatchNotFound", err)
	}

	row, err = store.InsertDispatch(ctx, newDispatch(user, 1))
	if err != nil {
		t.Fatalf("InsertDispatch (after delete): %v", err)
	}
	if ok, err := store.TransitionDispatch(ctx, row.ID, pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_QUEUED,
		pb.TrackerDispatchState_TRACKER_DISPATCH_STATE_RUNNING, "", time.Now()); err != nil || !ok {
		t.Fatalf("mark running = (%v, %v)", ok, err)
	}
	if ok, err := store.DeleteQueuedDispatch(ctx, row.ID); err != nil || ok {
		t.Fatalf("DeleteQueuedDispatch(running) = (%v, %v), want (false, nil)", ok, err)
	}
}
