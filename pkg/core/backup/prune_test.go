package backup

import (
	"os"
	"strings"
	"testing"
	"time"
)

// steppedClock returns a clock that advances by step on every call, so a
// sequence of Create calls gets distinct, ordered, deterministic
// timestamps — needed because Prune's whole job is ordering by CreatedAt.
func steppedClock(start time.Time, step time.Duration) func() time.Time {
	t := start
	return func() time.Time {
		cur := t
		t = t.Add(step)
		return cur
	}
}

// createN makes n plaintext local backups for (username, database) in
// order, oldest first, using m's current clock. Returns the created
// records in the SAME (oldest-first) order, for readable test assertions.
func createN(t *testing.T, m *Manager, username, database string, n int) []*Record {
	t.Helper()
	var out []*Record
	for i := 0; i < n; i++ {
		r, err := m.Create(CreateOptions{
			Username: username, ContainerName: username + "-container",
			Conn: PgConn{Database: database}, Destination: DestLocal,
		})
		if err != nil {
			t.Fatalf("Create #%d: %v", i, err)
		}
		out = append(out, r)
	}
	return out
}

func idsOf(recs []*Record) []string {
	ids := make([]string, len(recs))
	for i, r := range recs {
		ids[i] = r.ID
	}
	return ids
}

func contains(ids []string, id string) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}

func TestPrune_KeepsNewestNPerDatabase(t *testing.T) {
	m := newTestManager(t, newFakeOps([]byte("x")))
	m.clock = steppedClock(fixedClock(), time.Second)
	recs := createN(t, m, "alice", "app", 5) // oldest..newest

	res, err := m.Prune(PruneOptions{Username: "alice", Database: "app", Keep: 2})
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if len(res.Failures) != 0 {
		t.Fatalf("unexpected failures: %v", res.Failures)
	}
	wantDeleted := idsOf(recs[:3]) // the 3 oldest
	if len(res.Deleted) != 3 {
		t.Fatalf("deleted %v, want 3 ids (the oldest)", res.Deleted)
	}
	for _, id := range wantDeleted {
		if !contains(res.Deleted, id) {
			t.Errorf("expected %s (an older record) to be deleted, deleted=%v", id, res.Deleted)
		}
	}
	remaining, err := m.List("alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 2 {
		t.Fatalf("List after prune = %d records, want 2", len(remaining))
	}
	for _, r := range remaining {
		if r.ID == recs[0].ID || r.ID == recs[1].ID || r.ID == recs[2].ID {
			t.Errorf("record %s should have been pruned but is still listed", r.ID)
		}
	}
	// The deleted records' bytes are actually gone, not just unlisted.
	for _, r := range recs[:3] {
		if _, err := os.Stat(r.Location); !os.IsNotExist(err) {
			t.Errorf("expected %s to be removed from disk, stat err = %v", r.Location, err)
		}
	}
}

func TestPrune_EmptyDatabasePrunesEachDatabaseIndependently(t *testing.T) {
	m := newTestManager(t, newFakeOps([]byte("x")))
	m.clock = steppedClock(fixedClock(), time.Second)
	appRecs := createN(t, m, "alice", "app", 3)
	billingRecs := createN(t, m, "alice", "billing", 2)

	res, err := m.Prune(PruneOptions{Username: "alice", Keep: 1}) // Database omitted = every database
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if len(res.Deleted) != 3 { // 2 from app + 1 from billing
		t.Fatalf("deleted %v, want 3 total (2 app + 1 billing)", res.Deleted)
	}
	remaining, err := m.List("alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 2 {
		t.Fatalf("List after prune = %d, want 2 (newest of each database)", len(remaining))
	}
	if remaining[0].ID != appRecs[len(appRecs)-1].ID && remaining[1].ID != appRecs[len(appRecs)-1].ID {
		t.Error("the newest app record should have survived")
	}
	if remaining[0].ID != billingRecs[len(billingRecs)-1].ID && remaining[1].ID != billingRecs[len(billingRecs)-1].ID {
		t.Error("the newest billing record should have survived")
	}
}

func TestPrune_DatabaseFilterLeavesOtherDatabasesAlone(t *testing.T) {
	m := newTestManager(t, newFakeOps([]byte("x")))
	m.clock = steppedClock(fixedClock(), time.Second)
	createN(t, m, "alice", "app", 3)
	createN(t, m, "alice", "billing", 2)

	res, err := m.Prune(PruneOptions{Username: "alice", Database: "app", Keep: 1})
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if len(res.Deleted) != 2 {
		t.Fatalf("deleted %v, want 2 (only from app)", res.Deleted)
	}
	remaining, err := m.List("alice")
	if err != nil {
		t.Fatal(err)
	}
	billingCount := 0
	for _, r := range remaining {
		if r.Database == "billing" {
			billingCount++
		}
	}
	if billingCount != 2 {
		t.Errorf("billing database should be untouched by a database=\"app\" prune, got %d billing records", billingCount)
	}
}

func TestPrune_NeverTouchesAnotherTenant(t *testing.T) {
	m := newTestManager(t, newFakeOps([]byte("x")))
	m.clock = steppedClock(fixedClock(), time.Second)
	createN(t, m, "alice", "app", 3)
	bobRecs := createN(t, m, "bob", "app", 3)

	if _, err := m.Prune(PruneOptions{Username: "alice", Keep: 1}); err != nil {
		t.Fatalf("Prune: %v", err)
	}
	remainingBob, err := m.List("bob")
	if err != nil {
		t.Fatal(err)
	}
	if len(remainingBob) != 3 {
		t.Fatalf("bob's records changed by an alice-scoped prune: got %d, want 3", len(remainingBob))
	}
	// List returns newest-first; bobRecs was created oldest-first — compare
	// as sets, not by index, so this only checks identity, not ordering.
	remainingIDs := idsOf(remainingBob)
	for _, r := range bobRecs {
		if !contains(remainingIDs, r.ID) {
			t.Errorf("bob record %s was removed by an alice-scoped prune", r.ID)
		}
	}
}

func TestPrune_RejectsKeepLessThanOne(t *testing.T) {
	m := newTestManager(t, newFakeOps([]byte("x")))
	m.clock = steppedClock(fixedClock(), time.Second)
	recs := createN(t, m, "alice", "app", 2)

	for _, keep := range []int{0, -1} {
		_, err := m.Prune(PruneOptions{Username: "alice", Keep: keep})
		if err == nil || !strings.Contains(err.Error(), "keep must be at least 1") {
			t.Errorf("Prune(keep=%d) = %v, want a clear 'keep must be at least 1' error", keep, err)
		}
	}
	remaining, err := m.List("alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != len(recs) {
		t.Errorf("a rejected prune request must not touch any record; got %d records, want %d", len(remaining), len(recs))
	}
}

func TestPrune_FewerThanKeepIsANoop(t *testing.T) {
	m := newTestManager(t, newFakeOps([]byte("x")))
	m.clock = steppedClock(fixedClock(), time.Second)
	createN(t, m, "alice", "app", 2)

	res, err := m.Prune(PruneOptions{Username: "alice", Database: "app", Keep: 5})
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if len(res.Deleted) != 0 {
		t.Errorf("nothing should be pruned when there are fewer records than keep, got %v", res.Deleted)
	}
	remaining, err := m.List("alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 2 {
		t.Errorf("record count changed by a no-op prune: got %d, want 2", len(remaining))
	}
}

func TestPrune_RequiresUsername(t *testing.T) {
	m := newTestManager(t, newFakeOps([]byte("x")))
	if _, err := m.Prune(PruneOptions{Keep: 1}); err == nil {
		t.Error("expected an error for a missing username")
	}
}

// failOnceUploader fails Delete for exactly one destURI (the "poisoned"
// one), succeeding for every other — used to prove one bad delete doesn't
// abort pruning the rest (#1839, mirrors CreateAll's #954 partial-failure
// posture).
type failOnceUploader struct {
	fakeUploader
	poison string
}

func (f *failOnceUploader) Delete(destURI string) error {
	if destURI == f.poison {
		return errBoom
	}
	return f.fakeUploader.Delete(destURI)
}

var errBoom = &opErr{s: "boom: transient object-store error"}

func TestPrune_OneDeleteFailureDoesNotAbortTheRest(t *testing.T) {
	up := &failOnceUploader{}
	m := NewManager(newFakeOps([]byte("x")), up, t.TempDir())
	m.clock = steppedClock(fixedClock(), time.Second)

	var recs []*Record
	for i := 0; i < 3; i++ {
		r, err := m.Create(CreateOptions{
			Username: "alice", ContainerName: "alice-container",
			Conn: PgConn{Database: "app"}, Destination: DestGCS, GCSBucket: "gs://bucket",
		})
		if err != nil {
			t.Fatalf("Create #%d: %v", i, err)
		}
		recs = append(recs, r)
	}
	// Poison the middle-oldest record's object so its delete fails; the
	// oldest should still be deleted despite that failure.
	up.poison = recs[0].Location

	res, err := m.Prune(PruneOptions{Username: "alice", Database: "app", Keep: 1})
	if err != nil {
		t.Fatalf("Prune itself should not error on a per-record failure: %v", err)
	}
	if len(res.Failures) != 1 {
		t.Fatalf("Failures = %v, want exactly 1 (the poisoned record)", res.Failures)
	}
	if !strings.Contains(res.Failures[0], recs[0].ID) {
		t.Errorf("failure message should name the failing record %s: %v", recs[0].ID, res.Failures[0])
	}
	if len(res.Deleted) != 1 || res.Deleted[0] != recs[1].ID {
		t.Errorf("Deleted = %v, want exactly [%s] (the other older record, despite recs[0] failing)", res.Deleted, recs[1].ID)
	}
	remaining, err := m.List("alice")
	if err != nil {
		t.Fatal(err)
	}
	// recs[0] (failed delete) and recs[2] (kept, newest) should remain listed.
	if len(remaining) != 2 {
		t.Fatalf("List after partial-failure prune = %d, want 2 (the failed-to-delete one, plus the kept newest)", len(remaining))
	}
}
