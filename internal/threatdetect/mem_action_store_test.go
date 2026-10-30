package threatdetect

import (
	"context"
	"errors"
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func sampleAction(container string, at time.Time) *SecurityAction {
	return &SecurityAction{
		FindingID:        7,
		Container:        container,
		TenantID:         "tenant-a",
		Action:           pb.ProcessAction_PROCESS_ACTION_THROTTLE,
		PrevCPUCount:     "2",
		PrevCPUAllowance: "200ms/100ms",
		AppliedAt:        at,
		ExpiresAt:        at.Add(24 * time.Hour),
	}
}

// MemActionStore mirrors the security_actions table and its
// one-open-action-per-container partial unique index.
func TestMemActionStore_OnePerContainer(t *testing.T) {
	ctx := context.Background()
	s := NewMemActionStore()
	t0 := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

	if _, err := s.Open(ctx, "box-a"); !errors.Is(err, ErrNoOpenAction) {
		t.Fatalf("Open on empty store = %v, want ErrNoOpenAction", err)
	}

	a := sampleAction("box-a", t0)
	if err := s.Insert(ctx, a); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if a.ID == 0 {
		t.Fatal("Insert did not assign an id")
	}
	if err := s.Insert(ctx, sampleAction("box-a", t0)); !errors.Is(err, ErrActionOpen) {
		t.Fatalf("second Insert for the same container = %v, want ErrActionOpen", err)
	}
	if err := s.Insert(ctx, sampleAction("box-b", t0)); err != nil {
		t.Fatalf("Insert for another container: %v", err)
	}

	got, err := s.Open(ctx, "box-a")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got.ID != a.ID || got.PrevCPUCount != "2" || got.PrevCPUAllowance != "200ms/100ms" {
		t.Fatalf("Open = %+v, want the inserted row", got)
	}

	if err := s.Release(ctx, a.ID, ReleasedByOperator, t0.Add(time.Hour)); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if _, err := s.Open(ctx, "box-a"); !errors.Is(err, ErrNoOpenAction) {
		t.Fatalf("Open after release = %v, want ErrNoOpenAction", err)
	}
	// Released rows free the slot: a new action may open on the same box.
	if err := s.Insert(ctx, sampleAction("box-a", t0.Add(2*time.Hour))); err != nil {
		t.Fatalf("Insert after release: %v", err)
	}
	if err := s.Release(ctx, 999, ReleasedByOperator, t0); !errors.Is(err, ErrNoOpenAction) {
		t.Fatalf("Release of unknown id = %v, want ErrNoOpenAction", err)
	}
}

// A row inserted with ReleasedAt already set (a failed apply, recorded for
// the audit trail) never occupies the container's open slot.
func TestMemActionStore_FailedRowIsNotOpen(t *testing.T) {
	ctx := context.Background()
	s := NewMemActionStore()
	t0 := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	failed := sampleAction("box-a", t0)
	failed.Error = "incus: boom"
	failed.ReleasedAt = t0
	failed.ReleasedBy = ReleasedByError
	if err := s.Insert(ctx, failed); err != nil {
		t.Fatalf("Insert failed row: %v", err)
	}
	if _, err := s.Open(ctx, "box-a"); !errors.Is(err, ErrNoOpenAction) {
		t.Fatalf("Open after failed row = %v, want ErrNoOpenAction", err)
	}
	if err := s.Insert(ctx, sampleAction("box-a", t0)); err != nil {
		t.Fatalf("Insert after failed row: %v", err)
	}
}

func TestMemActionStore_ListExpired(t *testing.T) {
	ctx := context.Background()
	s := NewMemActionStore()
	t0 := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

	soon := sampleAction("box-soon", t0)
	soon.ExpiresAt = t0.Add(time.Hour)
	later := sampleAction("box-later", t0)
	later.ExpiresAt = t0.Add(48 * time.Hour)
	for _, a := range []*SecurityAction{soon, later} {
		if err := s.Insert(ctx, a); err != nil {
			t.Fatalf("Insert: %v", err)
		}
	}
	got, err := s.ListExpired(ctx, t0.Add(30*time.Minute))
	if err != nil || len(got) != 0 {
		t.Fatalf("ListExpired before any expiry = %v, %v; want none", got, err)
	}
	got, err = s.ListExpired(ctx, t0.Add(time.Hour))
	if err != nil || len(got) != 1 || got[0].Container != "box-soon" {
		t.Fatalf("ListExpired at the first expiry = %v, %v; want box-soon only", got, err)
	}
	if err := s.Release(ctx, soon.ID, ReleasedByTTL, t0.Add(time.Hour)); err != nil {
		t.Fatalf("Release: %v", err)
	}
	got, _ = s.ListExpired(ctx, t0.Add(72*time.Hour))
	if len(got) != 1 || got[0].Container != "box-later" {
		t.Fatalf("ListExpired after releasing box-soon = %v; want box-later only", got)
	}
}

// runActionStoreContract is the behaviour both ActionStore implementations
// (MemActionStore, PGActionStore) must share: the pending lifecycle, the
// expiry and orphan queries, Latest, release and the one-open-per-container
// rule. prefix keeps container names unique when the store is a shared DB.
func runActionStoreContract(t *testing.T, s ActionStore, findingID int64, prefix string) {
	t.Helper()
	ctx := context.Background()
	t0 := time.Now().UTC().Truncate(time.Microsecond)
	mk := func(c string, at time.Time, pending bool) *SecurityAction {
		a := sampleAction(prefix+c, at)
		a.FindingID, a.Pending = findingID, pending
		return a
	}
	ids := func(rows []*SecurityAction) map[int64]bool {
		m := map[int64]bool{}
		for _, r := range rows {
			m[r.ID] = true
		}
		return m
	}

	// Pending lifecycle: inserted pending, visible as open, confirmed once.
	p := mk("pend", t0, true)
	p.InstanceID = "uuid-" + prefix
	if err := s.Insert(ctx, p); err != nil {
		t.Fatalf("Insert pending: %v", err)
	}
	got, err := s.Open(ctx, p.Container)
	if err != nil || got.ID != p.ID || !got.Pending {
		t.Fatalf("Open after pending insert = %+v, %v; want the row with Pending=true", got, err)
	}
	if got.InstanceID != p.InstanceID {
		t.Fatalf("Open instance id = %q, want %q (#2835: the row names the instance it acted on)", got.InstanceID, p.InstanceID)
	}
	if err := s.MarkApplied(ctx, p.ID); err != nil {
		t.Fatalf("MarkApplied: %v", err)
	}
	if got, _ := s.Open(ctx, p.Container); got == nil || got.Pending {
		t.Fatalf("Open after MarkApplied = %+v, want Pending=false", got)
	}
	if err := s.MarkApplied(ctx, p.ID); !errors.Is(err, ErrNoOpenAction) {
		t.Fatalf("MarkApplied twice = %v, want ErrNoOpenAction", err)
	}

	// Fail: released_by=error with the cause; Latest returns it; slot freed.
	f := mk("fail", t0, true)
	if err := s.Insert(ctx, f); err != nil {
		t.Fatal(err)
	}
	if err := s.Fail(ctx, f.ID, "incus: boom", t0.Add(time.Second)); err != nil {
		t.Fatalf("Fail: %v", err)
	}
	last, err := s.Latest(ctx, f.Container)
	if err != nil || last.ID != f.ID || last.ReleasedBy != ReleasedByError || last.Error != "incus: boom" || last.Pending || last.Open() {
		t.Fatalf("Latest after Fail = %+v, %v", last, err)
	}
	if _, err := s.Open(ctx, f.Container); !errors.Is(err, ErrNoOpenAction) {
		t.Fatalf("Open after Fail = %v, want ErrNoOpenAction", err)
	}
	if err := s.Fail(ctx, f.ID, "again", t0); !errors.Is(err, ErrNoOpenAction) {
		t.Fatalf("Fail twice = %v, want ErrNoOpenAction", err)
	}
	if _, err := s.Latest(ctx, prefix+"never-seen"); !errors.Is(err, ErrNoOpenAction) {
		t.Fatalf("Latest for an unknown container = %v, want ErrNoOpenAction", err)
	}

	// Expiry: applied rows past expires_at, never pending ones.
	pastApplied := mk("exp-applied", t0.Add(-48*time.Hour), false)
	pastPending := mk("exp-pending", t0.Add(-48*time.Hour), true)
	for _, a := range []*SecurityAction{pastApplied, pastPending} {
		if err := s.Insert(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	exp, err := s.ListExpired(ctx, t0)
	if err != nil {
		t.Fatal(err)
	}
	if m := ids(exp); !m[pastApplied.ID] || m[pastPending.ID] {
		t.Fatalf("ListExpired = %v, want the applied row and not the pending one", m)
	}

	// Orphans: only pending rows at or before the cutoff.
	young := mk("orph-young", t0, true)
	if err := s.Insert(ctx, young); err != nil {
		t.Fatal(err)
	}
	orph, err := s.ListOrphaned(ctx, t0.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if m := ids(orph); !m[pastPending.ID] || m[young.ID] || m[pastApplied.ID] || m[p.ID] {
		t.Fatalf("ListOrphaned(-1h) = %v, want only the old pending row", m)
	}
	if m := ids(mustOrphans(t, s, t0.Add(time.Minute))); !m[young.ID] {
		t.Fatalf("ListOrphaned(+1m) = %v, want the young pending row too", m)
	}

	// Release closes the row; Open then returns nothing; second release fails.
	if err := s.Release(ctx, p.ID, ReleasedByOperator, t0.Add(time.Minute)); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if _, err := s.Open(ctx, p.Container); !errors.Is(err, ErrNoOpenAction) {
		t.Fatalf("Open after Release = %v, want ErrNoOpenAction", err)
	}
	if err := s.Release(ctx, p.ID, ReleasedByOperator, t0); !errors.Is(err, ErrNoOpenAction) {
		t.Fatalf("Release twice = %v, want ErrNoOpenAction", err)
	}

	// One open action per container, pending or not.
	if err := s.Insert(ctx, mk("exp-pending", t0, true)); !errors.Is(err, ErrActionOpen) {
		t.Fatalf("second open row = %v, want ErrActionOpen", err)
	}
}

func mustOrphans(t *testing.T, s ActionStore, cutoff time.Time) []*SecurityAction {
	t.Helper()
	rows, err := s.ListOrphaned(context.Background(), cutoff)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

// runListByFindingContract is the ListByFinding half of the contract
// (#2766): every row of findingID, on any container, open or released,
// newest first; rows of otherFindingID are not listed; an unknown finding
// lists nothing. Both ids must exist where the store enforces the
// finding_id foreign key (Postgres).
func runListByFindingContract(t *testing.T, s ActionStore, findingID, otherFindingID int64, prefix string) {
	t.Helper()
	ctx := context.Background()
	t0 := time.Now().UTC().Truncate(time.Microsecond)
	mk := func(c string, fid int64) *SecurityAction {
		a := sampleAction(prefix+c, t0)
		a.FindingID = fid
		return a
	}
	open := mk("lbf-open", findingID)
	released := mk("lbf-released", findingID)
	failed := mk("lbf-failed", findingID)
	failed.Error, failed.ReleasedAt, failed.ReleasedBy = "incus: boom", t0, ReleasedByError
	other := mk("lbf-other", otherFindingID)
	for _, a := range []*SecurityAction{open, released, failed, other} {
		if err := s.Insert(ctx, a); err != nil {
			t.Fatalf("Insert %s: %v", a.Container, err)
		}
	}
	if err := s.Release(ctx, released.ID, ReleasedByOperator, t0.Add(time.Minute)); err != nil {
		t.Fatalf("Release: %v", err)
	}

	rows, err := s.ListByFinding(ctx, findingID)
	if err != nil {
		t.Fatalf("ListByFinding: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("ListByFinding = %d rows, want 3 (open, released, failed)", len(rows))
	}
	for i, want := range []*SecurityAction{failed, released, open} { // newest first
		if rows[i].ID != want.ID || rows[i].Container != want.Container {
			t.Errorf("ListByFinding[%d] = %d/%s, want %d/%s", i, rows[i].ID, rows[i].Container, want.ID, want.Container)
		}
	}
	if !rows[2].Open() || rows[1].Open() || rows[1].ReleasedBy != ReleasedByOperator || rows[0].Open() || rows[0].ReleasedBy != ReleasedByError {
		t.Errorf("ListByFinding release state: %+v", rows)
	}
	for _, row := range rows {
		if row.ID == other.ID {
			t.Errorf("ListByFinding lists row %d of finding %d", other.ID, otherFindingID)
		}
	}
	if none, err := s.ListByFinding(ctx, otherFindingID+1000); err != nil || len(none) != 0 {
		t.Fatalf("ListByFinding for an unknown finding = %v, %v; want none", none, err)
	}
}

func TestActionStore_ContractHoldsForMemImpl(t *testing.T) {
	runActionStoreContract(t, NewMemActionStore(), 7, "")
}

func TestMemActionStore_ListByFinding(t *testing.T) {
	runListByFindingContract(t, NewMemActionStore(), 7, 8, "")
}
