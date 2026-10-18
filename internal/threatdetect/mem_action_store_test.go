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
