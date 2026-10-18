//go:build integration

// Integration coverage for the Postgres security_actions store (#2636): the
// one-open-action-per-container partial unique index, release, and the TTL
// query are database behaviour, so they run against real Postgres in the
// same CONTAINARIUM_TEST_DSN lane as store_integration_test.go.
package threatdetect

import (
	"context"
	"errors"
	"testing"
	"time"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestActionStore_OpenPerContainerIndex(t *testing.T) {
	pool := threatdetectPool(t)
	fs, _, _ := newStores(t, pool)
	ctx := context.Background()
	as, err := NewActionStore(ctx, pool)
	if err != nil {
		t.Fatalf("NewActionStore: %v", err)
	}
	f, err := fs.Insert(ctx, sampleFinding())
	if err != nil {
		t.Fatalf("Insert finding: %v", err)
	}
	t0 := time.Now().UTC().Truncate(time.Microsecond)

	a := sampleAction("c-miner", t0)
	a.FindingID = f.ID
	if err := as.Insert(ctx, a); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if a.ID == 0 {
		t.Fatal("Insert did not assign an id")
	}
	dup := sampleAction("c-miner", t0)
	dup.FindingID = f.ID
	if err := as.Insert(ctx, dup); !errors.Is(err, ErrActionOpen) {
		t.Fatalf("second open row for the same container = %v, want ErrActionOpen (partial unique index)", err)
	}

	got, err := as.Open(ctx, "c-miner")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got.ID != a.ID || got.FindingID != f.ID || got.Action != pb.ProcessAction_PROCESS_ACTION_THROTTLE ||
		got.PrevCPUCount != "2" || got.PrevCPUAllowance != "200ms/100ms" || !got.AppliedAt.Equal(t0) || !got.ExpiresAt.Equal(t0.Add(24*time.Hour)) {
		t.Fatalf("Open = %+v, want the inserted row", got)
	}
	if _, err := as.Open(ctx, "c-other"); !errors.Is(err, ErrNoOpenAction) {
		t.Fatalf("Open for another container = %v, want ErrNoOpenAction", err)
	}

	// The TTL query: nothing before expires_at, the row at/after it.
	if rows, err := as.ListExpired(ctx, t0.Add(time.Hour)); err != nil || len(rows) != 0 {
		t.Fatalf("ListExpired before expiry = %v, %v; want none", rows, err)
	}
	rows, err := as.ListExpired(ctx, t0.Add(24*time.Hour))
	if err != nil || len(rows) != 1 || rows[0].ID != a.ID {
		t.Fatalf("ListExpired at expiry = %v, %v; want the row", rows, err)
	}

	if err := as.Release(ctx, a.ID, ReleasedByOperator, t0.Add(time.Minute)); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if _, err := as.Open(ctx, "c-miner"); !errors.Is(err, ErrNoOpenAction) {
		t.Fatalf("Open after release = %v, want ErrNoOpenAction", err)
	}
	if err := as.Release(ctx, a.ID, ReleasedByOperator, t0); !errors.Is(err, ErrNoOpenAction) {
		t.Fatalf("Release twice = %v, want ErrNoOpenAction", err)
	}
	// Released rows free the slot; a failed row (released_at set on insert)
	// never takes it.
	failed := sampleAction("c-miner", t0)
	failed.FindingID, failed.Error, failed.ReleasedAt, failed.ReleasedBy = f.ID, "incus: boom", t0, ReleasedByError
	if err := as.Insert(ctx, failed); err != nil {
		t.Fatalf("Insert failed row: %v", err)
	}
	again := sampleAction("c-miner", t0.Add(time.Hour))
	again.FindingID = f.ID
	if err := as.Insert(ctx, again); err != nil {
		t.Fatalf("Insert after release + failed row: %v", err)
	}
	if rows, _ := as.ListExpired(ctx, t0.Add(72*time.Hour)); len(rows) != 1 || rows[0].ID != again.ID {
		t.Fatalf("ListExpired lists released/failed rows: %v", rows)
	}
}

// SetResponse persists the response JSONB and Get/List/Upsert read it back —
// the responder's dedupe and the operator's `findings list` both depend on
// the column surviving a round trip.
func TestFindingStore_SetResponseRoundTrip(t *testing.T) {
	pool := threatdetectPool(t)
	fs, _, bus := newStores(t, pool)
	ctx := context.Background()
	f, err := fs.Upsert(ctx, sampleFinding())
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if f.Response != nil {
		t.Fatalf("fresh finding has a response: %+v", f.Response)
	}
	t0 := time.Now().UTC().Truncate(time.Microsecond)
	sub := bus.Subscribe(&pb.SubscribeEventsRequest{
		ResourceTypes: []pb.ResourceType{pb.ResourceType_RESOURCE_TYPE_SECURITY_FINDING},
	})
	defer bus.Unsubscribe(sub.ID)
	updated, err := fs.SetResponse(ctx, f.ID, FindingResponse{
		Action: pb.ProcessAction_PROCESS_ACTION_THROTTLE, State: pb.ResponseState_RESPONSE_STATE_APPLIED,
		AppliedAt: t0, ExpiresAt: t0.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("SetResponse: %v", err)
	}
	if updated.Response == nil || updated.Response.State != pb.ResponseState_RESPONSE_STATE_APPLIED {
		t.Fatalf("SetResponse returned %+v", updated.Response)
	}
	select {
	case ev := <-sub.Events:
		if got := ev.GetSecurityFindingEvent().GetFinding().GetResponse(); got.GetState() != pb.ResponseState_RESPONSE_STATE_APPLIED {
			t.Fatalf("emitted finding response = %v, want APPLIED", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SetResponse emitted no SECURITY_FINDING event")
	}
	got, err := fs.Get(ctx, f.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Response == nil || got.Response.Action != pb.ProcessAction_PROCESS_ACTION_THROTTLE || !got.Response.AppliedAt.Equal(t0) || !got.Response.ExpiresAt.Equal(t0.Add(time.Hour)) {
		t.Fatalf("Get after SetResponse = %+v", got.Response)
	}
	// A re-fire (update path) carries the stored response back so the
	// responder's dedupe sees it.
	again, err := fs.Upsert(ctx, sampleFinding())
	if err != nil {
		t.Fatalf("Upsert again: %v", err)
	}
	if again.ID != f.ID || again.Response == nil || again.Response.State != pb.ResponseState_RESPONSE_STATE_APPLIED {
		t.Fatalf("Upsert update path = id %d response %+v, want id %d with the stored response", again.ID, again.Response, f.ID)
	}
	if _, err := fs.SetResponse(ctx, 999999, FindingResponse{}); !errors.Is(err, ErrFindingNotFound) {
		t.Fatalf("SetResponse on a missing id = %v, want ErrFindingNotFound", err)
	}
}
