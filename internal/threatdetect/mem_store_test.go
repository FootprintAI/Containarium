//go:build integration

// MemFindingStore is the degraded-mode (no Postgres for FINDINGS) sink, but
// it deliberately reuses the same *audit.Store dependency FindingStore does
// (design doc: "events and audit entries still flow" in degraded mode) —
// audit.Store has no interface in this repo, only a concrete Postgres-backed
// type. So proving MemFindingStore's audit interaction needs a real
// Postgres for the AUDIT chain even though the findings themselves never
// touch it — same CONTAINARIUM_TEST_DSN lane as store_integration_test.go.
package threatdetect

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/events"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func memTestDeps(t *testing.T) (*audit.Store, *events.Bus) {
	t.Helper()
	pool := threatdetectPool(t) // requires CONTAINARIUM_TEST_DSN; see store_integration_test.go
	ctx := context.Background()
	auditStore, err := audit.NewStore(ctx, pool)
	if err != nil {
		t.Fatalf("audit.NewStore: %v", err)
	}
	return auditStore, events.NewBus()
}

func sampleMemFinding() *Finding {
	return &Finding{
		Rule:      pb.ThreatRuleId_THREAT_RULE_ID_DENY_BURST,
		Severity:  pb.ThreatSeverity_THREAT_SEVERITY_MEDIUM,
		TenantID:  "tenant-a",
		Container: "c-probe",
		BackendID: "backend-1",
		Subject:   "",
		Evidence: Evidence{
			Denies: []DenyEvidence{{DstIP: "10.0.0.9", Reason: "policy", Count: 1}},
		},
	}
}

// The #1640 acceptance test, degraded-mode variant: a rule firing repeatedly
// for the same tenant+rule dedupes into one open finding with an updated
// count — proven here without Postgres, since this is exactly the path that
// exists so detection still dedupes when Postgres is down.
func TestMemFindingStore_UpsertDedupesOpenFinding(t *testing.T) {
	auditStore, bus := memTestDeps(t)
	s, err := NewMemFindingStore(events.NewEmitter(bus), auditStore)
	if err != nil {
		t.Fatalf("NewMemFindingStore: %v", err)
	}
	sub := bus.Subscribe(&pb.SubscribeEventsRequest{ResourceTypes: []pb.ResourceType{pb.ResourceType_RESOURCE_TYPE_SECURITY_FINDING}})
	defer bus.Unsubscribe(sub.ID)

	ctx := context.Background()
	first, err := s.Upsert(ctx, sampleMemFinding())
	if err != nil {
		t.Fatalf("Upsert #1: %v", err)
	}
	if first.Count != 1 {
		t.Fatalf("first upsert count = %d, want 1", first.Count)
	}
	drainEvent(t, sub)

	second, err := s.Upsert(ctx, sampleMemFinding())
	if err != nil {
		t.Fatalf("Upsert #2 (repeat): %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("repeat upsert got a new id %d, want %d (dedupe by rule/tenant/subject)", second.ID, first.ID)
	}
	if second.Count != 2 {
		t.Fatalf("repeat upsert count = %d, want 2", second.Count)
	}
	if len(second.Evidence.Denies) != 2 {
		t.Fatalf("repeat upsert evidence denies = %d, want 2 (merged, not replaced)", len(second.Evidence.Denies))
	}
	drainEvent(t, sub)

	if got := len(s.byKey); got != 1 {
		t.Fatalf("distinct open findings tracked = %d, want 1", got)
	}
}

// A finding for a DIFFERENT subject must not collide with an existing open
// finding's dedupe key.
func TestMemFindingStore_DistinctSubjectsDoNotCollide(t *testing.T) {
	auditStore, bus := memTestDeps(t)
	s, err := NewMemFindingStore(events.NewEmitter(bus), auditStore)
	if err != nil {
		t.Fatalf("NewMemFindingStore: %v", err)
	}
	ctx := context.Background()

	a := sampleMemFinding()
	a.Subject = "peer-tenant-x"
	b := sampleMemFinding()
	b.Subject = "peer-tenant-y"

	fa, err := s.Upsert(ctx, a)
	if err != nil {
		t.Fatalf("Upsert a: %v", err)
	}
	fb, err := s.Upsert(ctx, b)
	if err != nil {
		t.Fatalf("Upsert b: %v", err)
	}
	if fa.ID == fb.ID {
		t.Fatalf("distinct subjects collapsed into one finding: %d == %d", fa.ID, fb.ID)
	}
}

// If the audit write fails, a NEW finding must not be left visible — same
// invariant FindingStore.Upsert gives (#1639's "no orphan finding" guarantee,
// carried into degraded mode).
func TestMemFindingStore_AuditFailureOnNewFindingLeavesNoOrphan(t *testing.T) {
	pool := threatdetectPool(t)
	ctx := context.Background()
	auditStore, err := audit.NewStore(ctx, pool)
	if err != nil {
		t.Fatalf("audit.NewStore: %v", err)
	}
	pool.Close() // every subsequent audit.Store.Log call now fails

	bus := events.NewBus()
	sub := bus.Subscribe(&pb.SubscribeEventsRequest{ResourceTypes: []pb.ResourceType{pb.ResourceType_RESOURCE_TYPE_SECURITY_FINDING}})
	defer bus.Unsubscribe(sub.ID)

	s, err := NewMemFindingStore(events.NewEmitter(bus), auditStore)
	if err != nil {
		t.Fatalf("NewMemFindingStore: %v", err)
	}

	if _, err := s.Upsert(ctx, sampleMemFinding()); err == nil {
		t.Fatal("Upsert succeeded despite a broken audit store; want an error")
	}
	if len(s.byKey) != 0 {
		t.Fatalf("byKey has %d entries after a failed audit write, want 0 (no orphan finding)", len(s.byKey))
	}
	select {
	case ev := <-sub.Events:
		t.Fatalf("event bus published a finding despite the audit write failing: %+v", ev)
	default:
	}
}

func TestMemFindingStore_RingIsBounded(t *testing.T) {
	auditStore, bus := memTestDeps(t)
	s, err := NewMemFindingStore(events.NewEmitter(bus), auditStore)
	if err != nil {
		t.Fatalf("NewMemFindingStore: %v", err)
	}
	ctx := context.Background()

	for i := 0; i < memFindingRingCap+10; i++ {
		f := sampleMemFinding()
		f.Subject = fmt.Sprintf("subj-%d", i) // distinct subjects
		if _, err := s.Upsert(ctx, f); err != nil {
			t.Fatalf("Upsert #%d: %v", i, err)
		}
	}
	if len(s.ring) != memFindingRingCap {
		t.Fatalf("ring len = %d, want %d (bounded)", len(s.ring), memFindingRingCap)
	}
}

func TestMemFindingStore_ConcurrentUpsertsConvergeToOneRow(t *testing.T) {
	auditStore, bus := memTestDeps(t)
	s, err := NewMemFindingStore(events.NewEmitter(bus), auditStore)
	if err != nil {
		t.Fatalf("NewMemFindingStore: %v", err)
	}
	ctx := context.Background()

	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := s.Upsert(ctx, sampleMemFinding())
			errs[i] = err
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("Upsert goroutine %d: %v", i, err)
		}
	}
	if len(s.byKey) != 1 {
		t.Fatalf("distinct open findings after %d concurrent upserts = %d, want 1", n, len(s.byKey))
	}
	for _, f := range s.byKey {
		if f.Count != n {
			t.Fatalf("count after %d concurrent upserts = %d, want %d", n, f.Count, n)
		}
	}
}
