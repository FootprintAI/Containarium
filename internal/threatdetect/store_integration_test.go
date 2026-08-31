//go:build integration

// Integration coverage for FindingStore (#1639): a finding that doesn't
// really land in the audit hash chain, or doesn't survive a daemon restart,
// is a finding an operator can't trust — the sentry's entire point is being
// the thing nothing else already is. That's why this exercises real
// Postgres, a real events.Bus, and the real audit chain rather than mocks.
//
//	CONTAINARIUM_TEST_DSN=postgres://... go test -tags=integration ./internal/threatdetect/
package threatdetect

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/events"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func threatdetectPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("CONTAINARIUM_TEST_DSN")
	if dsn == "" {
		t.Fatal("CONTAINARIUM_TEST_DSN is unset. Failing rather than skipping, so a lane that " +
			"loses its database reports it instead of going quietly green.")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	// Only reset security_findings: it's this package's own table. audit_logs
	// belongs to internal/audit, whose own integration tests run concurrently
	// against this same database in CI (`go test ./pkgA/ ./pkgB/ ...` runs
	// package binaries in parallel) — dropping it here raced their schema
	// setup and produced spurious "relation does not exist" / duplicate
	// pg_type failures. audit.NewStore's initSchema is idempotent and safe
	// to call against a table this package doesn't own.
	if _, err := pool.Exec(context.Background(), `DROP TABLE IF EXISTS security_findings`); err != nil {
		t.Fatalf("reset (security_findings): %v", err)
	}
	return pool
}

func newStores(t *testing.T, pool *pgxpool.Pool) (*FindingStore, *audit.Store, *events.Bus) {
	t.Helper()
	ctx := context.Background()

	auditStore, err := audit.NewStore(ctx, pool)
	if err != nil {
		t.Fatalf("audit.NewStore: %v", err)
	}

	bus := events.NewBus()
	emitter := events.NewEmitter(bus)

	fs, err := NewFindingStore(ctx, pool, emitter, auditStore)
	if err != nil {
		t.Fatalf("NewFindingStore: %v", err)
	}
	return fs, auditStore, bus
}

func sampleFinding() *Finding {
	return &Finding{
		Rule:      pb.ThreatRuleId_THREAT_RULE_ID_BAD_DESTINATION,
		Severity:  pb.ThreatSeverity_THREAT_SEVERITY_HIGH,
		TenantID:  "tenant-a",
		Container: "c-miner",
		BackendID: "backend-1",
		Subject:   "203.0.113.9",
		Evidence: Evidence{
			Flows: []FlowEvidence{
				{SrcIP: "10.0.0.5", DstIP: "203.0.113.9", SrcPort: 51234, DstPort: 443, Protocol: "tcp", Bytes: 4096, Packets: 12},
			},
		},
	}
}

// The #1639 acceptance test: every finding lands in the audit log inside the
// existing hash chain, and VerifyChainSinceID still passes over a window
// containing findings.
func TestFindingStore_InsertRidesTheAuditChain(t *testing.T) {
	ctx := context.Background()
	pool := threatdetectPool(t)
	fs, auditStore, _ := newStores(t, pool)

	beforeID, err := auditStore.MaxRowID(ctx)
	if err != nil {
		t.Fatalf("MaxRowID: %v", err)
	}

	for i := 0; i < 3; i++ {
		f := sampleFinding()
		// Distinct subjects: the open-finding unique index is scoped to
		// (rule, tenant_id, subject), so identical subjects would collide.
		f.Subject = fmt.Sprintf("203.0.113.%d", 9+i)
		if _, err := fs.Insert(ctx, f); err != nil {
			t.Fatalf("Insert #%d: %v", i, err)
		}
	}

	firstBad, err := auditStore.VerifyChainSinceID(ctx, beforeID, 1000)
	if err != nil {
		t.Fatalf("VerifyChainSinceID: %v", err)
	}
	if firstBad != 0 {
		t.Fatalf("VerifyChainSinceID reported a broken chain at row %d over a window containing findings", firstBad)
	}

	// Filtered to rows this test actually wrote (id > beforeID): audit_logs is
	// shared with internal/audit's own tests (see threatdetectPool), and a
	// bare resource_type filter would also pick up rows a previous run left
	// behind, or (were this ever run with t.Parallel) a concurrent test's
	// rows — an unrelated leftover row would silently change the count this
	// asserts on.
	rows, _, err := auditStore.Query(ctx, audit.QueryParams{ResourceType: "security.finding", Limit: 1000})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	var ours int
	for _, r := range rows {
		if r.ID > beforeID {
			ours++
		}
	}
	if ours != 3 {
		t.Fatalf("expected 3 audit rows for security.finding with id > %d, got %d (of %d total)", beforeID, ours, len(rows))
	}
}

// A finding must be readable via SubscribeEvents (through the emitter/bus
// wiring) with the fields the #1639 acceptance criteria name: rule id,
// severity, tenant/container ref, backend, and evidence.
func TestFindingStore_InsertEmitsSecurityFindingEvent(t *testing.T) {
	ctx := context.Background()
	pool := threatdetectPool(t)
	fs, _, bus := newStores(t, pool)

	sub := bus.Subscribe(&pb.SubscribeEventsRequest{
		ResourceTypes: []pb.ResourceType{pb.ResourceType_RESOURCE_TYPE_SECURITY_FINDING},
	})
	defer bus.Unsubscribe(sub.ID)

	f := sampleFinding()
	inserted, err := fs.Insert(ctx, f)
	if err != nil {
		t.Fatalf("Insert: %v", err)
	}

	select {
	case ev := <-sub.Events:
		if ev.Type != pb.EventType_EVENT_TYPE_SECURITY_FINDING {
			t.Fatalf("event type = %v, want EVENT_TYPE_SECURITY_FINDING", ev.Type)
		}
		payload := ev.GetSecurityFindingEvent()
		if payload == nil {
			t.Fatalf("event has no SecurityFindingEvent payload: %+v", ev)
		}
		got := payload.Finding
		if got.Id != inserted.ID {
			t.Errorf("finding id = %d, want %d", got.Id, inserted.ID)
		}
		if got.Rule != pb.ThreatRuleId_THREAT_RULE_ID_BAD_DESTINATION {
			t.Errorf("rule = %v, want THREAT_RULE_ID_BAD_DESTINATION", got.Rule)
		}
		if got.Severity != pb.ThreatSeverity_THREAT_SEVERITY_HIGH {
			t.Errorf("severity = %v, want THREAT_SEVERITY_HIGH", got.Severity)
		}
		if got.TenantId != "tenant-a" {
			t.Errorf("tenant_id = %q, want tenant-a", got.TenantId)
		}
		if got.Container != "c-miner" {
			t.Errorf("container = %q, want c-miner", got.Container)
		}
		if got.BackendId != "backend-1" {
			t.Errorf("backend_id = %q, want backend-1", got.BackendId)
		}
		if got.Evidence == nil || len(got.Evidence.Flows) != 1 {
			t.Fatalf("evidence flows = %+v, want 1 flow", got.Evidence)
		}
		if got.Evidence.Flows[0].DstIp != "203.0.113.9" {
			t.Errorf("evidence dst_ip = %q, want 203.0.113.9", got.Evidence.Flows[0].DstIp)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for EVENT_TYPE_SECURITY_FINDING on the bus")
	}
}

// The #1639 acceptance test: findings persist across daemon restart. A
// restart is simulated by dropping every in-process reference and opening a
// fresh pool + store against the same database.
func TestFindingStore_PersistsAcrossRestart(t *testing.T) {
	ctx := context.Background()
	pool := threatdetectPool(t)
	fs, _, _ := newStores(t, pool)

	inserted, err := fs.Insert(ctx, sampleFinding())
	if err != nil {
		t.Fatalf("Insert: %v", err)
	}

	// Simulate a daemon restart: a brand new pool and store, no shared
	// in-memory state with the one above.
	restartPool, err := pgxpool.New(ctx, os.Getenv("CONTAINARIUM_TEST_DSN"))
	if err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	defer restartPool.Close()

	restartAudit, err := audit.NewStore(ctx, restartPool)
	if err != nil {
		t.Fatalf("audit.NewStore after restart: %v", err)
	}
	restartFS, err := NewFindingStore(ctx, restartPool, events.NewEmitter(events.NewBus()), restartAudit)
	if err != nil {
		t.Fatalf("NewFindingStore after restart: %v", err)
	}

	got, err := restartFS.Get(ctx, inserted.ID)
	if err != nil {
		t.Fatalf("Get after restart: %v", err)
	}
	if got.TenantID != "tenant-a" || got.Subject != "203.0.113.9" {
		t.Fatalf("finding after restart = %+v, want tenant-a/203.0.113.9", got)
	}
	if got.State != FindingStateOpen {
		t.Fatalf("state after restart = %q, want open", got.State)
	}
}

func TestFindingStore_EvidenceIsCapped(t *testing.T) {
	ctx := context.Background()
	pool := threatdetectPool(t)
	fs, _, _ := newStores(t, pool)

	f := sampleFinding()
	f.Evidence.Flows = nil
	for i := 0; i < EvidenceCap+5; i++ {
		f.Evidence.Flows = append(f.Evidence.Flows, FlowEvidence{DstIP: "203.0.113.9", DstPort: uint32(i)})
	}

	inserted, err := fs.Insert(ctx, f)
	if err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if len(inserted.Evidence.Flows) != EvidenceCap {
		t.Fatalf("stored flow evidence count = %d, want %d", len(inserted.Evidence.Flows), EvidenceCap)
	}

	got, err := fs.Get(ctx, inserted.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got.Evidence.Flows) != EvidenceCap {
		t.Fatalf("persisted flow evidence count = %d, want %d", len(got.Evidence.Flows), EvidenceCap)
	}
}

// If the audit write fails, the finding must not be left visible: not
// readable back, and not published on the event bus. A finding whose row
// exists but was never audited — or that reached subscribers but never made
// the chain — is exactly the "log line nobody watches" gap #1639 exists to
// close.
func TestFindingStore_AuditFailureLeavesNoOrphanFinding(t *testing.T) {
	ctx := context.Background()
	dsn := os.Getenv("CONTAINARIUM_TEST_DSN")
	pool := threatdetectPool(t) // resets security_findings; owns the "good" side

	// A second, independent pool backs the audit store. Its schema is set up
	// successfully, then the pool is closed — so audit.Store.Log fails on
	// every call from here on, while FindingStore's own pool (above) stays
	// open and can prove what did or didn't end up visible.
	auditPool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect (audit pool): %v", err)
	}
	auditStore, err := audit.NewStore(ctx, auditPool)
	if err != nil {
		t.Fatalf("audit.NewStore: %v", err)
	}
	auditPool.Close()

	bus := events.NewBus()
	sub := bus.Subscribe(&pb.SubscribeEventsRequest{
		ResourceTypes: []pb.ResourceType{pb.ResourceType_RESOURCE_TYPE_SECURITY_FINDING},
	})
	defer bus.Unsubscribe(sub.ID)

	fs, err := NewFindingStore(ctx, pool, events.NewEmitter(bus), auditStore)
	if err != nil {
		t.Fatalf("NewFindingStore: %v", err)
	}

	_, err = fs.Insert(ctx, sampleFinding())
	if err == nil {
		t.Fatal("Insert succeeded despite a broken audit store; want an error")
	}

	var count int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM security_findings`).Scan(&count); err != nil {
		t.Fatalf("count security_findings: %v", err)
	}
	if count != 0 {
		t.Fatalf("security_findings has %d rows after a failed audit write, want 0 (no orphan finding)", count)
	}

	select {
	case ev := <-sub.Events:
		t.Fatalf("event bus published a finding despite the audit write failing: %+v", ev)
	case <-time.After(200 * time.Millisecond):
		// Expected: no event.
	}
}
