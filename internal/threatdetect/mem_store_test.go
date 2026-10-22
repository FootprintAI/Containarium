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
	"time"

	"github.com/footprintai/containarium/internal/audit"
	"github.com/footprintai/containarium/internal/events"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// Keep the received pointers so the test can detect later changes to them.
type recordingFindingNotifier struct {
	findings []*Finding
}

func (n *recordingFindingNotifier) Notify(f *Finding) {
	n.findings = append(n.findings, f)
}

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

// #2748: the finding Upsert returns, and the one it hands the notifier, are
// read after the store's lock is released. A later Upsert of the same key
// must not change them.
func TestMemFindingStore_UpsertReturnsSnapshot(t *testing.T) {
	auditStore, bus := memTestDeps(t)
	s, err := NewMemFindingStore(events.NewEmitter(bus), auditStore)
	if err != nil {
		t.Fatalf("NewMemFindingStore: %v", err)
	}

	n := &recordingFindingNotifier{}
	s.SetNotifier(n)

	ctx := context.Background()
	first, err := s.Upsert(ctx, sampleMemFinding())
	if err != nil {
		t.Fatalf("Upsert #1: %v", err)
	}
	if _, err := s.Upsert(ctx, sampleMemFinding()); err != nil {
		t.Fatalf("Upsert #2: %v", err)
	}

	if first.Count != 1 {
		t.Fatalf("first returned finding has count %d, want 1", first.Count)
	}
	if got := len(n.findings); got != 2 {
		t.Fatalf("notifications = %d, want 2", got)
	}
	if delivered := n.findings[0]; delivered.Count != 1 {
		t.Fatalf("first notification has count %d after the second upsert, want 1", delivered.Count)
	}
}

// A deduped repeat can raise an open finding's severity but never lower it:
// the sshd posture reconciler records MEDIUM when it undid tampering and
// HIGH if the box is later still permissive (#2424).
func TestMemFindingStore_UpsertEscalatesSeverityNeverLowers(t *testing.T) {
	auditStore, bus := memTestDeps(t)
	s, err := NewMemFindingStore(events.NewEmitter(bus), auditStore)
	if err != nil {
		t.Fatalf("NewMemFindingStore: %v", err)
	}
	ctx := context.Background()
	at := func(sev pb.ThreatSeverity) *Finding {
		f := sampleMemFinding()
		f.Severity = sev
		return f
	}
	for _, step := range []struct {
		in, want pb.ThreatSeverity
	}{
		{pb.ThreatSeverity_THREAT_SEVERITY_MEDIUM, pb.ThreatSeverity_THREAT_SEVERITY_MEDIUM},
		{pb.ThreatSeverity_THREAT_SEVERITY_HIGH, pb.ThreatSeverity_THREAT_SEVERITY_HIGH},
		{pb.ThreatSeverity_THREAT_SEVERITY_MEDIUM, pb.ThreatSeverity_THREAT_SEVERITY_HIGH},
	} {
		got, err := s.Upsert(ctx, at(step.in))
		if err != nil {
			t.Fatalf("Upsert(%v): %v", step.in, err)
		}
		if got.Severity != step.want {
			t.Fatalf("after Upsert(%v) severity = %v, want %v", step.in, got.Severity, step.want)
		}
	}
}

// #2643, through the store and the real WebhookNotifier gate: a persistent
// condition upserted many times is delivered once, and its resolution once.
func TestMemFindingStore_PersistentFindingNotifiesOnceThenOnResolve(t *testing.T) {
	auditStore, bus := memTestDeps(t)
	s, err := NewMemFindingStore(events.NewEmitter(bus), auditStore)
	if err != nil {
		t.Fatalf("NewMemFindingStore: %v", err)
	}
	n := NewWebhookNotifier(newFakeConfigSource("http://127.0.0.1:1", ""), nil) // no worker: queue length = deliveries
	s.SetNotifier(n)

	ctx := context.Background()
	var id int64
	for i := 0; i < 10; i++ {
		f, uerr := s.Upsert(ctx, sampleMemFinding())
		if uerr != nil {
			t.Fatalf("Upsert #%d: %v", i+1, uerr)
		}
		id = f.ID
	}
	if got := len(n.queue); got != 1 {
		t.Fatalf("deliveries after 10 upserts = %d, want 1", got)
	}
	if _, err := s.Resolve(ctx, id); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := len(n.queue); got != 2 {
		t.Fatalf("deliveries after resolve = %d, want 2 (open, then resolved)", got)
	}
	<-n.queue
	if resolved := <-n.queue; resolved.State != FindingStateResolved {
		t.Errorf("second delivery state = %q, want resolved", resolved.State)
	}
}

// SetResponse keeps process_killed once set (#2766), like the Postgres
// store: a later response that carries process_killed=false (a release on
// a box that killed nothing) cannot drop a recorded kill.
func TestMemFindingStore_SetResponseKeepsProcessKilled(t *testing.T) {
	auditStore, bus := memTestDeps(t)
	s, err := NewMemFindingStore(events.NewEmitter(bus), auditStore)
	if err != nil {
		t.Fatalf("NewMemFindingStore: %v", err)
	}
	ctx := context.Background()
	f, err := s.Upsert(ctx, sampleMemFinding())
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	t0 := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	got, err := s.SetResponse(ctx, f.ID, FindingResponse{Action: pb.ProcessAction_PROCESS_ACTION_ALERT, State: pb.ResponseState_RESPONSE_STATE_NONE, AppliedAt: t0})
	if err != nil {
		t.Fatalf("SetResponse: %v", err)
	}
	if got.Response.ProcessKilled {
		t.Fatalf("first response = %+v, want process_killed=false", got.Response)
	}
	if _, err := s.SetResponse(ctx, f.ID, FindingResponse{Action: pb.ProcessAction_PROCESS_ACTION_ALERT, State: pb.ResponseState_RESPONSE_STATE_NONE, AppliedAt: t0, ProcessKilled: true}); err != nil {
		t.Fatalf("SetResponse with kill: %v", err)
	}
	got, err = s.SetResponse(ctx, f.ID, FindingResponse{
		Action: pb.ProcessAction_PROCESS_ACTION_THROTTLE, State: pb.ResponseState_RESPONSE_STATE_RELEASED,
		AppliedAt: t0, ReleasedAt: t0.Add(time.Minute), ReleasedBy: ReleasedByOperator,
	})
	if err != nil {
		t.Fatalf("SetResponse release: %v", err)
	}
	if got.Response.State != pb.ResponseState_RESPONSE_STATE_RELEASED || !got.Response.ProcessKilled {
		t.Fatalf("release response = %+v, want RELEASED with process_killed kept", got.Response)
	}
	back, err := s.Get(ctx, f.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !back.Response.ProcessKilled {
		t.Fatalf("stored response = %+v, want process_killed kept", back.Response)
	}
}

// A failed audit must preserve another upsert's count, evidence and severity.
func TestMemFindingStore_AuditRollbackKeepsConcurrentUpdate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool := threatdetectPool(t)
	auditStore, err := audit.NewStore(ctx, pool)
	if err != nil {
		t.Fatalf("audit.NewStore: %v", err)
	}

	s, err := NewMemFindingStore(events.NewEmitter(events.NewBus()), auditStore)
	if err != nil {
		t.Fatalf("NewMemFindingStore: %v", err)
	}

	first, err := s.Upsert(ctx, sampleMemFinding())
	if err != nil {
		t.Fatalf("initial Upsert: %v", err)
	}

	// Pause audit writes while both in-memory updates are applied.
	lockTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin audit lock: %v", err)
	}
	t.Cleanup(func() {
		_ = lockTx.Rollback(context.Background())
	})
	if _, err := lockTx.Exec(ctx, "LOCK TABLE audit_logs IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatalf("lock audit table: %v", err)
	}

	waitForCount := func(want int64) {
		t.Helper()
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()

		for {
			got, err := s.Get(ctx, first.ID)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if got.Count == want {
				return
			}
			select {
			case <-ctx.Done():
				t.Fatalf("waiting for count %d: %v", want, ctx.Err())
			case <-ticker.C:
			}
		}
	}

	ctxA, cancelA := context.WithCancel(ctx)
	defer cancelA()
	aDone := make(chan error, 1)
	go func() {
		_, err := s.Upsert(ctxA, sampleMemFinding())
		aDone <- err
	}()
	waitForCount(2)

	b := sampleMemFinding()
	b.Severity = pb.ThreatSeverity_THREAT_SEVERITY_HIGH
	b.Evidence.Denies[0].Reason = "successful-update"

	bDone := make(chan error, 1)
	go func() {
		_, err := s.Upsert(ctx, b)
		bDone <- err
	}()
	waitForCount(3)

	// Fail A only after B's update has been merged.
	cancelA()
	select {
	case err := <-aDone:
		if err == nil {
			t.Fatal("A succeeded, want an audit failure")
		}
	case <-ctx.Done():
		t.Fatalf("waiting for A: %v", ctx.Err())
	}

	// Release the table so B can finish its audit.
	if err := lockTx.Rollback(ctx); err != nil {
		t.Fatalf("release audit lock: %v", err)
	}
	select {
	case err := <-bDone:
		if err != nil {
			t.Fatalf("B failed: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("waiting for B: %v", ctx.Err())
	}

	got, err := s.Get(ctx, first.ID)
	if err != nil {
		t.Fatalf("Get after rollback: %v", err)
	}
	if got.Count != 2 {
		t.Errorf("count = %d, want 2", got.Count)
	}
	if got.Severity != pb.ThreatSeverity_THREAT_SEVERITY_HIGH {
		t.Errorf("severity = %v, want HIGH", got.Severity)
	}

	found := false
	for _, evidence := range got.Evidence.Denies {
		if evidence.Reason == "successful-update" {
			found = true
			break
		}
	}
	if !found {
		t.Error("B's evidence was lost during A's rollback")
	}
}

// Findings already handed out must stay stable while the store is updated.
func TestMemFindingStore_ConcurrentHandoutSnapshots(t *testing.T) {
	for _, name := range []string{"Get", "List", "SetResponse", "Resolve"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			auditStore, bus := memTestDeps(t)
			s, err := NewMemFindingStore(events.NewEmitter(bus), auditStore)
			if err != nil {
				t.Fatalf("NewMemFindingStore: %v", err)
			}

			n := &recordingFindingNotifier{}
			s.SetNotifier(n)

			applied := FindingResponse{
				Action: pb.ProcessAction_PROCESS_ACTION_THROTTLE,
				State:  pb.ResponseState_RESPONSE_STATE_APPLIED,
			}
			input := sampleMemFinding()
			input.Response = &applied
			first, err := s.Upsert(ctx, input)
			if err != nil {
				t.Fatalf("initial Upsert: %v", err)
			}

			var snapshot *Finding
			wantState := pb.FindingState_FINDING_STATE_OPEN
			switch name {
			case "Get":
				snapshot, err = s.Get(ctx, first.ID)
			case "List":
				rows, listErr := s.List(ctx, ListFilter{})
				if listErr != nil {
					t.Fatalf("List: %v", listErr)
				}
				if len(rows) != 1 {
					t.Fatalf("List returned %d findings, want 1", len(rows))
				}
				snapshot = rows[0]
			case "SetResponse":
				snapshot, err = s.SetResponse(ctx, first.ID, applied)
			case "Resolve":
				snapshot, err = s.Resolve(ctx, first.ID)
				wantState = pb.FindingState_FINDING_STATE_RESOLVED
			}
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}

			// Capture these before the updater starts appending notifications.
			snapshots := []*Finding{
				snapshot,
				n.findings[len(n.findings)-1],
			}

			expired := applied
			expired.State = pb.ResponseState_RESPONSE_STATE_EXPIRED
			done := make(chan error, 1)
			go func() {
				for i := 0; i < 16; i++ {
					if _, err := s.Upsert(ctx, sampleMemFinding()); err != nil {
						done <- err
						return
					}
					// Responses can still change on the original resolved finding.
					if _, err := s.SetResponse(ctx, first.ID, expired); err != nil {
						done <- err
						return
					}
				}
				done <- nil
			}()

			ticker := time.NewTicker(time.Millisecond)
			defer ticker.Stop()
			for running := true; running; {
				select {
				case err := <-done:
					if err != nil {
						t.Fatalf("concurrent update: %v", err)
					}
					running = false
				case <-ctx.Done():
					t.Fatalf("waiting for updates: %v", ctx.Err())
				case <-ticker.C:
				}

				for _, finding := range snapshots {
					got := finding.ToProto()
					if got.GetCount() != 1 ||
						got.GetState() != wantState ||
						got.GetResponse().GetState() != pb.ResponseState_RESPONSE_STATE_APPLIED ||
						len(got.GetEvidence().GetDenies()) != 1 {
						t.Fatalf("snapshot changed: %v", got)
					}
				}
			}
		})
	}
}
