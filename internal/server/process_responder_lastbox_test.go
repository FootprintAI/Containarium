package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lxc/incus/v7/shared/api"

	"github.com/footprintai/containarium/internal/threatdetect"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// goneActuator is fakeActuator for boxes that may no longer exist: an undo on
// a box in gone fails the way Incus does for a deleted instance (404).
type goneActuator struct {
	*fakeActuator
	mu   sync.Mutex
	gone map[string]bool
}

func (a *goneActuator) isGone(name string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.gone[name]
}

func (a *goneActuator) SetCPULimit(name, count, allowance string) error {
	if a.isGone(name) {
		return api.StatusErrorf(http.StatusNotFound, "Instance not found")
	}
	return a.fakeActuator.SetCPULimit(name, count, allowance)
}

func (a *goneActuator) Unfreeze(name string) error {
	if a.isGone(name) {
		return api.StatusErrorf(http.StatusNotFound, "Instance not found")
	}
	return a.fakeActuator.Unfreeze(name)
}

// twoThrottled: box-a and box-b of one tenant share a miner-signature
// finding, both throttled with a 1 h TTL, box-b 30 min after box-a. Returns
// the finding id.
func twoThrottled(t *testing.T) (*responderFixture, int64) {
	t.Helper()
	ctx := context.Background()
	fx, sink := queuedThrottle(t)
	fx.r.runJob(ctx, queueFor(t, fx, sink, "box-a"))
	fx.clock = fx.clock.Add(30 * time.Minute)
	job := queueFor(t, fx, sink, "box-b")
	fx.r.runJob(ctx, job)
	for _, box := range []string{"box-a", "box-b"} {
		if _, err := openAction(fx, box); err != nil {
			t.Fatalf("%s not throttled: %v", box, err)
		}
	}
	return fx, job.f.ID
}

// pendingOn records an action row on box that was never confirmed: the daemon
// died between the insert and MarkApplied.
func pendingOn(t *testing.T, fx *responderFixture, id int64, box string) *threatdetect.SecurityAction {
	t.Helper()
	row := &threatdetect.SecurityAction{FindingID: id, Container: box, TenantID: "tenant-a", Pending: true,
		Action: pb.ProcessAction_PROCESS_ACTION_THROTTLE, PrevCPUCount: "2", AppliedAt: fx.clock, ExpiresAt: fx.clock.Add(time.Hour)}
	if err := fx.actions.Insert(context.Background(), row); err != nil {
		t.Fatal(err)
	}
	return row
}

func releaseKeptOpen(t *testing.T, fx *responderFixture, box string) {
	t.Helper()
	f, kept, err := fx.r.Release(context.Background(), box)
	if err != nil {
		t.Fatal(err)
	}
	if !kept || f == nil || f.State != threatdetect.FindingStateOpen {
		t.Fatalf("Release(%s) = kept_open=%t, finding %+v; want kept open", box, kept, f)
	}
}

// lastResolve is the response the finding was last resolved with.
func lastResolve(t *testing.T, fx *responderFixture) threatdetect.FindingResponse {
	t.Helper()
	fx.findings.mu.Lock()
	defer fx.findings.mu.Unlock()
	if len(fx.findings.resolvedWith) == 0 {
		t.Fatal("the finding was never resolved with a response")
	}
	return fx.findings.resolvedWith[len(fx.findings.resolvedWith)-1]
}

func latestRow(t *testing.T, fx *responderFixture, box string) *threatdetect.SecurityAction {
	t.Helper()
	row, err := fx.actions.Latest(context.Background(), box)
	if err != nil {
		t.Fatal(err)
	}
	return row
}

// TestSharedFinding_LastBoxEndingResolves (#2835 item 1): an operator released
// box-a, and the shared finding stayed open only because box-b still held it.
// Whichever way box-b's action then ends — its TTL, the orphan sweep, the box
// being deleted, or a sweep finding the box already gone — the finding is
// resolved in the same write that records box-b's end, as the release of the
// last box would have resolved it. Nothing is left holding it open forever.
func TestSharedFinding_LastBoxEndingResolves(t *testing.T) {
	ctx := context.Background()
	t.Run("box-b's TTL expires", func(t *testing.T) {
		fx, id := twoThrottled(t)
		releaseKeptOpen(t, fx, "box-a")
		fx.clock = fx.clock.Add(61 * time.Minute) // past box-b's TTL
		if n := fx.r.SweepExpired(ctx, fx.clock); n != 1 {
			t.Fatalf("SweepExpired released %d, want 1 (box-b)", n)
		}
		if f := mustGet(t, fx, id); f.State != threatdetect.FindingStateResolved {
			t.Fatalf("finding after box-b's expiry = %s, want resolved", f.State)
		}
		if r := lastResolve(t, fx); r.State != pb.ResponseState_RESPONSE_STATE_EXPIRED || r.Container != "box-b" || r.ReleasedBy != threatdetect.ReleasedByTTL {
			t.Errorf("resolved with %+v, want box-b's EXPIRED by ttl", r)
		}
		if d := auditDetails(fx.audit, "resolve"); len(d) != 1 || !strings.Contains(d[0], "container=box-b") {
			t.Errorf("resolve audit = %v, want one naming box-b", d)
		}
	})
	t.Run("box-b's never-confirmed row is reaped by the orphan sweep", func(t *testing.T) {
		fx, sink := queuedThrottle(t)
		job := queueFor(t, fx, sink, "box-a")
		fx.r.runJob(ctx, job)
		pendingOn(t, fx, job.f.ID, "box-b")
		releaseKeptOpen(t, fx, "box-a")
		if n := fx.r.SweepExpired(ctx, fx.clock.Add(threatdetect.PendingOrphanAfter+time.Second)); n != 1 {
			t.Fatalf("SweepExpired released %d, want 1 (box-b's orphan)", n)
		}
		if f := mustGet(t, fx, job.f.ID); f.State != threatdetect.FindingStateResolved {
			t.Fatalf("finding after the orphan sweep = %s, want resolved", f.State)
		}
		if r := lastResolve(t, fx); r.State != pb.ResponseState_RESPONSE_STATE_RELEASED || r.Container != "box-b" || r.ReleasedBy != threatdetect.ReleasedByOrphanSweep {
			t.Errorf("resolved with %+v, want box-b's RELEASED by orphan-sweep", r)
		}
	})
	t.Run("box-b is deleted", func(t *testing.T) {
		fx, id := twoThrottled(t)
		releaseKeptOpen(t, fx, "box-a")
		calls := len(fx.act.calls)
		fx.r.ContainerDeleted(ctx, "box-b")
		if got := fx.act.calls[calls:]; len(got) != 0 {
			t.Errorf("Incus calls for a deleted box = %v, want none", got)
		}
		if row := latestRow(t, fx, "box-b"); row.Open() || row.ReleasedBy != threatdetect.ReleasedByContainerDeleted {
			t.Errorf("box-b's row = %+v, want closed by %s", row, threatdetect.ReleasedByContainerDeleted)
		}
		f := mustGet(t, fx, id)
		if f.State != threatdetect.FindingStateResolved {
			t.Fatalf("finding after box-b's deletion = %s, want resolved", f.State)
		}
		if r := f.Response; r.State != pb.ResponseState_RESPONSE_STATE_RELEASED || r.Container != "box-b" || r.ReleasedBy != threatdetect.ReleasedByContainerDeleted {
			t.Errorf("finding's response = %+v, want box-b's RELEASED by %s, not its APPLIED", *r, threatdetect.ReleasedByContainerDeleted)
		}
	})
	t.Run("the TTL sweep finds box-b already gone", func(t *testing.T) {
		fx, id := twoThrottled(t)
		gone := &goneActuator{fakeActuator: fx.act, gone: map[string]bool{"box-b": true}}
		fx.r.act = gone
		releaseKeptOpen(t, fx, "box-a")
		fx.clock = fx.clock.Add(61 * time.Minute)
		if n := fx.r.SweepExpired(ctx, fx.clock); n != 1 {
			t.Fatalf("SweepExpired released %d, want 1: a deleted box has nothing to restore", n)
		}
		if row := latestRow(t, fx, "box-b"); row.Open() || row.ReleasedBy != threatdetect.ReleasedByContainerDeleted {
			t.Errorf("box-b's row = %+v, want closed by %s", row, threatdetect.ReleasedByContainerDeleted)
		}
		if f := mustGet(t, fx, id); f.State != threatdetect.FindingStateResolved {
			t.Fatalf("finding = %s, want resolved", f.State)
		}
		if n := fx.r.SweepExpired(ctx, fx.clock.Add(time.Minute)); n != 0 {
			t.Errorf("the next sweep released %d, want 0: nothing is retried", n)
		}
		if expired := fx.findings.byRule(pb.ThreatRuleId_THREAT_RULE_ID_PROCESS_ACTION_EXPIRED); len(expired) != 0 {
			t.Errorf("PROCESS_ACTION_EXPIRED findings = %d, want none: nothing was restored on a deleted box", len(expired))
		}
	})
	t.Run("the orphan sweep finds box-b already gone", func(t *testing.T) {
		fx, sink := queuedThrottle(t)
		job := queueFor(t, fx, sink, "box-a")
		fx.r.runJob(ctx, job)
		pendingOn(t, fx, job.f.ID, "box-b")
		fx.r.act = &goneActuator{fakeActuator: fx.act, gone: map[string]bool{"box-b": true}}
		releaseKeptOpen(t, fx, "box-a")
		if n := fx.r.SweepExpired(ctx, fx.clock.Add(threatdetect.PendingOrphanAfter+time.Second)); n != 1 {
			t.Fatalf("SweepExpired released %d, want 1", n)
		}
		if row := latestRow(t, fx, "box-b"); row.Open() || row.ReleasedBy != threatdetect.ReleasedByContainerDeleted {
			t.Errorf("box-b's row = %+v, want closed by %s", row, threatdetect.ReleasedByContainerDeleted)
		}
		if f := mustGet(t, fx, job.f.ID); f.State != threatdetect.FindingStateResolved {
			t.Fatalf("finding = %s, want resolved", f.State)
		}
	})
}

// TestBoxEndingWithoutOperatorDecisionKeepsFindingOpen: the rule above only
// finishes an operator's release. With no operator release on any box, a
// box's TTL expiry or deletion leaves the finding open for the operator, as a
// single box's expiry always has, and it no longer shows the ended box's
// APPLIED record.
func TestBoxEndingWithoutOperatorDecisionKeepsFindingOpen(t *testing.T) {
	ctx := context.Background()
	t.Run("box-b deleted while box-a holds", func(t *testing.T) {
		fx, id := twoThrottled(t)
		fx.r.ContainerDeleted(ctx, "box-b")
		f := mustGet(t, fx, id)
		if f.State != threatdetect.FindingStateOpen {
			t.Fatalf("finding = %s, want open: box-a still holds it", f.State)
		}
		assertStanding(t, fx, id, "box-a", "box-b", pb.ResponseState_RESPONSE_STATE_RELEASED)
	})
	t.Run("then box-a expires: nobody decided", func(t *testing.T) {
		fx, id := twoThrottled(t)
		fx.r.ContainerDeleted(ctx, "box-b")
		fx.clock = fx.clock.Add(31 * time.Minute) // past box-a's TTL
		if n := fx.r.SweepExpired(ctx, fx.clock); n != 1 {
			t.Fatalf("SweepExpired released %d, want 1", n)
		}
		f := mustGet(t, fx, id)
		if f.State != threatdetect.FindingStateOpen {
			t.Fatalf("finding = %s, want open: no operator decided", f.State)
		}
		if r := f.Response; r.State != pb.ResponseState_RESPONSE_STATE_EXPIRED || r.Container != "box-a" {
			t.Errorf("finding's response = %+v, want box-a's EXPIRED", *r)
		}
	})
	t.Run("the only box is deleted", func(t *testing.T) {
		fx := newResponderFixture(t, false)
		fx.setDefault(t, pb.ProcessAction_PROCESS_ACTION_FREEZE, "", time.Hour)
		f := fx.fire(t, "box-a", ruleMiningBehavior, pb.ThreatSeverity_THREAT_SEVERITY_HIGH)
		fx.r.ContainerDeleted(ctx, "box-a")
		got := mustGet(t, fx, f.ID)
		if got.State != threatdetect.FindingStateOpen {
			t.Errorf("finding = %s, want open", got.State)
		}
		if r := got.Response; r.State != pb.ResponseState_RESPONSE_STATE_RELEASED || r.ReleasedBy != threatdetect.ReleasedByContainerDeleted || r.Container != "box-a" {
			t.Errorf("finding's response = %+v, want RELEASED by %s on box-a", *r, threatdetect.ReleasedByContainerDeleted)
		}
		if d := auditDetails(fx.audit, "release"); len(d) != 1 || !strings.Contains(d[0], "released_by="+threatdetect.ReleasedByContainerDeleted) {
			t.Errorf("release audit = %v, want one by %s", d, threatdetect.ReleasedByContainerDeleted)
		}
	})
	t.Run("a box with no action: nothing happens", func(t *testing.T) {
		fx := newResponderFixture(t, false)
		fx.r.ContainerDeleted(ctx, "box-a")
		if got := fx.audit.actions(); len(got) != 0 {
			t.Errorf("audit = %v, want nothing", got)
		}
	})
}

// TestSharedFinding_PendingRowOnAnotherBox (#2835 item 3): a crashed apply on
// box-b left a row that was never confirmed. It is an action that may stand
// (the throttle may or may not have taken effect), so it keeps the shared
// finding open like an applied action does, but it is never shown as
// APPLIED: nothing confirmed it. The orphan sweep bounds it, at
// PendingOrphanAfter plus one sweep interval (see
// TestSharedFinding_LastBoxEndingResolves).
func TestSharedFinding_PendingRowOnAnotherBox(t *testing.T) {
	ctx := context.Background()
	t.Run("box-a's release", func(t *testing.T) {
		fx, sink := queuedThrottle(t)
		job := queueFor(t, fx, sink, "box-a")
		fx.r.runJob(ctx, job)
		pendingOn(t, fx, job.f.ID, "box-b")
		releaseKeptOpen(t, fx, "box-a")
		if r := mustGet(t, fx, job.f.ID).Response; r.State == pb.ResponseState_RESPONSE_STATE_APPLIED || r.Container != "box-a" {
			t.Errorf("finding's response = %+v, want box-a's own RELEASED, not box-b's unconfirmed row as APPLIED", *r)
		}
	})
	t.Run("box-a's TTL expiry", func(t *testing.T) {
		fx, sink := queuedThrottle(t)
		job := queueFor(t, fx, sink, "box-a")
		fx.r.runJob(ctx, job)
		fx.clock = fx.clock.Add(59 * time.Minute)
		pendingOn(t, fx, job.f.ID, "box-b")
		fx.clock = fx.clock.Add(2 * time.Minute) // past box-a's TTL, box-b's row not yet an orphan
		if n := fx.r.SweepExpired(ctx, fx.clock); n != 1 {
			t.Fatalf("SweepExpired released %d, want 1 (box-a)", n)
		}
		if r := mustGet(t, fx, job.f.ID).Response; r.State != pb.ResponseState_RESPONSE_STATE_EXPIRED || r.Container != "box-a" {
			t.Errorf("finding's response = %+v, want box-a's EXPIRED, not box-b's unconfirmed row as APPLIED", *r)
		}
	})
}

// A failed apply on box-b next to box-a's never-confirmed row records
// box-b's FAILED (writeBox), not box-a's row as APPLIED.
func TestSharedFinding_FailureNextToPendingRow(t *testing.T) {
	fx, sink := queuedThrottle(t)
	job := queueFor(t, fx, sink, "box-b")
	pendingOn(t, fx, job.f.ID, "box-a")
	fx.act.mu.Lock()
	fx.act.fail = errors.New("incus: boom")
	fx.act.mu.Unlock()
	fx.r.runJob(context.Background(), job)
	if r := mustGet(t, fx, job.f.ID).Response; r.State != pb.ResponseState_RESPONSE_STATE_FAILED || r.Container != "box-b" {
		t.Errorf("finding's response = %+v, want box-b's FAILED, not box-a's unconfirmed row as APPLIED", *r)
	}
}

// TestRecordKill_OldRecordIsNotRelabelled (#2835 item 4): a response stored by
// a daemon from before per-box records carries no container. Box-a was
// released on such a daemon while box-b stayed throttled, so the finding
// reads RELEASED with no box. Box-b's next kill must not relabel that as
// "RELEASED on box-b" while box-b is throttled: the record becomes box-b's
// APPLIED, the action that actually stands.
func TestRecordKill_OldRecordIsNotRelabelled(t *testing.T) {
	ctx := context.Background()
	fx := newResponderFixture(t, false)
	fx.setDefault(t, pb.ProcessAction_PROCESS_ACTION_THROTTLE, "10%", time.Hour)
	fx.setKill(t, "", true)
	fx.r.SetProcessKiller(&fakeKiller{})
	f := fx.fireSignature(t, "box-a", 100)
	fx.fireSignature(t, "box-b", 200)
	rowA, err := openAction(fx, "box-a")
	if err != nil {
		t.Fatal(err)
	}
	// What the old daemon left: box-a's row released by the operator and the
	// finding's response its RELEASED record, with no container.
	if err := fx.actions.Release(ctx, rowA.ID, threatdetect.ReleasedByOperator, fx.clock); err != nil {
		t.Fatal(err)
	}
	fx.findings.mu.Lock()
	fx.findings.rows[f.ID].Response = &threatdetect.FindingResponse{Action: pb.ProcessAction_PROCESS_ACTION_THROTTLE,
		State: pb.ResponseState_RESPONSE_STATE_RELEASED, ReleasedAt: fx.clock, ReleasedBy: threatdetect.ReleasedByOperator,
		ProcessKilled: true, KilledPID: 200, Kills: 2}
	fx.findings.mu.Unlock()

	fx.fireSignature(t, "box-b", 300)
	r := mustGet(t, fx, f.ID).Response
	if r.State != pb.ResponseState_RESPONSE_STATE_APPLIED || r.Container != "box-b" || r.Action != pb.ProcessAction_PROCESS_ACTION_THROTTLE {
		t.Errorf("finding's response after box-b's kill = %+v, want box-b's THROTTLE APPLIED, not the old RELEASED relabelled", *r)
	}
	if !r.ProcessKilled || r.KilledPID != 300 || r.Kills != 3 {
		t.Errorf("kill facts = killed %t pid %d kills %d, want true 300 3", r.ProcessKilled, r.KilledPID, r.Kills)
	}
}

// TestRecordKill_OldRecordWithNoActionKeepsTheWritersBox: with no action
// standing anywhere, an old container-less record is labelled with the box
// whose write this is, as before.
func TestRecordKill_OldRecordWithNoActionKeepsTheWritersBox(t *testing.T) {
	fx := newResponderFixture(t, false)
	fx.setKill(t, "", true)
	fx.r.SetProcessKiller(&fakeKiller{})
	f := fx.fireSignature(t, "box-a", 100)
	fx.findings.mu.Lock()
	fx.findings.rows[f.ID].Response = &threatdetect.FindingResponse{Action: pb.ProcessAction_PROCESS_ACTION_ALERT,
		State: pb.ResponseState_RESPONSE_STATE_NONE, ProcessKilled: true, KilledPID: 100, Kills: 1}
	fx.findings.mu.Unlock()
	fx.fireSignature(t, "box-a", 101)
	if r := mustGet(t, fx, f.ID).Response; r.State != pb.ResponseState_RESPONSE_STATE_NONE || r.Container != "box-a" || r.Kills != 2 {
		t.Errorf("finding's response = %+v, want ALERT NONE on box-a with 2 kills", *r)
	}
}

// TestSharedFinding_LastBoxEndingWaitsForOtherHolders: an ending box resolves
// the finding only when it was the last thing holding it. Another box's
// never-confirmed apply or its queued response still holds it, as in Release
// and settle.
func TestSharedFinding_LastBoxEndingWaitsForOtherHolders(t *testing.T) {
	ctx := context.Background()
	t.Run("a never-confirmed apply on box-c", func(t *testing.T) {
		fx, id := twoThrottled(t)
		pendingOn(t, fx, id, "box-c")
		releaseKeptOpen(t, fx, "box-a")
		fx.r.ContainerDeleted(ctx, "box-b")
		if f := mustGet(t, fx, id); f.State != threatdetect.FindingStateOpen {
			t.Fatalf("finding = %s, want open: box-c's apply may stand", f.State)
		}
		if n := fx.r.SweepExpired(ctx, fx.clock.Add(threatdetect.PendingOrphanAfter+time.Second)); n != 1 {
			t.Fatalf("SweepExpired released %d, want 1 (box-c's orphan)", n)
		}
		if f := mustGet(t, fx, id); f.State != threatdetect.FindingStateResolved {
			t.Fatalf("finding after box-c's orphan = %s, want resolved", f.State)
		}
	})
	t.Run("a queued response for box-c", func(t *testing.T) {
		fx, sink := queuedThrottle(t)
		fx.r.runJob(ctx, queueFor(t, fx, sink, "box-a"))
		jobB := queueFor(t, fx, sink, "box-b")
		fx.r.runJob(ctx, jobB)
		releaseKeptOpen(t, fx, "box-a")
		jobC := queueFor(t, fx, sink, "box-c")
		fx.r.ContainerDeleted(ctx, "box-b")
		if f := mustGet(t, fx, jobB.f.ID); f.State != threatdetect.FindingStateOpen {
			t.Fatalf("finding = %s, want open: box-c's response is still queued", f.State)
		}
		fx.r.runJob(ctx, jobC)
		if _, err := openAction(fx, "box-c"); err != nil {
			t.Fatalf("box-c's queued response did not run: %v", err)
		}
	})
}
