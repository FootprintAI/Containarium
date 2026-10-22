package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lxc/incus/v7/shared/api"

	"github.com/footprintai/containarium/internal/threatdetect"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// deleteBox is what the Incus delete hook does for box: it tells the
// responder the box (with its current instance id) is gone, then waits for
// the responder's background close, so a test reads the result.
func deleteBox(fx *responderFixture, box string) {
	id, _ := fx.act.InstanceID(box)
	fx.act.mu.Lock()
	fx.act.missing[box] = true
	fx.act.mu.Unlock()
	fx.r.ContainerDeleted(context.Background(), box, id)
	fx.r.waitBackground()
}

// reThrottle fires box again after its earlier action ended, so it is
// throttled again, and returns its new open row.
func reThrottle(t *testing.T, fx *responderFixture, box string) *threatdetect.SecurityAction {
	t.Helper()
	sink := NewAsyncActingSink(fx.findings, fx.r)
	fx.r.runJob(context.Background(), queueFor(t, fx, sink, box))
	row, err := openAction(fx, box)
	if err != nil {
		t.Fatalf("%s not throttled again: %v", box, err)
	}
	return row
}

// TestEndBox_OnlyAStandingOperatorReleaseResolves (#2835 review, item 1).
// The rule: a box's end without an operator (TTL, orphan sweep, deletion)
// resolves a shared finding only when it was the last thing holding it AND an
// operator's release is still the latest word on some box of the finding:
// that release would have resolved the finding had this box not held it. An
// operator release that a later action on the same box superseded is not a
// decision about the finding any more.
func TestEndBox_OnlyAStandingOperatorReleaseResolves(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		run  func(t *testing.T, fx *responderFixture)
		want threatdetect.FindingState
	}{
		{"release A, delete B: resolved", func(t *testing.T, fx *responderFixture) {
			releaseKeptOpen(t, fx, "box-a")
			deleteBox(fx, "box-b")
		}, threatdetect.FindingStateResolved},
		{"TTL both, nobody released: open", func(t *testing.T, fx *responderFixture) {
			fx.clock = fx.clock.Add(61 * time.Minute)
			if n := fx.r.SweepExpired(ctx, fx.clock); n != 2 {
				t.Fatalf("SweepExpired released %d, want 2", n)
			}
		}, threatdetect.FindingStateOpen},
		{"release A, A re-throttled, B expires, A's second throttle expires: open", func(t *testing.T, fx *responderFixture) {
			releaseKeptOpen(t, fx, "box-a")
			fx.clock = fx.clock.Add(10 * time.Minute)
			reThrottle(t, fx, "box-a") // expires 70 min after B's start
			fx.clock = fx.clock.Add(51 * time.Minute)
			if n := fx.r.SweepExpired(ctx, fx.clock); n != 1 {
				t.Fatalf("SweepExpired released %d, want 1 (box-b)", n)
			}
			fx.clock = fx.clock.Add(10 * time.Minute)
			if n := fx.r.SweepExpired(ctx, fx.clock); n != 1 {
				t.Fatalf("SweepExpired released %d, want 1 (box-a's second throttle)", n)
			}
		}, threatdetect.FindingStateOpen},
		{"release A, A re-throttled, B expires, A deleted: open", func(t *testing.T, fx *responderFixture) {
			releaseKeptOpen(t, fx, "box-a")
			fx.clock = fx.clock.Add(10 * time.Minute)
			reThrottle(t, fx, "box-a")
			fx.clock = fx.clock.Add(51 * time.Minute)
			if n := fx.r.SweepExpired(ctx, fx.clock); n != 1 {
				t.Fatalf("SweepExpired released %d, want 1 (box-b)", n)
			}
			deleteBox(fx, "box-a")
		}, threatdetect.FindingStateOpen},
		{"release A, A re-throttled and released again, B deleted: resolved", func(t *testing.T, fx *responderFixture) {
			releaseKeptOpen(t, fx, "box-a")
			fx.clock = fx.clock.Add(time.Minute)
			reThrottle(t, fx, "box-a")
			releaseKeptOpen(t, fx, "box-a")
			deleteBox(fx, "box-b")
		}, threatdetect.FindingStateResolved},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx, id := twoThrottled(t)
			tc.run(t, fx)
			if f := mustGet(t, fx, id); f.State != tc.want {
				t.Errorf("finding = %s, want %s", f.State, tc.want)
			}
		})
	}
}

// stalledActions is an ActionStore whose Open blocks until its context ends.
type stalledActions struct {
	threatdetect.ActionStore
}

func (stalledActions) Open(ctx context.Context, _ string) (*threatdetect.SecurityAction, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// ctxActions is an ActionStore that, like Postgres, fails every call made
// with a context that has already ended.
type ctxActions struct {
	threatdetect.ActionStore
}

func (s ctxActions) Open(ctx context.Context, c string) (*threatdetect.SecurityAction, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.ActionStore.Open(ctx, c)
}

func (s ctxActions) Release(ctx context.Context, id int64, by string, at time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.ActionStore.Release(ctx, id, by, at)
}

// TestContainerDeleted_NeverHoldsUpTheDelete (#2835 review, item 2): the
// delete path tells the responder and goes on. The close runs in the
// background, detached from the caller's context, bounded by its own
// timeout, and never under a lock the caller waits for.
func TestContainerDeleted_NeverHoldsUpTheDelete(t *testing.T) {
	t.Run("the responder is busy", func(t *testing.T) {
		fx, _ := twoThrottled(t)
		fx.r.mu.Lock() // an Incus call of another response in flight
		start := time.Now()
		fx.r.ContainerDeleted(context.Background(), "box-b", "id-box-b")
		if d := time.Since(start); d > time.Second {
			t.Fatalf("ContainerDeleted waited %s for the responder's lock", d)
		}
		fx.r.mu.Unlock()
		fx.r.waitBackground()
		if row := latestRow(t, fx, "box-b"); row.Open() {
			t.Errorf("box-b's row = %+v, want closed once the responder was free", row)
		}
	})
	t.Run("the request context is already cancelled", func(t *testing.T) {
		fx, _ := twoThrottled(t)
		fx.r.actions = ctxActions{fx.actions}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		fx.r.ContainerDeleted(ctx, "box-b", "id-box-b")
		fx.r.waitBackground()
		if row := latestRow(t, fx, "box-b"); row.Open() || row.ReleasedBy != threatdetect.ReleasedByContainerDeleted {
			t.Errorf("box-b's row = %+v, want closed: a cancelled request must not leave it open", row)
		}
	})
	t.Run("the store stalls", func(t *testing.T) {
		fx, _ := twoThrottled(t)
		fx.r.actions = stalledActions{fx.actions}
		fx.r.deletedCloseTimeout = 50 * time.Millisecond
		start := time.Now()
		fx.r.ContainerDeleted(context.Background(), "box-b", "id-box-b")
		if d := time.Since(start); d > time.Second {
			t.Fatalf("ContainerDeleted waited %s on a stalled store", d)
		}
		fx.r.waitBackground()
		if !fx.r.mu.TryLock() {
			t.Fatal("the responder's lock is still held after the bounded close gave up")
		}
		fx.r.mu.Unlock()
	})
	t.Run("a new box with the same name is left alone", func(t *testing.T) {
		fx, _ := twoThrottled(t)
		fx.r.ContainerDeleted(context.Background(), "box-b", "id-of-an-older-box-b")
		fx.r.waitBackground()
		if _, err := openAction(fx, "box-b"); err != nil {
			t.Errorf("box-b's action was closed by the deletion of another instance with its name: %v", err)
		}
	})
}

// TestNameReuse_SweepNeverWritesAnOldBoxsLimitsOnANewBox (#2835 review, item
// 3): box-a is deleted behind the daemon's back while throttled, and a new
// box-a is created. Whatever then ends the old action (its TTL, the orphan
// sweep, an operator release) must not write the old box's saved limits onto
// the new box: the action row carries the Incus instance id it was applied
// to, and a different instance under the same name is a box that is gone.
func TestNameReuse_SweepNeverWritesAnOldBoxsLimitsOnANewBox(t *testing.T) {
	ctx := context.Background()
	setup := func(t *testing.T) (*responderFixture, *threatdetect.SecurityAction) {
		fx := newResponderFixture(t, false)
		fx.act.count["box-a"], fx.act.allow["box-a"] = "2", "200ms/100ms"
		fx.act.ids["box-a"] = "uuid-old"
		fx.setDefault(t, pb.ProcessAction_PROCESS_ACTION_THROTTLE, "10%", time.Hour)
		fx.fire(t, "box-a", ruleMiningBehavior, pb.ThreatSeverity_THREAT_SEVERITY_HIGH)
		row, err := openAction(fx, "box-a")
		if err != nil {
			t.Fatal(err)
		}
		if row.InstanceID != "uuid-old" {
			t.Fatalf("action row instance id = %q, want uuid-old (recorded at apply)", row.InstanceID)
		}
		// Deleted and re-created out of band: a new instance, its own limits.
		fx.act.ids["box-a"] = "uuid-new"
		fx.act.count["box-a"], fx.act.allow["box-a"] = "4", ""
		return fx, row
	}
	untouched := func(t *testing.T, fx *responderFixture) {
		t.Helper()
		if fx.act.count["box-a"] != "4" || fx.act.allow["box-a"] != "" {
			t.Errorf("new box-a's limits = %q/%q, want 4/\"\" untouched", fx.act.count["box-a"], fx.act.allow["box-a"])
		}
		if row := latestRow(t, fx, "box-a"); row.Open() || row.ReleasedBy != threatdetect.ReleasedByContainerDeleted {
			t.Errorf("old row = %+v, want closed by %s", row, threatdetect.ReleasedByContainerDeleted)
		}
	}
	t.Run("TTL expiry", func(t *testing.T) {
		fx, _ := setup(t)
		if n := fx.r.SweepExpired(ctx, fx.clock.Add(61*time.Minute)); n != 1 {
			t.Fatalf("SweepExpired released %d, want 1", n)
		}
		untouched(t, fx)
	})
	t.Run("operator release", func(t *testing.T) {
		fx, _ := setup(t)
		if _, _, err := fx.r.Release(ctx, "box-a"); !errors.Is(err, threatdetect.ErrNoOpenAction) {
			t.Fatalf("Release = %v, want ErrNoOpenAction: the new box-a has no action", err)
		}
		untouched(t, fx)
	})
	t.Run("orphan sweep", func(t *testing.T) {
		fx := newResponderFixture(t, false)
		fx.act.ids["box-a"] = "uuid-old"
		pending := &threatdetect.SecurityAction{FindingID: 1, Container: "box-a", TenantID: "tenant-a", Pending: true, InstanceID: "uuid-old",
			Action: pb.ProcessAction_PROCESS_ACTION_THROTTLE, PrevCPUCount: "2", PrevCPUAllowance: "200ms/100ms",
			AppliedAt: fx.clock, ExpiresAt: fx.clock.Add(time.Hour)}
		if err := fx.actions.Insert(ctx, pending); err != nil {
			t.Fatal(err)
		}
		fx.act.ids["box-a"] = "uuid-new"
		fx.act.count["box-a"], fx.act.allow["box-a"] = "4", ""
		if n := fx.r.SweepExpired(ctx, fx.clock.Add(threatdetect.PendingOrphanAfter+time.Second)); n != 1 {
			t.Fatalf("SweepExpired released %d, want 1", n)
		}
		untouched(t, fx)
	})
	t.Run("same instance: the undo still runs", func(t *testing.T) {
		fx, _ := setup(t)
		fx.act.ids["box-a"] = "uuid-old"
		if n := fx.r.SweepExpired(ctx, fx.clock.Add(61*time.Minute)); n != 1 {
			t.Fatalf("SweepExpired released %d, want 1", n)
		}
		if fx.act.count["box-a"] != "2" || fx.act.allow["box-a"] != "200ms/100ms" {
			t.Errorf("limits = %q/%q, want the recorded 2/200ms/100ms restored", fx.act.count["box-a"], fx.act.allow["box-a"])
		}
		if row := latestRow(t, fx, "box-a"); row.ReleasedBy != threatdetect.ReleasedByTTL {
			t.Errorf("row = %+v, want released by ttl", row)
		}
	})
}

// notFoundUndo answers 404 to the undo of a box that still exists (an
// operation-wait 404, not a missing instance).
type notFoundUndo struct{ *fakeActuator }

func (notFoundUndo) SetCPULimit(string, string, string) error {
	return api.StatusErrorf(http.StatusNotFound, "operation not found")
}

// TestUndoNotFound_BoxStillThereIsRetried (#2835 review, item 4): a 404 from
// the undo alone does not mean the box is gone. A fresh instance lookup
// decides: the same instance is still there, so the action stays open and the
// next sweep retries.
func TestUndoNotFound_BoxStillThereIsRetried(t *testing.T) {
	fx := newResponderFixture(t, false)
	fx.setDefault(t, pb.ProcessAction_PROCESS_ACTION_THROTTLE, "10%", time.Hour)
	fx.fire(t, "box-a", ruleMiningBehavior, pb.ThreatSeverity_THREAT_SEVERITY_HIGH)
	fx.r.act = notFoundUndo{fx.act}
	if n := fx.r.SweepExpired(context.Background(), fx.clock.Add(61*time.Minute)); n != 0 {
		t.Fatalf("SweepExpired released %d, want 0: the box is still there", n)
	}
	if _, err := openAction(fx, "box-a"); err != nil {
		t.Errorf("box-a's action = %v, want still open for the next sweep", err)
	}
	if d := auditDetails(fx.audit, "release"); len(d) != 0 && strings.Contains(d[0], threatdetect.ReleasedByContainerDeleted) {
		t.Errorf("release audit = %v, want none", d)
	}
}

// TestContainerDeleted_UnknownInstanceLooksTheBoxUp (#2897 review): when the
// deleted instance's id or the open row's id is unknown, the close cannot
// tell the deleted box's action from a new same-named box's. It looks the
// box up and closes only when no box by that name exists; an existing box's
// action is left to the sweep and its undo, never closed without one.
func TestContainerDeleted_UnknownInstanceLooksTheBoxUp(t *testing.T) {
	ctx := context.Background()
	t.Run("no id at delete, a new box-b is throttled", func(t *testing.T) {
		fx, _ := twoThrottled(t) // box-b's action is the live instance's
		fx.r.ContainerDeleted(ctx, "box-b", "")
		fx.r.waitBackground()
		if _, err := openAction(fx, "box-b"); err != nil {
			t.Errorf("box-b's action was closed without an undo: %v", err)
		}
	})
	t.Run("no id at apply, the delete names an older instance", func(t *testing.T) {
		fx := newResponderFixture(t, false)
		row := &threatdetect.SecurityAction{FindingID: 1, Container: "box-b", TenantID: "tenant-a",
			Action: pb.ProcessAction_PROCESS_ACTION_FREEZE, AppliedAt: fx.clock, ExpiresAt: fx.clock.Add(time.Hour)}
		if err := fx.actions.Insert(ctx, row); err != nil {
			t.Fatal(err)
		}
		fx.r.ContainerDeleted(ctx, "box-b", "id-of-an-older-box-b")
		fx.r.waitBackground()
		if _, err := openAction(fx, "box-b"); err != nil {
			t.Errorf("box-b's action was closed without an undo: %v", err)
		}
	})
	t.Run("no id at delete, the box is gone", func(t *testing.T) {
		fx, _ := twoThrottled(t)
		fx.act.mu.Lock()
		fx.act.missing["box-b"] = true
		fx.act.mu.Unlock()
		fx.r.ContainerDeleted(ctx, "box-b", "")
		fx.r.waitBackground()
		if row := latestRow(t, fx, "box-b"); row.Open() || row.ReleasedBy != threatdetect.ReleasedByContainerDeleted {
			t.Errorf("box-b's row = %+v, want closed by %s", row, threatdetect.ReleasedByContainerDeleted)
		}
	})
}

// TestBoxGone_EmptyLiveIDIsUnknown: a box whose instance id reads empty is
// not a different instance; its undo runs.
func TestBoxGone_EmptyLiveIDIsUnknown(t *testing.T) {
	fx := newResponderFixture(t, false)
	fx.act.count["box-a"], fx.act.allow["box-a"] = "2", "200ms/100ms"
	fx.act.ids["box-a"] = "uuid-1"
	fx.setDefault(t, pb.ProcessAction_PROCESS_ACTION_THROTTLE, "10%", time.Hour)
	fx.fire(t, "box-a", ruleMiningBehavior, pb.ThreatSeverity_THREAT_SEVERITY_HIGH)
	fx.act.ids["box-a"] = ""
	if n := fx.r.SweepExpired(context.Background(), fx.clock.Add(61*time.Minute)); n != 1 {
		t.Fatalf("SweepExpired released %d, want 1", n)
	}
	if fx.act.count["box-a"] != "2" || fx.act.allow["box-a"] != "200ms/100ms" {
		t.Errorf("limits = %q/%q, want the recorded 2/200ms/100ms restored", fx.act.count["box-a"], fx.act.allow["box-a"])
	}
}

// TestRun_RegistersTheDeleteHook: the responder hooks Incus deletes for as
// long as it runs (the daemon starts it with Run), and unhooks on shutdown.
func TestRun_RegistersTheDeleteHook(t *testing.T) {
	fx, _ := twoThrottled(t)
	hooked := make(chan func(name, instanceID string), 1)
	removed := make(chan struct{})
	fx.r.registerDelete = func(fn func(name, instanceID string)) func() {
		hooked <- fn
		return func() { close(removed) }
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { fx.r.Run(ctx); close(done) }()
	var fn func(string, string)
	select {
	case fn = <-hooked:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not register the delete hook")
	}
	fx.act.mu.Lock()
	fx.act.missing["box-b"] = true
	fx.act.mu.Unlock()
	fn("box-b", "id-box-b")
	fx.r.waitBackground()
	if row := latestRow(t, fx, "box-b"); row.Open() {
		t.Errorf("box-b's row = %+v, want closed through the hook", row)
	}
	cancel()
	<-done
	select {
	case <-removed:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not remove the delete hook on shutdown")
	}
}
