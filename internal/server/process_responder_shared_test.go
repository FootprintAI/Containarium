package server

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/footprintai/containarium/internal/app"
	"github.com/footprintai/containarium/internal/threatdetect"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// queueFor queues a miner-signature finding from box, with no worker
// running. Every box uses the same subject, so all of one tenant's boxes
// share one finding, as miner-signature findings do in production.
func queueFor(t *testing.T, fx *responderFixture, sink *ActingSink, box string) responseJob {
	t.Helper()
	if _, err := sink.Upsert(context.Background(), &threatdetect.Finding{Rule: ruleMinerSignature,
		Severity: pb.ThreatSeverity_THREAT_SEVERITY_HIGH, TenantID: "tenant-a", Container: box, Subject: "name:xmrig"}); err != nil {
		t.Fatal(err)
	}
	select {
	case job := <-fx.r.queue:
		if job.f.Container != box {
			t.Fatalf("queued job is for %q, want %q", job.f.Container, box)
		}
		return job
	default:
		t.Fatal("nothing queued")
		return responseJob{}
	}
}

func openAction(fx *responderFixture, box string) (*threatdetect.SecurityAction, error) {
	return fx.actions.Open(context.Background(), box)
}

// TestQueuedResponse_SharedFindingReleaseIsPerContainer (#2766): two boxes of
// one tenant match the same signature and share one finding. A release is
// judged against the job's own container: releasing (or expiring) box A
// leaves box B's queued response to run, releasing box B skips it, and a
// resolve of the finding itself skips every box's job.
func TestQueuedResponse_SharedFindingReleaseIsPerContainer(t *testing.T) {
	cases := []struct {
		name string
		// run sets the scene and returns the jobs the worker then runs, in
		// order.
		run func(t *testing.T, fx *responderFixture, sink *ActingSink) []responseJob
		// applied: the boxes that must end with an open THROTTLE.
		applied []string
		// skipped: the substring each expected response-skipped audit row
		// carries, one entry per row.
		skipped []string
		// findingOpen: the shared finding's state after the jobs ran.
		findingOpen bool
		// responseApplied: the finding's response ends APPLIED (the queued
		// response ran and recorded itself).
		responseApplied bool
	}{
		{
			name: "operator release of A leaves B's queued response applied",
			run: func(t *testing.T, fx *responderFixture, sink *ActingSink) []responseJob {
				fx.r.runJob(context.Background(), queueFor(t, fx, sink, "box-a"))
				jobB := queueFor(t, fx, sink, "box-b")
				if _, err := fx.r.Release(context.Background(), "box-a"); err != nil {
					t.Fatal(err)
				}
				return []responseJob{jobB}
			},
			applied:         []string{"box-b"},
			findingOpen:     true,
			responseApplied: true,
		},
		{
			name: "TTL release of A leaves B's queued response applied",
			run: func(t *testing.T, fx *responderFixture, sink *ActingSink) []responseJob {
				fx.r.runJob(context.Background(), queueFor(t, fx, sink, "box-a"))
				jobB := queueFor(t, fx, sink, "box-b")
				if n := fx.r.SweepExpired(context.Background(), fx.clock.Add(2*time.Hour)); n != 1 {
					t.Fatalf("SweepExpired released %d, want 1", n)
				}
				return []responseJob{jobB}
			},
			applied:         []string{"box-b"},
			findingOpen:     true,
			responseApplied: true,
		},
		{
			name: "operator release of B skips B's queued response",
			run: func(t *testing.T, fx *responderFixture, sink *ActingSink) []responseJob {
				ctx := context.Background()
				fx.r.runJob(ctx, queueFor(t, fx, sink, "box-a"))
				fx.r.runJob(ctx, queueFor(t, fx, sink, "box-b"))
				jobB := queueFor(t, fx, sink, "box-b") // B's rule re-fires while throttled
				jobA := queueFor(t, fx, sink, "box-a") // and A's, so the finding stays open
				if _, err := fx.r.Release(ctx, "box-b"); err != nil {
					t.Fatal(err)
				}
				return []responseJob{jobB, jobA}
			},
			applied:     []string{"box-a"},
			skipped:     []string{"action on box-b released by operator"},
			findingOpen: true,
		},
		{
			name: "resolving the finding skips both boxes' queued responses",
			run: func(t *testing.T, fx *responderFixture, sink *ActingSink) []responseJob {
				jobA := queueFor(t, fx, sink, "box-a")
				jobB := queueFor(t, fx, sink, "box-b")
				if jobA.f.ID != jobB.f.ID {
					t.Fatalf("finding ids %d and %d: the boxes must share one finding", jobA.f.ID, jobB.f.ID)
				}
				if _, err := fx.findings.Resolve(context.Background(), jobA.f.ID); err != nil {
					t.Fatal(err)
				}
				return []responseJob{jobA, jobB}
			},
			skipped: []string{"no longer open", "no longer open"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			fx, sink := queuedThrottle(t)
			jobs := tc.run(t, fx, sink)
			for _, job := range jobs {
				fx.r.runJob(ctx, job)
			}

			for _, box := range []string{"box-a", "box-b"} {
				row, err := openAction(fx, box)
				want := false
				for _, b := range tc.applied {
					want = want || b == box
				}
				switch {
				case want && (err != nil || row.Action != pb.ProcessAction_PROCESS_ACTION_THROTTLE):
					t.Errorf("%s: open action = %+v, %v; want THROTTLE", box, row, err)
				case !want && !errors.Is(err, threatdetect.ErrNoOpenAction):
					t.Errorf("%s: open action = %+v, %v; want none", box, row, err)
				}
			}
			d := auditDetails(fx.audit, "response-skipped")
			if len(d) != len(tc.skipped) {
				t.Fatalf("response-skipped audit = %v, want %d row(s)", d, len(tc.skipped))
			}
			for i, want := range tc.skipped {
				if !strings.Contains(d[i], want) {
					t.Errorf("response-skipped[%d] = %q, want it to contain %q", i, d[i], want)
				}
			}
			f, err := fx.findings.Get(ctx, jobs[0].f.ID)
			if err != nil {
				t.Fatal(err)
			}
			if got := f.State == threatdetect.FindingStateOpen; got != tc.findingOpen {
				t.Fatalf("finding state = %s, want open=%t", f.State, tc.findingOpen)
			}
			if tc.responseApplied &&
				(f.Response == nil || f.Response.State != pb.ResponseState_RESPONSE_STATE_APPLIED) {
				t.Fatalf("response = %+v, want APPLIED for the box still acted on", f.Response)
			}
		})
	}
}

// TestRelease_SharedFindingResolvedWithLastBox: releasing box A while box B
// has a response queued keeps the shared finding open (audited as
// finding_kept_open=true); once B's response ran, releasing B resolves it.
func TestRelease_SharedFindingResolvedWithLastBox(t *testing.T) {
	ctx := context.Background()
	fx, sink := queuedThrottle(t)
	fx.r.runJob(ctx, queueFor(t, fx, sink, "box-a"))
	jobB := queueFor(t, fx, sink, "box-b")
	if _, err := fx.r.Release(ctx, "box-a"); err != nil {
		t.Fatal(err)
	}
	if d := auditDetails(fx.audit, "release"); len(d) != 1 || !strings.Contains(d[0], "finding_kept_open=true") {
		t.Fatalf("release audit = %v, want finding_kept_open=true", d)
	}
	fx.r.runJob(ctx, jobB)
	f, err := fx.r.Release(ctx, "box-b")
	if err != nil {
		t.Fatal(err)
	}
	if f == nil || f.State != threatdetect.FindingStateResolved {
		t.Fatalf("finding after the last box's release = %+v, want resolved", f)
	}
	if d := auditDetails(fx.audit, "release"); len(d) != 2 || !strings.Contains(d[1], "finding_kept_open=false") {
		t.Fatalf("release audit = %v, want the second with finding_kept_open=false", d)
	}
}

// TestQueuedResponse_ReleaseBetweenReadAndLockSkipsKill pins the re-check
// under r.mu before the kill: a release or resolve that lands after the
// worker's unlocked read, but before it takes the lock, must still stop the
// kill. The afterQueuedRead seam lands it in exactly that window; without the
// locked re-check the process would be killed.
func TestQueuedResponse_ReleaseBetweenReadAndLockSkipsKill(t *testing.T) {
	cases := []struct {
		name   string
		setup  func(t *testing.T, fx *responderFixture, sink *ActingSink)
		land   func(t *testing.T, fx *responderFixture, job responseJob)
		reason string
	}{
		{
			name: "finding resolved",
			land: func(t *testing.T, fx *responderFixture, job responseJob) {
				if _, err := fx.findings.Resolve(context.Background(), job.f.ID); err != nil {
					t.Fatal(err)
				}
			},
			reason: "no longer open",
		},
		{
			name: "own container's action expired",
			setup: func(t *testing.T, fx *responderFixture, sink *ActingSink) {
				fx.r.runJob(context.Background(), queueFor(t, fx, sink, "box-a"))
			},
			land: func(t *testing.T, fx *responderFixture, _ responseJob) {
				if n := fx.r.SweepExpired(context.Background(), fx.clock.Add(2*time.Hour)); n != 1 {
					t.Fatalf("SweepExpired released %d, want 1", n)
				}
			},
			reason: "action on box-a released by ttl",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			fx, sink := queuedThrottle(t)
			if tc.setup != nil {
				tc.setup(t, fx, sink)
			}
			fx.setKill(t, "", true)
			killer := &fakeKiller{}
			fx.r.SetProcessKiller(killer)
			job := queueSignature(t, fx, sink, 4242)
			landed := 0
			fx.r.afterQueuedRead = func() {
				landed++
				tc.land(t, fx, job)
			}

			fx.r.runJob(ctx, job)

			if landed != 1 {
				t.Fatalf("seam ran %d time(s), want 1 (the unlocked read must pass first)", landed)
			}
			if len(killer.calls) != 0 || len(auditDetails(fx.audit, "kill")) != 0 {
				t.Fatalf("killed %v after a %s landed before the locked re-check", killer.calls, tc.name)
			}
			if d := auditDetails(fx.audit, "response-skipped"); len(d) != 1 || !strings.Contains(d[0], tc.reason) {
				t.Fatalf("response-skipped audit = %v, want one containing %q", d, tc.reason)
			}
		})
	}
}

// flakyPolicyKV is a policy config store whose reads can be made to fail.
type flakyPolicyKV struct {
	mu   sync.Mutex
	m    map[string]string
	fail bool
}

func (k *flakyPolicyKV) Get(_ context.Context, key string) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.fail {
		return "", errors.New("config store unavailable")
	}
	v, ok := k.m[key]
	if !ok {
		return "", app.ErrDaemonConfigNotFound
	}
	return v, nil
}

func (k *flakyPolicyKV) Set(_ context.Context, key, value string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.m[key] = value
	return nil
}

// TestProcessKilledRecorded_PolicyReadFailsAfterKill (#2766): the kill ran
// and was audited, then the policy read for the policy action failed. The
// policy action is skipped, but the finding must still say the process was
// killed.
func TestProcessKilledRecorded_PolicyReadFailsAfterKill(t *testing.T) {
	ctx := context.Background()
	fx := newResponderFixture(t, false)
	kv := &flakyPolicyKV{m: map[string]string{}}
	fx.policies = threatdetect.NewProcessPolicyStore(kv)
	fx.r.policies = fx.policies
	fx.setDefault(t, pb.ProcessAction_PROCESS_ACTION_THROTTLE, "10%", time.Hour)
	fx.setKill(t, "", true)
	fx.r.SetProcessKiller(killerFunc(func(string, uint32) error {
		kv.mu.Lock()
		kv.fail = true // the store goes away right after the kill
		kv.mu.Unlock()
		return nil
	}))

	out := fx.fireSignature(t, "box-a", 4242)

	if len(auditDetails(fx.audit, "kill")) != 1 {
		t.Fatalf("kill audits = %v, want one", auditDetails(fx.audit, "kill"))
	}
	if out == nil || out.Response == nil || !out.Response.ProcessKilled {
		t.Fatalf("returned finding = %+v, want process_killed=true", out)
	}
	f, _ := fx.findings.Get(ctx, out.ID)
	if f.Response == nil || !f.Response.ProcessKilled {
		t.Fatalf("stored response = %+v, want process_killed=true", f.Response)
	}
	if setCPUCalls(fx) != 0 {
		t.Fatal("applied a policy action with an unreadable policy")
	}
}

// TestProcessKilledRecorded_SurvivesRelease (#2766): a kill recorded while
// another action stood on the box (killed_pid is not on that row) must not
// be wiped by the release that later rewrites the finding's response.
func TestProcessKilledRecorded_SurvivesRelease(t *testing.T) {
	ctx := context.Background()
	fx := newResponderFixture(t, false)
	fx.setDefault(t, pb.ProcessAction_PROCESS_ACTION_THROTTLE, "10%", time.Hour)
	fx.r.SetProcessKiller(&fakeKiller{})
	fx.fireSignature(t, "box-a", 100) // throttled, kill off: killed_pid 0
	fx.setKill(t, "", true)
	f := fx.fireSignature(t, "box-a", 101) // throttle stands, the kill is recorded
	if f == nil || f.Response == nil || !f.Response.ProcessKilled {
		t.Fatalf("after the kill: %+v, want process_killed=true", f)
	}

	released, err := fx.r.Release(ctx, "box-a")
	if err != nil {
		t.Fatal(err)
	}
	if released == nil || released.Response == nil || !released.Response.ProcessKilled {
		t.Fatalf("after release: %+v, want process_killed still true", released)
	}
}
